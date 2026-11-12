// SPDX-License-Identifier: LicenseRef-Reticulum
//! The running daemon: the user's LXMF address, the private propagation
//! node that serves the stored messages, and the upstream fetcher.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_core::constants::{MESSAGE_GET_PATH, PEERING_COST, PROPAGATION_COST, PROPAGATION_COST_FLEX, SYNC_LIMIT};
use lxmf_core::handlers::{PropagationNodeAnnounceData, get_announce_app_data, get_propagation_node_app_data};
use lxmf_core::message_api::LxMessage;
use rns_identity::destination::Destination;
use rns_runtime::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::{RnsAccess, Settings};
use crate::outbox::{Added, Outbox};
use crate::store::{ERROR_NO_ACCESS, ERROR_NO_IDENTITY, Ingested, Store, Summary, Via, error_reply, write_atomic};
use crate::{ratchets, upstream};

pub const DELIVERY_ASPECT: &str = "lxmf.delivery";
pub const PROPAGATION_ASPECT: &str = "lxmf.propagation";

/// How long to wait after starting before the first announce, so
/// interfaces have come up.
const FIRST_ANNOUNCE_DELAY: Duration = Duration::from_secs(5);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const STATUS_INTERVAL: Duration = Duration::from_secs(60);
const SUMMARY_LOG_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Most bytes of outgoing messages waiting for the upstream node.
const OUTBOX_MAX_BYTES: u64 = 50_000_000;
/// Largest send an app may hand the node, as Python LXMF's per-transfer
/// limit for clients.
const SUBMISSION_LIMIT_BYTES: usize = lxmf_core::constants::PROPAGATION_LIMIT * 1000;

pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// The user's LXMF address.
pub fn delivery_address(identity_hash: &[u8; 16]) -> [u8; 16] {
    Destination::hash_from_name_and_identity(DELIVERY_ASPECT, Some(identity_hash))
}

/// The propagation node's address.
pub fn node_address(node_identity_hash: &[u8; 16]) -> [u8; 16] {
    Destination::hash_from_name_and_identity(PROPAGATION_ASPECT, Some(node_identity_hash))
}

/// The node's own identity, made the first time it is needed.
pub fn load_or_create_node_identity(path: &Path, user: &Identity) -> Result<Identity, String> {
    let identity = if path.exists() {
        load_identity(path)?
    } else {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let identity = Identity::new();
        identity
            .to_file(path)
            .map_err(|e| format!("could not save the node identity {}: {e}", path.display()))?;
        tracing::info!("created the propagation node's identity {}", path.display());
        identity
    };
    if identity.hash == user.hash {
        return Err(format!(
            "{} is the user's identity; the node needs one of its own (LXMF clients holding the user's identity \
             register its lxmf.propagation address themselves and would never reach the node)",
            path.display()
        ));
    }
    Ok(identity)
}

/// The last upstream fetch.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UpstreamResult {
    pub at: f64,
    pub ok: bool,
    pub stored: usize,
    pub duplicates: usize,
    pub failed: usize,
    pub error: Option<String>,
}

/// What `status` reads: written to the state directory every minute.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub pid: u32,
    pub started_at: f64,
    pub updated_at: f64,
    pub identity_hash: String,
    pub node_identity_hash: String,
    pub lxmf_address: String,
    pub propagation_node: String,
    pub last_announce: Option<f64>,
    pub received_direct: u64,
    pub received_upstream: u64,
    pub duplicates: u64,
    pub dropped: u64,
    pub syncs_served: u64,
    pub syncs_refused: u64,
    pub messages_served: u64,
    #[serde(default)]
    pub outgoing_queued: u64,
    #[serde(default)]
    pub outgoing_refused: u64,
    #[serde(default)]
    pub sent_upstream: u64,
    #[serde(default)]
    pub outbox: usize,
    pub upstream: Option<String>,
    pub last_upstream: Option<UpstreamResult>,
    pub store: Summary,
}

#[derive(Default)]
pub struct Counters {
    pub received_direct: AtomicU64,
    pub received_upstream: AtomicU64,
    pub duplicates: AtomicU64,
    pub dropped: AtomicU64,
    pub syncs_served: AtomicU64,
    pub syncs_refused: AtomicU64,
    pub messages_served: AtomicU64,
    pub outgoing_queued: AtomicU64,
    pub outgoing_refused: AtomicU64,
    pub sent_upstream: AtomicU64,
}

/// An identity the user had before: messages to its address are taken in,
/// moved to the user's address and kept for the apps.
#[derive(Clone)]
pub struct OldIdentity {
    pub identity: Identity,
    pub address: [u8; 16],
    /// Ratchet rings to decrypt its propagated messages with.
    pub rings: Vec<std::path::PathBuf>,
}

/// What the tasks share.
pub struct Shared {
    pub runtime: ReticulumHandle,
    pub identity: Identity,
    pub node_identity: Identity,
    pub store: Arc<Store>,
    pub outbox: Arc<Outbox>,
    /// Woken when a message is queued for the upstream node.
    pub outbox_ready: tokio::sync::Notify,
    pub counters: Counters,
    pub last_announce: Mutex<Option<f64>>,
    pub last_upstream: Mutex<Option<UpstreamResult>>,
    /// Ratchet rings to decrypt propagated messages with: the bouncer's own,
    /// then any configured extra ones.
    pub rings: Vec<std::path::PathBuf>,
    pub old: Vec<OldIdentity>,
}

/// Check, verify and store one complete LXMF message for the user. Returns
/// whether it is now held (stored, or held already).
pub async fn take_in(shared: &Arc<Shared>, packed: Vec<u8>, via: Via) -> bool {
    take_in_for(shared, packed, via, None).await
}

/// As [`take_in`], for a message to the user's address or, with `old`, to
/// that old address. A message to an old address is verified as sent, then
/// moved to the user's address, so the apps (which hold only the user's
/// identity) can open it. Its signature covers the address it was sent to,
/// so the apps show it as not matching; replies go to its sender as usual.
pub async fn take_in_for(shared: &Arc<Shared>, packed: Vec<u8>, via: Via, old: Option<[u8; 16]>) -> bool {
    let message = match LxMessage::unpack(&packed) {
        Ok(message) => message,
        Err(e) => {
            shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("dropped a malformed message ({}): {e}", via_label(via));
            return false;
        }
    };
    let source = message.source_hash();
    // Verify the signature when the sender's key is known, as LXMF clients
    // do: a forged message is dropped; one from an unknown sender is kept,
    // and the client verifies it once it knows the sender.
    let verified = match shared.runtime.recall(source).await {
        Ok(Some(sender)) => match message.verify(&sender.identity.get_public_key()) {
            Ok(_) => "verified",
            Err(e) => {
                shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("dropped a message claiming to be from {}: {e}", hex::encode(source));
                return false;
            }
        },
        _ => "sender unknown, signature not checked",
    };
    let (packed, moved) = match old {
        None => (packed, String::new()),
        Some(old) => {
            if packed.len() < 16 || packed[..16] != old {
                shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("dropped a message not addressed to old address {}", hex::encode(old));
                return false;
            }
            let mut moved = shared.store.user_address().to_vec();
            moved.extend_from_slice(&packed[16..]);
            (moved, format!(", sent to old address {}", hex::encode(old)))
        }
    };
    let store = shared.store.clone();
    let result = tokio::task::spawn_blocking(move || store.ingest(&packed, via)).await;
    match result {
        Ok(Ok(Ingested::Stored {
            message_id,
            transient_id,
        })) => {
            let counter = match via {
                Via::Direct => &shared.counters.received_direct,
                Via::Upstream => &shared.counters.received_upstream,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                "stored message {} from {} ({}{moved}, {verified}; transient id {})",
                hex::encode(message_id),
                hex::encode(source),
                via_label(via),
                hex::encode(transient_id)
            );
            true
        }
        Ok(Ok(Ingested::Duplicate { message_id })) => {
            shared.counters.duplicates.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "message {} ({}) is held already",
                hex::encode(message_id),
                via_label(via)
            );
            true
        }
        Ok(Err(e)) => {
            shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                "could not store a message from {} ({}): {e}",
                hex::encode(source),
                via_label(via)
            );
            false
        }
        Err(e) => {
            shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::error!("storing a message failed: {e}");
            false
        }
    }
}

fn via_label(via: Via) -> &'static str {
    match via {
        Via::Direct => "direct",
        Via::Upstream => "from upstream",
    }
}

/// A message as it arrives at the delivery address: opportunistic packets
/// carry it without the destination hash, Links with it.
fn with_destination(address: &[u8; 16], data: Vec<u8>) -> Vec<u8> {
    if data.len() >= 16 && data[..16] == *address {
        data
    } else {
        let mut full = address.to_vec();
        full.extend_from_slice(&data);
        full
    }
}

/// The propagation node's announce data. It says it is not an active node,
/// so other propagation nodes don't peer with it; clients set to it by hash
/// sync from it all the same.
fn node_app_data(name: Option<&str>) -> Vec<u8> {
    let mut data = PropagationNodeAnnounceData::new(
        false,
        lxmf_core::constants::PROPAGATION_LIMIT as u64,
        SYNC_LIMIT as u64,
        PROPAGATION_COST,
        PROPAGATION_COST_FLEX,
        PEERING_COST,
    );
    if let Some(name) = name {
        data.metadata
            .insert(lxmf_core::constants::PN_META_NAME, name.as_bytes().to_vec());
    }
    data.metadata.insert(0xFE, b"lxmf-bouncer".to_vec());
    data.metadata.insert(
        lxmf_core::constants::PN_META_VERSION,
        env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
    );
    get_propagation_node_app_data(&data)
}

/// Is a shared instance with this name listening on this host?
fn shared_instance_listening(instance_name: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("rns/{instance_name}");
        std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
            .and_then(|addr| std::os::unix::net::UnixStream::connect_addr(&addr))
            .is_ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = instance_name;
        false
    }
}

async fn start_reticulum(settings: &Settings, shutdown: ShutdownSignal) -> Result<ReticulumHandle, String> {
    let dir = settings.rns_config_dir();
    if let Some(config) = settings.generated_rns_config() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        write_atomic(&dir.join("config"), config.as_bytes()).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    if let RnsAccess::Shared { instance_name } = &settings.rns {
        // Without this check the bouncer would itself become the shared
        // instance (with no interfaces) when rnsd isn't running.
        if !shared_instance_listening(instance_name) {
            return Err(format!(
                "no Reticulum shared instance {instance_name:?} is running on this host (start rnsd first)"
            ));
        }
    }
    let dir = dir.to_string_lossy().to_string();
    let runtime = init(Some(&dir), None, shutdown, Arc::new(AtomicBool::new(true)))
        .await
        .map_err(|e| format!("Reticulum did not start: {e}"))?;
    for (name, reason) in runtime.startup_interface_failures() {
        tracing::warn!("interface {name} failed to start: {reason}");
    }
    Ok(runtime)
}

/// Load the user's identity (a 64-byte Reticulum private key file).
pub fn load_identity(path: &Path) -> Result<Identity, String> {
    Identity::from_file(path).map_err(|e| format!("could not load the identity {}: {e}", path.display()))
}

pub async fn run(settings: Settings) -> Result<(), String> {
    let identity = load_identity(&settings.identity)?;
    std::fs::create_dir_all(&settings.state_dir).map_err(|e| format!("{}: {e}", settings.state_dir.display()))?;
    let node_identity = load_or_create_node_identity(&settings.node_identity, &identity)?;
    let (address, node_hash) = (delivery_address(&identity.hash), node_address(&node_identity.hash));
    std::fs::create_dir_all(settings.ratchet_dir())
        .map_err(|e| format!("{}: {e}", settings.ratchet_dir().display()))?;

    let store = {
        let (dir, ledger, user, max, expiry) = (
            settings.store_dir(),
            settings.ledger_path(),
            identity.clone(),
            settings.max_store_bytes,
            settings.expiry,
        );
        tokio::task::spawn_blocking(move || Store::open(&dir, &ledger, &user, node_hash, max, expiry))
            .await
            .map_err(|e| e.to_string())??
    };
    let store = Arc::new(store);
    let outbox = Arc::new(Outbox::open(&settings.outbox_dir(), OUTBOX_MAX_BYTES, settings.expiry)?);

    let shutdown = ShutdownSignal::new();
    let mut signals = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());
    let runtime = start_reticulum(&settings, shutdown.clone()).await?;

    let ring = ratchets::ring_path(&settings.ratchet_dir(), &address);
    let mut rings = vec![ring.clone()];
    rings.extend(settings.extra_ratchets.iter().cloned());
    let shared_user_hash = identity.hash;
    let mut old = Vec::new();
    for (path, extra) in &settings.old_identities {
        let identity = load_identity(path)?;
        if identity.hash == shared_user_hash {
            return Err(format!("old identity {} is the current identity", path.display()));
        }
        let old_address = delivery_address(&identity.hash);
        let mut rings = vec![ratchets::ring_path(&settings.ratchet_dir(), &old_address)];
        rings.extend(extra.iter().cloned());
        old.push(OldIdentity {
            identity,
            address: old_address,
            rings,
        });
    }
    let shared = Arc::new(Shared {
        runtime: runtime.clone(),
        identity: identity.clone(),
        node_identity: node_identity.clone(),
        store: store.clone(),
        outbox,
        outbox_ready: tokio::sync::Notify::new(),
        counters: Counters::default(),
        last_announce: Mutex::new(None),
        last_upstream: Mutex::new(None),
        rings,
        old: old.clone(),
    });

    // The user's LXMF address, with ratchets as Python LXMF gives every
    // address: senders encrypt to the newest one announced.
    let display_name = settings.display_name.clone();
    let delivery = runtime
        .register_ratcheted_destination(
            identity.clone(),
            DELIVERY_ASPECT,
            DestinationRuntimeOptions {
                proof_strategy: ProofStrategy::ProveAll,
                resource_strategy: ResourceStrategy::AcceptAll,
                default_app_data: Some(get_announce_app_data(display_name.as_deref(), None)),
                ..DestinationRuntimeOptions::default()
            },
            DestinationRatchetOptions::new(&ring),
        )
        .await
        .map_err(|e| format!("could not register the LXMF address: {e}"))?;

    // Old addresses: announced and taken in like the user's.
    let mut old_deliveries = Vec::new();
    for o in &old {
        let registered = runtime
            .register_ratcheted_destination(
                o.identity.clone(),
                DELIVERY_ASPECT,
                DestinationRuntimeOptions {
                    proof_strategy: ProofStrategy::ProveAll,
                    resource_strategy: ResourceStrategy::AcceptAll,
                    default_app_data: Some(get_announce_app_data(display_name.as_deref(), None)),
                    ..DestinationRuntimeOptions::default()
                },
                DestinationRatchetOptions::new(&o.rings[0]),
            )
            .await
            .map_err(|e| format!("could not register old address {}: {e}", hex::encode(o.address)))?;
        tracing::info!("also taking messages to old address {}", hex::encode(o.address));
        old_deliveries.push((registered, o.address));
    }

    // The propagation node: `/get` for allowed identities, and, when there
    // is an upstream node to pass them to, the messages apps send through
    // it. With no upstream it takes nothing in (no Resources, no proofs for
    // packets), so a propagated send through it fails visibly instead of
    // being kept where its recipient never looks.
    let takes_sends = settings.upstream.is_some();
    let node = runtime
        .register_destination(
            node_identity.clone(),
            PROPAGATION_ASPECT,
            DestinationRuntimeOptions {
                proof_strategy: if takes_sends {
                    ProofStrategy::ProveAll
                } else {
                    ProofStrategy::ProveNone
                },
                resource_strategy: if takes_sends {
                    ResourceStrategy::AcceptApp
                } else {
                    ResourceStrategy::AcceptNone
                },
                resource_accept: Some(ResourceAcceptPolicy::new(|_link, advert| {
                    advert.data_size <= SUBMISSION_LIMIT_BYTES
                })),
                default_app_data: Some(node_app_data(settings.node_name.as_deref())),
                ..DestinationRuntimeOptions::default()
            },
        )
        .await
        .map_err(|e| format!("could not register the propagation node: {e}"))?;
    let allowed: HashSet<[u8; 16]> = std::iter::once(identity.hash)
        .chain(settings.allowed_identities.iter().copied())
        .collect();
    {
        let shared = shared.clone();
        node.handle
            .register_request_handler(
                MESSAGE_GET_PATH,
                AllowPolicy::AllowAll,
                Vec::new(),
                false,
                move |request| {
                    let Some(remote) = request.remote_identity else {
                        shared.counters.syncs_refused.fetch_add(1, Ordering::Relaxed);
                        return RequestOutcome::Reply(error_reply(ERROR_NO_IDENTITY));
                    };
                    if !allowed.contains(&remote.hash) {
                        shared.counters.syncs_refused.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "refused a sync from identity {} (not allowed)",
                            hex::encode(remote.hash)
                        );
                        return RequestOutcome::Reply(error_reply(ERROR_NO_ACCESS));
                    }
                    let client = Destination::hash_from_name_and_identity(DELIVERY_ASPECT, Some(&remote.hash));
                    let (reply, served) = shared.store.handle_get(&request.data, &client);
                    if served > 0 {
                        shared.counters.syncs_served.fetch_add(1, Ordering::Relaxed);
                        shared.counters.messages_served.fetch_add(served, Ordering::Relaxed);
                        tracing::info!("served {served} message(s) to a client of {}", hex::encode(remote.hash));
                    }
                    RequestOutcome::Reply(reply)
                },
            )
            .await
            .map_err(|e| format!("could not start the propagation node: {e}"))?;
    }

    tracing::info!(
        "lxmf-bouncer {} holding identity {}: LXMF address {}, propagation node {}",
        env!("CARGO_PKG_VERSION"),
        hex::encode(identity.hash),
        hex::encode(address),
        hex::encode(node_hash)
    );
    log_summary(&store.summary());

    let mut tasks = vec![
        tokio::spawn(announcer(
            shared.clone(),
            delivery.handle.clone(),
            old_deliveries.iter().map(|(r, _)| r.handle.clone()).collect(),
            node.handle.clone(),
            settings.announce_interval,
            display_name,
            settings.node_name.clone(),
        )),
        tokio::spawn(delivery_events(shared.clone(), delivery, address, None)),
        tokio::spawn(node_events(shared.clone(), node, takes_sends)),
        tokio::spawn(housekeeping(shared.clone(), settings.clone())),
    ];
    for (registered, old_address) in old_deliveries {
        tasks.push(tokio::spawn(delivery_events(
            shared.clone(),
            registered,
            old_address,
            Some(old_address),
        )));
    }
    if let Some(upstream) = settings.upstream {
        tracing::info!(
            "fetching from upstream propagation node {} every {} min",
            hex::encode(upstream),
            settings.upstream_interval.as_secs() / 60
        );
        tasks.push(tokio::spawn(upstream::run(
            shared.clone(),
            upstream,
            settings.upstream_interval,
        )));
        tasks.push(tokio::spawn(upstream::forward_loop(shared.clone(), upstream)));
    }

    signals.recv().await;
    tracing::info!("shutting down");
    for task in &tasks {
        task.abort();
    }
    write_status(&shared, &settings).await;
    runtime.shutdown_and_wait().await;
    Ok(())
}

async fn announcer(
    shared: Arc<Shared>,
    delivery: DestinationHandle,
    old: Vec<DestinationHandle>,
    node: DestinationHandle,
    every: Duration,
    display_name: Option<String>,
    node_name: Option<String>,
) {
    tokio::time::sleep(FIRST_ANNOUNCE_DELAY).await;
    loop {
        let delivered = delivery
            .announce(DestinationAnnounceOptions {
                app_data: Some(get_announce_app_data(display_name.as_deref(), None)),
                ..DestinationAnnounceOptions::default()
            })
            .await;
        let noded = node
            .announce(DestinationAnnounceOptions {
                app_data: Some(node_app_data(node_name.as_deref())),
                ..DestinationAnnounceOptions::default()
            })
            .await;
        for handle in &old {
            if let Err(e) = handle
                .announce(DestinationAnnounceOptions {
                    app_data: Some(get_announce_app_data(display_name.as_deref(), None)),
                    ..DestinationAnnounceOptions::default()
                })
                .await
            {
                tracing::warn!("announcing an old address failed: {e}");
            }
        }
        match (delivered, noded) {
            (Ok(()), Ok(())) => {
                *shared.last_announce.lock().unwrap_or_else(|e| e.into_inner()) = Some(now());
                tracing::info!("announced the LXMF address and the propagation node");
            }
            (Err(e), _) | (_, Err(e)) => tracing::warn!("announce failed: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

/// Messages to the user: one packet (opportunistic), or over a Link as a
/// packet or a Resource (direct).
async fn delivery_events(
    shared: Arc<Shared>,
    mut delivery: RegisteredDestination,
    address: [u8; 16],
    old: Option<[u8; 16]>,
) {
    let events = &mut delivery.events;
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let taker = {
        let shared = shared.clone();
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                let shared = shared.clone();
                tokio::spawn(async move { take_in_for(&shared, data, Via::Direct, old).await });
            }
        })
    };
    loop {
        let data = tokio::select! {
            Some(packet) = events.packets.recv() => packet.data,
            Some((data, _link)) = events.link_packets.recv() => data,
            Some(done) = events.resource_completions.recv() => done.data,
            Some(_) = events.links_established.recv() => continue,
            Some(_) = events.links_identified.recv() => continue,
            Some(_) = events.link_packet_proofs.recv() => continue,
            Some(_) = events.resource_proofs.recv() => continue,
            Some(_) = events.resource_events.recv() => continue,
            Some(_) = events.channel_messages.recv() => continue,
            Some(_) = events.links_closed.recv() => continue,
            else => break,
        };
        let _ = tx.send(with_destination(&address, data));
    }
    taker.abort();
}

/// The node's events: messages the apps send through it (one Link packet,
/// or a Resource) when it takes them; requests are answered by the handler.
async fn node_events(shared: Arc<Shared>, mut node: RegisteredDestination, takes_sends: bool) {
    let events = &mut node.events;
    loop {
        tokio::select! {
            Some(_) = events.packets.recv() => {}
            Some((data, _link)) = events.link_packets.recv() => {
                if takes_sends {
                    tokio::spawn(take_submission(shared.clone(), data));
                } else {
                    tracing::debug!("ignored a packet sent to the propagation node");
                }
            }
            Some(done) = events.resource_completions.recv() => {
                if takes_sends {
                    tokio::spawn(take_submission(shared.clone(), done.data));
                }
            }
            Some(_) = events.links_established.recv() => {}
            Some(_) = events.links_identified.recv() => {}
            Some(_) = events.link_packet_proofs.recv() => {}
            Some(_) = events.resource_proofs.recv() => {}
            Some(_) = events.resource_events.recv() => {}
            Some(_) = events.channel_messages.recv() => {}
            Some(_) = events.links_closed.recv() => {}
            else => break,
        }
    }
}

/// A send from one of the user's apps: `[timestamp, [message + stamp, ...]]`,
/// each message encrypted for its recipient. Each one with a good enough
/// stamp is queued for the upstream node; one to the user is stored for
/// the apps instead.
async fn take_submission(shared: Arc<Shared>, data: Vec<u8>) {
    let min_cost = lxmf_core::constants::PROPAGATION_COST.saturating_sub(lxmf_core::constants::PROPAGATION_COST_FLEX);
    let checked = tokio::task::spawn_blocking(move || {
        let (_, entries) =
            lxmf_core::message::LxMessage::unpack_propagation_wrapper_owned(data.into(), SUBMISSION_LIMIT_BYTES)
                .map_err(|e| e.to_string())?;
        Ok::<_, String>(
            entries
                .iter()
                .map(|entry| lxmf_core::stamper::validate_pn_stamp(entry, min_cost).map(|parts| parts.1))
                .collect::<Vec<_>>(),
        )
    })
    .await;
    let entries = match checked {
        Ok(Ok(entries)) => entries,
        Ok(Err(e)) => {
            shared.counters.outgoing_refused.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("refused a send to the propagation node: {e}");
            return;
        }
        Err(e) => {
            tracing::error!("checking a send failed: {e}");
            return;
        }
    };
    let address = shared.store.user_address();
    let mut queued = false;
    for entry in entries {
        let Some(data) = entry else {
            shared.counters.outgoing_refused.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("refused an outgoing message without a good enough stamp");
            continue;
        };
        if data.len() <= 16 {
            continue;
        }
        if data[..16] == address {
            // To the user: keep it for the apps, as a message that came in.
            let (identity, rings, ciphertext) = (shared.identity.clone(), shared.rings.clone(), data[16..].to_vec());
            match tokio::task::spawn_blocking(move || ratchets::decrypt(&identity, &rings, &ciphertext)).await {
                Ok(Ok(plaintext)) => {
                    let mut full = address.to_vec();
                    full.extend_from_slice(&plaintext);
                    take_in(&shared, full, Via::Direct).await;
                }
                _ => tracing::warn!("a message to the user sent through the node could not be decrypted"),
            }
            continue;
        }
        let outbox = shared.outbox.clone();
        let destination = hex::encode(&data[..16]);
        match tokio::task::spawn_blocking(move || outbox.add(&data)).await {
            Ok(Ok((Added::Queued, id))) => {
                shared.counters.outgoing_queued.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "queued outgoing message {} to {destination} for upstream",
                    hex::encode(id)
                );
                queued = true;
            }
            Ok(Ok((Added::Duplicate, id))) => {
                tracing::debug!("outgoing message {} is queued already", hex::encode(id));
            }
            Ok(Err(e)) => {
                shared.counters.outgoing_refused.fetch_add(1, Ordering::Relaxed);
                tracing::error!("could not queue an outgoing message to {destination}: {e}");
            }
            Err(e) => tracing::error!("queueing an outgoing message failed: {e}"),
        }
    }
    if queued {
        shared.outbox_ready.notify_one();
    }
}

fn log_summary(summary: &Summary) {
    tracing::info!(
        "store: {} message(s), {} bytes, from {} sender(s)",
        summary.messages,
        summary.bytes,
        summary.by_sender.len()
    );
}

async fn write_status(shared: &Arc<Shared>, settings: &Settings) {
    let store = shared.store.clone();
    let summary = tokio::task::spawn_blocking(move || store.summary())
        .await
        .unwrap_or_default();
    let outbox = shared.outbox.clone();
    let outbox_count = tokio::task::spawn_blocking(move || outbox.summary().0)
        .await
        .unwrap_or_default();
    let c = &shared.counters;
    let (address, node) = (
        delivery_address(&shared.identity.hash),
        node_address(&shared.node_identity.hash),
    );
    let status = Status {
        pid: std::process::id(),
        started_at: STARTED.get().copied().unwrap_or_default(),
        updated_at: now(),
        identity_hash: hex::encode(shared.identity.hash),
        node_identity_hash: hex::encode(shared.node_identity.hash),
        lxmf_address: hex::encode(address),
        propagation_node: hex::encode(node),
        last_announce: *shared.last_announce.lock().unwrap_or_else(|e| e.into_inner()),
        received_direct: c.received_direct.load(Ordering::Relaxed),
        received_upstream: c.received_upstream.load(Ordering::Relaxed),
        duplicates: c.duplicates.load(Ordering::Relaxed),
        dropped: c.dropped.load(Ordering::Relaxed),
        syncs_served: c.syncs_served.load(Ordering::Relaxed),
        syncs_refused: c.syncs_refused.load(Ordering::Relaxed),
        messages_served: c.messages_served.load(Ordering::Relaxed),
        outgoing_queued: c.outgoing_queued.load(Ordering::Relaxed),
        outgoing_refused: c.outgoing_refused.load(Ordering::Relaxed),
        sent_upstream: c.sent_upstream.load(Ordering::Relaxed),
        outbox: outbox_count,
        upstream: settings.upstream.map(hex::encode),
        last_upstream: shared.last_upstream.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        store: summary,
    };
    let path = settings.status_path();
    match serde_json::to_vec_pretty(&status) {
        Ok(data) => {
            if let Err(e) = write_atomic(&path, &data) {
                tracing::warn!("could not write {}: {e}", path.display());
            }
        }
        Err(e) => tracing::warn!("could not encode the status: {e}"),
    }
}

pub static STARTED: std::sync::OnceLock<f64> = std::sync::OnceLock::new();

/// Expire old messages, write the status file, log a summary now and then.
async fn housekeeping(shared: Arc<Shared>, settings: Settings) {
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    let mut status = tokio::time::interval(STATUS_INTERVAL);
    let mut summary =
        tokio::time::interval_at(tokio::time::Instant::now() + SUMMARY_LOG_INTERVAL, SUMMARY_LOG_INTERVAL);
    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                let store = shared.store.clone();
                let _ = tokio::task::spawn_blocking(move || store.maintain()).await;
            }
            _ = status.tick() => write_status(&shared, &settings).await,
            _ = summary.tick() => log_summary(&shared.store.summary()),
        }
    }
}
