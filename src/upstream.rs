// SPDX-License-Identifier: LicenseRef-Reticulum
//! Fetching the user's messages from another propagation node (one that
//! people sending to the user may have used), as a client holding the
//! user's identity would, and keeping them in the bouncer's own store.
//!
//! The protocol is Python LXMF's `request_messages_from_propagation_node`:
//! a Link identified as the user, `/get [nil, nil]` for the list, `/get
//! [wants, haves, limit]` for the messages, then `/get [nil, received]` so
//! the node drops what the bouncer now holds.
//!
//! It also passes on what the user's apps send through the bouncer's node:
//! each queued message goes to the upstream node as a Python LXMF client
//! sends a propagated message (`[timestamp, [message + stamp]]` in a
//! Resource over a Link), with a stamp meeting the upstream node's cost.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lxmf_core::constants::MESSAGE_GET_PATH;
use rmpv::Value;
use rns_runtime::prelude::*;

use crate::bouncer::{Shared, UpstreamResult, now, take_in_for};
use crate::store::Via;

/// How often to retry sending queued messages upstream.
const FORWARD_RETRY: Duration = Duration::from_secs(5 * 60);
/// How long one message's transfer may take.
const RESOURCE_TIMEOUT: Duration = Duration::from_secs(180);

const FIRST_FETCH_DELAY: Duration = Duration::from_secs(20);
const PATH_TIMEOUT: Duration = Duration::from_secs(30);
const LINK_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Most kilobytes asked for in one download.
const DOWNLOAD_LIMIT_KB: f64 = 1000.0;
/// Downloads in one fetch, at most.
const MAX_ROUNDS: usize = 100;
/// A message that could not be opened is tried again after this long (a
/// ratchet file may have been added meanwhile).
const SKIP_FOR: Duration = Duration::from_secs(6 * 60 * 60);

/// Messages on upstream nodes not to fetch again yet, with when each was
/// set aside.
#[derive(Default)]
struct Skip(HashMap<Vec<u8>, Instant>);

impl Skip {
    fn insert(&mut self, id: Vec<u8>) {
        self.0.insert(id, Instant::now());
    }
    fn contains(&self, id: &[u8]) -> bool {
        self.0.get(id).is_some_and(|at| at.elapsed() < SKIP_FOR)
    }
    fn expire(&mut self) {
        self.0.retain(|_, at| at.elapsed() < SKIP_FOR);
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("writing to a Vec");
    out
}

fn peer_error(code: u64) -> String {
    let reason = match code {
        0xF0 => "the node could not identify us",
        0xF1 => "access denied",
        0xF4 => "invalid data",
        0xF6 => "throttled",
        0xFD => "not found",
        0xFE => "timed out",
        _ => "unknown error",
    };
    format!("propagation node error {code:#x}: {reason}")
}

async fn get(handle: &LinkSessionHandle, request: Value) -> Result<Value, String> {
    let response = handle
        .request(MESSAGE_GET_PATH, &encode(&request), Some(REQUEST_TIMEOUT))
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    match rmpv::decode::read_value(&mut response.data.as_slice()) {
        Ok(Value::Integer(code)) => Err(peer_error(code.as_u64().unwrap_or(0))),
        Ok(other) => Ok(other),
        Err(e) => Err(format!("unreadable reply: {e}")),
    }
}

/// Fetch from each node every `interval`, for as long as the bouncer runs.
pub async fn run(shared: Arc<Shared>, nodes: Vec<[u8; 16]>, interval: Duration) {
    tokio::time::sleep(FIRST_FETCH_DELAY).await;
    // Messages that could not be opened stay on the node; don't fetch them
    // again each time.
    let mut skip = Skip::default();
    let user = Holder {
        identity: shared.identity.clone(),
        address: shared.store.user_address(),
        rings: shared.rings.clone(),
        old: false,
    };
    let holders: Vec<Holder> = std::iter::once(user)
        .chain(shared.old.iter().map(|o| Holder {
            identity: o.identity.clone(),
            address: o.address,
            rings: o.rings.clone(),
            old: true,
        }))
        .collect();
    loop {
        skip.expire();
        let mut result = UpstreamResult::default();
        for &node in &nodes {
            for holder in &holders {
                let one = fetch(&shared, node, holder, &mut skip).await;
                result.at = one.at;
                result.stored += one.stored;
                result.duplicates += one.duplicates;
                result.failed += one.failed;
                if result.error.is_none() {
                    result.error = one.error.map(|e| {
                        let e = if holder.old {
                            format!("for old address {}: {e}", hex::encode(holder.address))
                        } else {
                            e
                        };
                        if nodes.len() > 1 {
                            format!("{}: {e}", hex::encode(node))
                        } else {
                            e
                        }
                    });
                }
            }
        }
        result.ok = result.error.is_none();
        match &result.error {
            None if result.stored + result.failed > 0 => tracing::info!(
                "upstream fetch: {} new, {} held already, {} not stored",
                result.stored,
                result.duplicates,
                result.failed
            ),
            None => tracing::debug!("upstream fetch: nothing new"),
            Some(e) => tracing::warn!("upstream fetch failed: {e}"),
        }
        *shared.last_upstream.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
        tokio::time::sleep(interval).await;
    }
}

/// An identity to fetch messages for: the user's, or an old one.
struct Holder {
    identity: Identity,
    address: [u8; 16],
    rings: Vec<std::path::PathBuf>,
    old: bool,
}

async fn fetch(shared: &Arc<Shared>, node: [u8; 16], holder: &Holder, skip: &mut Skip) -> UpstreamResult {
    let mut result = UpstreamResult {
        at: now(),
        ..UpstreamResult::default()
    };
    if let Err(e) = shared.runtime.await_path(node, PATH_TIMEOUT).await {
        result.error = Some(format!("no path to the node: {e}"));
        return result;
    }
    let options = LinkConnectOptions {
        path_timeout: PATH_TIMEOUT,
        client_label: "lxmf-bouncer.upstream".into(),
        identify: true,
        // Given explicitly: otherwise the runtime asks the transport for hop
        // count and first-hop timeout, which a shared-instance client can
        // only do over rnsd's RPC socket (with rnsd's RPC key).
        establishment_timeout: Some(LINK_TIMEOUT),
        ..LinkConnectOptions::default()
    };
    let session = match shared
        .runtime
        .connect_link(node, holder.identity.clone(), options)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            result.error = Some(format!("no Link to the node: {e}"));
            return result;
        }
    };
    let LinkSession { handle, .. } = session;
    if let Err(e) = fetch_on(shared, &handle, holder, skip, &mut result).await {
        result.error = Some(e);
    }
    handle.close().await;
    result.ok = result.error.is_none();
    result
}

async fn fetch_on(
    shared: &Arc<Shared>,
    handle: &LinkSessionHandle,
    holder: &Holder,
    skip: &mut Skip,
    result: &mut UpstreamResult,
) -> Result<(), String> {
    let Value::Array(listed) = get(handle, Value::Array(vec![Value::Nil, Value::Nil])).await? else {
        return Err("unexpected message list".into());
    };
    let mut waiting: Vec<Value> = listed
        .into_iter()
        .filter(|id| id.as_slice().is_some_and(|id| !skip.contains(id)))
        .collect();
    let address = holder.address;
    for _ in 0..MAX_ROUNDS {
        if waiting.is_empty() {
            break;
        }
        let request = Value::Array(vec![
            Value::Array(waiting.clone()),
            Value::Array(Vec::new()),
            Value::F64(DOWNLOAD_LIMIT_KB),
        ]);
        let Value::Array(blobs) = get(handle, request).await? else {
            return Err("unexpected message data".into());
        };
        if blobs.is_empty() {
            // What is left doesn't fit in one download; leave it for a
            // client limit the node can meet (or a larger one next time).
            break;
        }
        let mut held = Vec::new();
        for blob in blobs.iter().filter_map(|b| b.as_slice()) {
            let id = rns_crypto::sha::full_hash(blob).to_vec();
            waiting.retain(|wanted| wanted.as_slice() != Some(id.as_slice()));
            if blob.len() <= 16 || blob[..16] != address {
                skip.insert(id);
                result.failed += 1;
                continue;
            }
            let (identity, rings, ciphertext) = (holder.identity.clone(), holder.rings.clone(), blob[16..].to_vec());
            let opened = tokio::task::spawn_blocking(move || crate::ratchets::decrypt(&identity, &rings, &ciphertext))
                .await
                .map_err(|e| e.to_string())?;
            let plaintext = match opened {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    tracing::warn!(
                        "a message on the upstream node could not be decrypted ({e}); it was probably \
                         encrypted to a ratchet of a client that announced this identity (see extra_ratchets)"
                    );
                    skip.insert(id);
                    result.failed += 1;
                    continue;
                }
            };
            let mut full = address.to_vec();
            full.extend_from_slice(&plaintext);
            // As stored: moved to the user's address when it came to an old one.
            let mut as_stored = shared.store.user_address().to_vec();
            as_stored.extend_from_slice(&full[16..]);
            let message_id = lxmf_core::message_api::LxMessage::unpack(&as_stored)
                .ok()
                .map(|m| m.message_id());
            let known = message_id.is_some_and(|id| shared.store.knows(&id));
            if take_in_for(shared, full, Via::Upstream, holder.old.then_some(address)).await {
                if known {
                    result.duplicates += 1;
                } else {
                    result.stored += 1;
                }
                held.push(Value::Binary(id));
            } else {
                skip.insert(id);
                result.failed += 1;
            }
        }
        // The bouncer holds these now: the node can drop them.
        if !held.is_empty()
            && let Err(e) = get(handle, Value::Array(vec![Value::Nil, Value::Array(held)])).await
        {
            tracing::warn!("upstream node did not take the purge: {e}");
        }
    }
    Ok(())
}

/// Pass messages queued for upstream node `index` to it: when one is
/// queued, and every few minutes while any wait.
pub async fn forward_loop(shared: Arc<Shared>, index: usize) {
    tokio::time::sleep(FIRST_FETCH_DELAY).await;
    let queue = &shared.upstreams[index];
    let node = queue.node;
    loop {
        let outbox = queue.outbox.clone();
        let pending = tokio::task::spawn_blocking(move || outbox.pending())
            .await
            .unwrap_or_default();
        if !pending.is_empty() {
            let waiting = pending.len();
            match forward(&shared, index, pending).await {
                Ok(sent) if sent == waiting => {}
                Ok(sent) => {
                    tracing::warn!("passed {sent} of {waiting} outgoing message(s) upstream; retrying the rest later")
                }
                Err(e) => tracing::warn!(
                    "could not pass {waiting} outgoing message(s) to {}: {e}; retrying in {} min",
                    hex::encode(node),
                    FORWARD_RETRY.as_secs() / 60
                ),
            }
        }
        tokio::select! {
            _ = queue.ready.notified() => {}
            _ = tokio::time::sleep(FORWARD_RETRY) => {}
        }
    }
}

async fn forward(shared: &Arc<Shared>, index: usize, pending: Vec<crate::outbox::Queued>) -> Result<usize, String> {
    let queue = &shared.upstreams[index];
    let node = queue.node;
    shared
        .runtime
        .await_path(node, PATH_TIMEOUT)
        .await
        .map_err(|e| format!("no path to the node: {e}"))?;
    // The stamp cost the node announced; a node that hasn't been heard
    // gets the default cost.
    let cost = match shared.runtime.recall(node).await {
        Ok(Some(known)) => known
            .app_data
            .as_deref()
            .and_then(lxmf_core::handlers::pn_stamp_cost_from_app_data)
            .unwrap_or(lxmf_core::constants::PROPAGATION_COST),
        _ => lxmf_core::constants::PROPAGATION_COST,
    };
    let options = LinkConnectOptions {
        path_timeout: PATH_TIMEOUT,
        client_label: "lxmf-bouncer.forward".into(),
        // Python LXMF clients don't identify to send either.
        identify: false,
        establishment_timeout: Some(LINK_TIMEOUT),
        ..LinkConnectOptions::default()
    };
    let LinkSession { handle, .. } = shared
        .runtime
        .connect_link(node, shared.identity.clone(), options)
        .await
        .map_err(|e| format!("no Link to the node: {e}"))?;
    let mut sent = 0;
    let mut failure = None;
    for queued in pending {
        let id = queued.transient_id;
        let stamp = tokio::task::spawn_blocking(move || {
            lxmf_core::stamper::generate_stamp(&id, cost, lxmf_core::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS_PN)
        })
        .await
        .ok()
        .flatten();
        let Some((stamp, _)) = stamp else {
            failure = Some(format!("could not make a stamp of cost {cost}"));
            break;
        };
        let mut blob = queued.data;
        blob.extend_from_slice(&stamp);
        let wrapper = encode(&Value::Array(vec![
            Value::F64(now()),
            Value::Array(vec![Value::Binary(blob)]),
        ]));
        let transfer = match handle.send_resource_bytes(wrapper, ResourceOptions::default()).await {
            Ok(transfer) => transfer,
            Err(e) => {
                failure = Some(format!("could not start the transfer: {e}"));
                break;
            }
        };
        match tokio::time::timeout(RESOURCE_TIMEOUT, transfer.concluded()).await {
            Ok(Ok(_)) => {
                let outbox = queue.outbox.clone();
                let _ = tokio::task::spawn_blocking(move || outbox.remove(&id)).await;
                shared
                    .counters
                    .sent_upstream
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::info!("passed outgoing message {} to {}", hex::encode(id), hex::encode(node));
                sent += 1;
            }
            Ok(Err(e)) => {
                failure = Some(format!("the node did not take message {}: {e}", hex::encode(id)));
                break;
            }
            Err(_) => {
                failure = Some(format!("sending message {} timed out", hex::encode(id)));
                break;
            }
        }
    }
    handle.close().await;
    match failure {
        Some(e) if sent == 0 => Err(e),
        Some(e) => {
            tracing::warn!("{e}");
            Ok(sent)
        }
        None => Ok(sent),
    }
}
