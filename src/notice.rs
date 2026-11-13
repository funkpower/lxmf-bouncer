// SPDX-License-Identifier: LicenseRef-Reticulum
//! Telling people who still write to an old address the user's current one.
//!
//! A message to an old address reaches the apps with a signature that no
//! longer matches (it covers the old address), so they mark it invalid. The
//! only cure is for the sender to write to the current address. When an old
//! identity has `notify_senders`, the bouncer sends each such sender one
//! message from that old address saying where the user is now, and records
//! that it did once the sender's side proves receipt.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lxmf_core::message_api::{DeliveryMethod, LxMessageDraft, RecipientStamp};
use rns_identity::destination::{DestType, Destination, Direction};
use rns_runtime::prelude::*;

use crate::bouncer::{DELIVERY_ASPECT, Shared, now};
use crate::store::write_atomic;

const PATH_TIMEOUT: Duration = Duration::from_secs(30);
const PROOF_TIMEOUT: Duration = Duration::from_secs(60);
/// Don't try the same sender again sooner than this after a failed attempt.
const RETRY_AFTER: f64 = 60.0 * 60.0;

/// Who has been told, by old address and sender (hex), with when.
pub struct Notices {
    path: PathBuf,
    sent: Mutex<BTreeMap<String, f64>>,
    tried: Mutex<BTreeMap<String, f64>>,
}

fn key(old: &[u8; 16], sender: &[u8; 16]) -> String {
    format!("{}:{}", hex::encode(old), hex::encode(sender))
}

impl Notices {
    pub fn open(path: PathBuf) -> Self {
        let sent = std::fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        Self {
            path,
            sent: Mutex::new(sent),
            tried: Mutex::new(BTreeMap::new()),
        }
    }

    /// Should `sender` be told now? Claims the attempt if so.
    fn claim(&self, old: &[u8; 16], sender: &[u8; 16]) -> bool {
        let k = key(old, sender);
        if self.sent.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&k) {
            return false;
        }
        let mut tried = self.tried.lock().unwrap_or_else(|e| e.into_inner());
        if tried.get(&k).is_some_and(|at| now() - at < RETRY_AFTER) {
            return false;
        }
        tried.insert(k, now());
        true
    }

    fn record(&self, old: &[u8; 16], sender: &[u8; 16]) {
        let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        sent.insert(key(old, sender), now());
        match serde_json::to_vec_pretty(&*sent) {
            Ok(data) => {
                if let Err(e) = write_atomic(&self.path, &data) {
                    tracing::warn!("could not write {}: {e}", self.path.display());
                }
            }
            Err(e) => tracing::warn!("could not encode the notices: {e}"),
        }
    }
}

/// The notice's text.
pub fn text(current: &[u8; 16]) -> String {
    format!(
        "This address is no longer in use. Please write to me at {} instead. \
         Messages sent here still reach me for now, but show as unverified.",
        hex::encode(current)
    )
}

/// Tell `sender`, who wrote to the old address `old`, the user's current
/// address, unless that was done already (or tried within the hour).
pub async fn tell(shared: Arc<Shared>, old: [u8; 16], sender: [u8; 16]) {
    let Some(identity) = shared.old.iter().find(|o| o.address == old).map(|o| o.identity.clone()) else {
        return;
    };
    if sender == shared.store.user_address() || shared.old.iter().any(|o| o.address == sender) {
        return;
    }
    if !shared.notices.claim(&old, &sender) {
        return;
    }
    match send(&shared, &identity, old, sender).await {
        Ok(()) => {
            shared.notices.record(&old, &sender);
            tracing::info!(
                "told {} (writing to old address {}) to use {}",
                hex::encode(sender),
                hex::encode(old),
                hex::encode(shared.store.user_address())
            );
        }
        Err(e) => tracing::warn!(
            "could not tell {} about the current address (will try again on their next message after an hour): {e}",
            hex::encode(sender)
        ),
    }
}

async fn send(shared: &Arc<Shared>, identity: &Identity, old: [u8; 16], sender: [u8; 16]) -> Result<(), String> {
    if !shared.runtime.has_path(sender).await.unwrap_or(false) {
        shared
            .runtime
            .await_path(sender, PATH_TIMEOUT)
            .await
            .map_err(|e| format!("no path: {e}"))?;
    }
    let recalled = shared
        .runtime
        .recall(sender)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("the sender's key isn't known")?;
    let cost = recalled
        .app_data
        .as_deref()
        .and_then(lxmf_core::handlers::stamp_cost_from_app_data)
        .unwrap_or(0);
    let draft = LxMessageDraft::new(
        sender,
        old,
        "",
        &text(&shared.store.user_address()),
        DeliveryMethod::Opportunistic,
    )
    .map_err(|e| e.to_string())?;
    let signer = identity.clone();
    let message = tokio::task::spawn_blocking(move || {
        let signed = draft
            .sign_with(|bytes| signer.sign(bytes).ok_or("the old identity can't sign"))
            .map_err(|e| e.to_string())?;
        let stamp = if cost > 0 {
            let (stamp, _) = lxmf_core::stamper::generate_stamp(
                &signed.message_id(),
                cost,
                lxmf_core::constants::STAMP_WORKBLOCK_EXPAND_ROUNDS,
            )
            .ok_or_else(|| format!("could not make a stamp of cost {cost}"))?;
            Some(RecipientStamp::ProofOfWork(stamp))
        } else {
            None
        };
        signed.finalize(stamp).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    let packed = message.pack().map_err(|e| e.to_string())?;
    let destination = Destination::new(Some(&recalled.identity), Direction::Out, DestType::Single, DELIVERY_ASPECT)
        .map_err(|e| e.to_string())?;
    // Opportunistic: the packet carries the message without the destination hash.
    let sent = shared
        .runtime
        .send_to(
            &destination,
            &packed[16..],
            SendOptions {
                create_receipt: true,
                timeout: Some(PROOF_TIMEOUT),
                ..SendOptions::default()
            },
        )
        .await
        .map_err(|e| e.to_string())?;
    let receipt = sent.receipt.ok_or("no receipt")?;
    let mut status = receipt.watch();
    loop {
        match *status.borrow_and_update() {
            PacketReceiptStatus::Delivered { .. } => return Ok(()),
            PacketReceiptStatus::Sent => {}
            other => return Err(format!("not delivered ({other:?})")),
        }
        if status.changed().await.is_err() {
            return Err("receipt dropped".into());
        }
    }
}
