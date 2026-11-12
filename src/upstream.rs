// SPDX-License-Identifier: LicenseRef-Reticulum
//! Fetching the user's messages from another propagation node (one that
//! people sending to the user may have used), as a client holding the
//! user's identity would, and keeping them in the bouncer's own store.
//!
//! The protocol is Python LXMF's `request_messages_from_propagation_node`:
//! a Link identified as the user, `/get [nil, nil]` for the list, `/get
//! [wants, haves, limit]` for the messages, then `/get [nil, received]` so
//! the node drops what the bouncer now holds.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use lxmf_core::constants::MESSAGE_GET_PATH;
use rmpv::Value;
use rns_runtime::prelude::*;

use crate::bouncer::{Shared, UpstreamResult, now, take_in};
use crate::store::Via;

const FIRST_FETCH_DELAY: Duration = Duration::from_secs(20);
const PATH_TIMEOUT: Duration = Duration::from_secs(30);
const LINK_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Most kilobytes asked for in one download.
const DOWNLOAD_LIMIT_KB: f64 = 1000.0;
/// Downloads in one fetch, at most.
const MAX_ROUNDS: usize = 100;

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

/// Fetch every `interval`, for as long as the bouncer runs.
pub async fn run(shared: Arc<Shared>, node: [u8; 16], interval: Duration) {
    tokio::time::sleep(FIRST_FETCH_DELAY).await;
    // Messages that could not be opened stay on the node; don't fetch them
    // again each time.
    let mut skip: HashSet<Vec<u8>> = HashSet::new();
    loop {
        let result = fetch(&shared, node, &mut skip).await;
        match &result.error {
            None if result.stored + result.failed > 0 => tracing::info!(
                "upstream fetch: {} new, {} held already, {} not stored",
                result.stored,
                result.duplicates,
                result.failed
            ),
            None => tracing::debug!("upstream fetch: nothing new"),
            Some(e) => tracing::warn!("upstream fetch from {} failed: {e}", hex::encode(node)),
        }
        *shared.last_upstream.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
        tokio::time::sleep(interval).await;
    }
}

async fn fetch(shared: &Arc<Shared>, node: [u8; 16], skip: &mut HashSet<Vec<u8>>) -> UpstreamResult {
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
        .connect_link(node, shared.identity.clone(), options)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            result.error = Some(format!("no Link to the node: {e}"));
            return result;
        }
    };
    let LinkSession { handle, .. } = session;
    if let Err(e) = fetch_on(shared, &handle, skip, &mut result).await {
        result.error = Some(e);
    }
    handle.close().await;
    result.ok = result.error.is_none();
    result
}

async fn fetch_on(
    shared: &Arc<Shared>,
    handle: &LinkSessionHandle,
    skip: &mut HashSet<Vec<u8>>,
    result: &mut UpstreamResult,
) -> Result<(), String> {
    let Value::Array(listed) = get(handle, Value::Array(vec![Value::Nil, Value::Nil])).await? else {
        return Err("unexpected message list".into());
    };
    let mut waiting: Vec<Value> = listed
        .into_iter()
        .filter(|id| id.as_slice().is_some_and(|id| !skip.contains(id)))
        .collect();
    let address = shared.store.user_address();
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
            let (identity, rings, ciphertext) = (shared.identity.clone(), shared.rings.clone(), blob[16..].to_vec());
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
            let message_id = lxmf_core::message_api::LxMessage::unpack(&full)
                .ok()
                .map(|m| m.message_id());
            let known = message_id.is_some_and(|id| shared.store.knows(&id));
            if take_in(shared, full, Via::Upstream).await {
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
