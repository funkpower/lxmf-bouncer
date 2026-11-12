// SPDX-License-Identifier: LicenseRef-Reticulum
//! The message store: rsLXMF's propagation node store, holding every
//! message for the user encrypted for the user, as a propagation node holds
//! messages, plus a ledger of which messages (by LXMF message ID) are in it.
//!
//! The ledger stops the same message being stored twice when it arrives by
//! more than one route (directly and from the upstream node, or resent by a
//! sender that missed the delivery proof). Each copy put in the store is
//! encrypted afresh, so its transient ID (the hash of the ciphertext) is no
//! use for that.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use lxmf_core::message_api::LxMessage;
use lxmf_core::propagation_node::{
    PropagationAdmission, PropagationNode, PropagationNodeConfig, ValidatedOpaquePropagationBlob,
};
use rmpv::Value;
use rns_identity::identity::Identity;
use serde::{Deserialize, Serialize};

/// Propagation node error codes, as `/get` answers them (Python `LXMPeer`).
pub const ERROR_NO_IDENTITY: u8 = 0xF0;
pub const ERROR_NO_ACCESS: u8 = 0xF1;

/// What the ledger keeps about one stored message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntry {
    /// Transient ID of the copy in the store (hex).
    pub transient_id: String,
    /// The sender's LXMF address (hex).
    pub source: String,
    /// When it was stored (Unix seconds).
    pub stored_at: f64,
    /// Size of the stored copy, in bytes.
    pub size: usize,
    /// How it came: `direct` or `upstream`.
    pub via: String,
}

/// How a message reached the bouncer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Direct,
    Upstream,
}

impl Via {
    fn label(self) -> &'static str {
        match self {
            Via::Direct => "direct",
            Via::Upstream => "upstream",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// Stored, with this message ID and transient ID.
    Stored {
        message_id: [u8; 32],
        transient_id: [u8; 32],
    },
    /// Already stored.
    Duplicate { message_id: [u8; 32] },
}

/// A summary of the store, for logs and `status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub messages: usize,
    pub bytes: usize,
    pub oldest: Option<f64>,
    pub newest: Option<f64>,
    /// Messages held per sender address.
    pub by_sender: BTreeMap<String, usize>,
}

struct Inner {
    node: PropagationNode,
    ledger: HashMap<String, LedgerEntry>,
}

pub struct Store {
    inner: Mutex<Inner>,
    ledger_path: PathBuf,
    /// The user's LXMF address and public identity, to encrypt for.
    user_address: [u8; 16],
    user: Identity,
    expiry: Duration,
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("writing to a Vec");
    out
}

/// A propagation node error code, as `/get` answers it.
pub fn error_reply(code: u8) -> Vec<u8> {
    encode(&Value::from(code))
}

/// Rewrite a client's `/get` request so the client's "haves" (messages it
/// already holds, which a propagation node would delete) are ignored: every
/// client of the user gets its own copy, until the message expires.
///
/// Returns the request to give the node, or `Err` with the reply to send
/// straight back (a purge-only request is answered with an empty list, as
/// Python's node answers it; malformed input with nil).
pub fn without_haves(request: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let nil = vec![0xc0];
    let Ok(Value::Array(mut parts)) = rmpv::decode::read_value(&mut &request[..]) else {
        return Err(nil);
    };
    if !(2..=3).contains(&parts.len()) {
        return Err(nil);
    }
    match (&parts[0], &parts[1]) {
        (Value::Nil, Value::Nil) => Ok(request.to_vec()),
        (Value::Nil, _) => Err(encode(&Value::Array(Vec::new()))),
        _ => {
            parts[1] = Value::Nil;
            Ok(encode(&Value::Array(parts)))
        }
    }
}

impl Store {
    /// Open (or create) the store for the user's identity.
    pub fn open(
        store_dir: &Path,
        ledger_path: &Path,
        user: &Identity,
        node_hash: [u8; 16],
        max_bytes: usize,
        expiry: Duration,
    ) -> Result<Self, String> {
        let user_address =
            rns_identity::destination::Destination::hash_from_name_and_identity("lxmf.delivery", Some(&user.hash));
        let config = PropagationNodeConfig {
            max_storage: max_bytes,
            max_message_age: expiry.as_secs(),
            // Clients never send to this node (it only serves), and its own
            // copies carry no proof of work.
            min_stamp_cost: 0,
            max_message_size: usize::MAX,
            ..PropagationNodeConfig::default()
        };
        let node = PropagationNode::with_storage(config, node_hash, store_dir.to_path_buf())
            .map_err(|e| format!("could not open the message store {}: {e}", store_dir.display()))?;
        let ledger = match std::fs::read(ledger_path) {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", ledger_path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(format!("{}: {e}", ledger_path.display())),
        };
        let public = Identity::from_public_key(&user.get_public_key()).map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Mutex::new(Inner { node, ledger }),
            ledger_path: ledger_path.to_path_buf(),
            user_address,
            user: public,
            expiry,
        })
    }

    pub fn user_address(&self) -> [u8; 16] {
        self.user_address
    }

    fn save_ledger(&self, ledger: &HashMap<String, LedgerEntry>) -> Result<(), String> {
        let data = serde_json::to_vec(ledger).map_err(|e| e.to_string())?;
        write_atomic(&self.ledger_path, &data).map_err(|e| format!("{}: {e}", self.ledger_path.display()))
    }

    /// Store one complete LXMF message for the user (destination hash,
    /// source, signature, payload: the bytes as signed). It is encrypted for
    /// the user, as a sender encrypts a propagated message, so clients
    /// holding the identity can download it from the node. Blocking.
    pub fn ingest(&self, packed: &[u8], via: Via) -> Result<Ingested, String> {
        let message = LxMessage::unpack(packed).map_err(|e| format!("not an LXMF message: {e}"))?;
        if message.destination_hash() != self.user_address {
            return Err(format!(
                "addressed to {}, not to the user",
                hex::encode(message.destination_hash())
            ));
        }
        let message_id = message.message_id();
        let key = hex::encode(message_id);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.ledger.contains_key(&key) {
            return Ok(Ingested::Duplicate { message_id });
        }
        let ciphertext = self
            .user
            .encrypt(&packed[16..], None)
            .map_err(|e| format!("could not encrypt: {e}"))?;
        let mut blob = Vec::with_capacity(16 + ciphertext.len() + 32);
        blob.extend_from_slice(&self.user_address);
        blob.extend_from_slice(&ciphertext);
        // The propagation stamp slot: this node asks no work of itself, and
        // the stamp is stripped before clients download the message.
        let stamp: [u8; 32] = rand::random();
        blob.extend_from_slice(&stamp);
        let size = blob.len();
        let validated =
            ValidatedOpaquePropagationBlob::validate(blob.into(), 0).ok_or("message too large for the store")?;
        let transient_id = validated.transient_id();
        let plan = match inner.node.plan_opaque_admission(validated) {
            PropagationAdmission::Reserved(plan) => plan,
            PropagationAdmission::Rejected => return Err("the store is full (see [store] max_size_mb)".into()),
            _ => return Err("the store already holds this copy".into()),
        };
        match plan.persist() {
            Ok(persisted) => {
                if !inner.node.commit_store_write(persisted) {
                    return Err("the store did not take the message".into());
                }
            }
            Err(e) => {
                inner.node.abort_store_write(&transient_id, size);
                return Err(format!("could not write the message: {e}"));
            }
        }
        inner.ledger.insert(
            key,
            LedgerEntry {
                transient_id: hex::encode(transient_id),
                source: hex::encode(message.source_hash()),
                stored_at: now(),
                size,
                via: via.label().into(),
            },
        );
        if let Err(e) = self.save_ledger(&inner.ledger) {
            // The message is stored; only its dedupe record could be lost.
            tracing::warn!("could not save the ledger: {e}");
        }
        Ok(Ingested::Stored {
            message_id,
            transient_id,
        })
    }

    /// Whether a message (by LXMF message ID) is held, or was until it
    /// expired.
    pub fn knows(&self, message_id: &[u8; 32]) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ledger
            .contains_key(&hex::encode(message_id))
    }

    /// Answer a `/get` request from the client whose LXMF address is
    /// `client`. Messages are served but never deleted for a client (see
    /// [`without_haves`]). Blocking (reads message files).
    pub fn handle_get(&self, request: &[u8], client: &[u8; 16]) -> (Vec<u8>, u64) {
        let request = match without_haves(request) {
            Ok(request) => request,
            Err(reply) => return (reply, 0),
        };
        let action = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .node
            .handle_get_request(&request, client);
        action.into_response_with_served_count()
    }

    /// Drop expired messages (and, past the size limit, the oldest), and
    /// forget ledger entries for messages long gone. Blocking.
    pub fn maintain(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.node.tick();
        // Keep a message's ID a day past its expiry, so a late copy from
        // upstream is not taken in again as new.
        let forget_before = now() - self.expiry.as_secs_f64() - 86_400.0;
        let before = inner.ledger.len();
        inner.ledger.retain(|_, entry| entry.stored_at >= forget_before);
        if inner.ledger.len() != before
            && let Err(e) = self.save_ledger(&inner.ledger)
        {
            tracing::warn!("could not save the ledger: {e}");
        }
    }

    pub fn summary(&self) -> Summary {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut summary = Summary {
            messages: inner.node.message_count(),
            bytes: inner.node.total_size(),
            ..Summary::default()
        };
        for entry in inner.ledger.values() {
            let Some(id) = hex::decode(&entry.transient_id)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
            else {
                continue;
            };
            if !inner.node.contains(&id) {
                continue;
            }
            *summary.by_sender.entry(entry.source.clone()).or_default() += 1;
            summary.oldest = Some(summary.oldest.map_or(entry.stored_at, |o: f64| o.min(entry.stored_at)));
            summary.newest = Some(summary.newest.map_or(entry.stored_at, |n: f64| n.max(entry.stored_at)));
        }
        summary
    }
}

/// Write a file by writing a temporary one beside it and renaming it over.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lxmf_core::message_api::{DeliveryMethod, LxMessageDraft};

    fn signed(sender: &Identity, to: [u8; 16], content: &str, at: f64) -> Vec<u8> {
        let from =
            rns_identity::destination::Destination::hash_from_name_and_identity("lxmf.delivery", Some(&sender.hash));
        let mut draft = LxMessageDraft::new(to, from, "a title", content, DeliveryMethod::Direct).unwrap();
        draft.set_timestamp(at).unwrap();
        let signed = draft.sign(&sender.get_signing_key().unwrap()).unwrap();
        signed.finalize(None).unwrap().pack().unwrap()
    }

    fn get(store: &Store, request: Value, client: &[u8; 16]) -> Value {
        let (reply, _) = store.handle_get(&encode(&request), client);
        rmpv::decode::read_value(&mut reply.as_slice()).unwrap()
    }

    #[test]
    fn haves_are_ignored_and_purges_answered_empty() {
        let list = encode(&Value::Array(vec![Value::Nil, Value::Nil]));
        assert_eq!(without_haves(&list), Ok(list.clone()));
        let id = Value::Binary(vec![1; 32]);
        let get = encode(&Value::Array(vec![
            Value::Array(vec![id.clone()]),
            Value::Array(vec![id.clone()]),
            Value::F64(100.0),
        ]));
        let rewritten = rmpv::decode::read_value(&mut without_haves(&get).unwrap().as_slice()).unwrap();
        assert_eq!(
            rewritten,
            Value::Array(vec![Value::Array(vec![id.clone()]), Value::Nil, Value::F64(100.0)])
        );
        let purge = encode(&Value::Array(vec![Value::Nil, Value::Array(vec![id])]));
        assert_eq!(without_haves(&purge), Err(vec![0x90]));
        assert_eq!(without_haves(&[0x01]), Err(vec![0xc0]));
    }

    #[test]
    fn messages_are_stored_once_served_to_every_client_and_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, ledger) = (dir.path().join("messagestore"), dir.path().join("ledger.json"));
        let user = Identity::new();
        let sender = Identity::new();
        let store = Store::open(
            &store_dir,
            &ledger,
            &user,
            [5; 16],
            1_000_000,
            Duration::from_secs(86_400),
        )
        .unwrap();
        let address = store.user_address();
        let packed = signed(&sender, address, "hello there", 1_800_000_000.0);

        let Ingested::Stored {
            message_id,
            transient_id,
        } = store.ingest(&packed, Via::Direct).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            store.ingest(&packed, Via::Upstream).unwrap(),
            Ingested::Duplicate { message_id }
        );
        assert!(store.knows(&message_id));
        // For someone else: refused.
        assert!(store.ingest(&signed(&sender, [7; 16], "x", 1.0), Via::Direct).is_err());

        // Listed for the user; a second client listing (and claiming to have
        // it) does not delete it.
        let listed = get(&store, Value::Array(vec![Value::Nil, Value::Nil]), &address);
        assert_eq!(listed, Value::Array(vec![Value::Binary(transient_id.to_vec())]));
        let want = Value::Array(vec![Value::Binary(transient_id.to_vec())]);
        for _ in 0..2 {
            let Value::Array(blobs) = get(&store, Value::Array(vec![want.clone(), want.clone()]), &address) else {
                panic!()
            };
            assert_eq!(blobs.len(), 1);
            let blob = blobs[0].as_slice().unwrap();
            // As a client checks it: the transient ID is the hash of what came.
            assert_eq!(rns_crypto::sha::full_hash(blob), transient_id);
            assert_eq!(&blob[..16], &address);
            let plain = user.decrypt(&blob[16..], None, false).unwrap();
            assert_eq!(&plain[..], &packed[16..]);
            let mut full = address.to_vec();
            full.extend_from_slice(&plain);
            let message = LxMessage::unpack(&full).unwrap();
            assert_eq!(message.content_text(), "hello there");
            assert!(message.verify(&sender.get_public_key()).is_ok());
            get(&store, Value::Array(vec![Value::Nil, want.clone()]), &address);
        }
        // Not for another address.
        assert_eq!(
            get(&store, Value::Array(vec![Value::Nil, Value::Nil]), &[9; 16]),
            Value::Array(vec![])
        );
        assert_eq!(store.summary().messages, 1);
        drop(store);

        let store = Store::open(
            &store_dir,
            &ledger,
            &user,
            [5; 16],
            1_000_000,
            Duration::from_secs(86_400),
        )
        .unwrap();
        let summary = store.summary();
        assert_eq!(summary.messages, 1);
        assert_eq!(summary.by_sender.values().sum::<usize>(), 1);
        assert_eq!(
            store.ingest(&packed, Via::Direct).unwrap(),
            Ingested::Duplicate { message_id }
        );
    }

    #[test]
    fn a_full_store_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let user = Identity::new();
        let store = Store::open(
            &dir.path().join("m"),
            &dir.path().join("l.json"),
            &user,
            [5; 16],
            100,
            Duration::from_secs(60),
        )
        .unwrap();
        let sender = Identity::new();
        let address = store.user_address();
        // The first may cross the limit (as Python's node allows); the next not.
        store
            .ingest(&signed(&sender, address, &"a".repeat(200), 1.0), Via::Direct)
            .unwrap();
        assert!(store.ingest(&signed(&sender, address, "b", 2.0), Via::Direct).is_err());
    }
}
