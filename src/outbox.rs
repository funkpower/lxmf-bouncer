// SPDX-License-Identifier: LicenseRef-Reticulum
//! Messages the user's apps send through the bouncer's propagation node, on
//! their way to the upstream node.
//!
//! An app that cannot reach a recipient directly hands the message to its
//! propagation node, which for the user's apps is the bouncer. The message
//! is already encrypted for its recipient: the bouncer can't read it and
//! doesn't need to. It keeps each one on disk until the upstream node takes
//! it, so a send survives restarts and an unreachable upstream.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::store::write_atomic;

const SUFFIX: &str = "lxm";

/// One queued message: `destination hash + ciphertext`, without a stamp
/// (each node it goes to wants a stamp of its own).
#[derive(Debug, Clone)]
pub struct Queued {
    pub transient_id: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    Queued,
    Duplicate,
}

pub struct Outbox {
    dir: PathBuf,
    max_bytes: u64,
    expiry: Duration,
    lock: Mutex<()>,
}

fn file_name(id: &[u8; 32]) -> String {
    format!("{}.{SUFFIX}", hex::encode(id))
}

impl Outbox {
    pub fn open(dir: &Path, max_bytes: u64, expiry: Duration) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            max_bytes,
            expiry,
            lock: Mutex::new(()),
        })
    }

    /// The queued files with their size and age, oldest first. Expired ones
    /// are deleted on the way.
    fn scan(&self) -> Vec<(PathBuf, [u8; 32], u64, SystemTime)> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return found;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(SUFFIX) {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| hex::decode(s).ok())
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
            else {
                continue;
            };
            let Ok(meta) = entry.metadata() else { continue };
            let queued = meta.modified().unwrap_or(now);
            if now.duration_since(queued).unwrap_or_default() > self.expiry {
                tracing::warn!(
                    "gave up on outgoing message {} (not taken upstream within the expiry)",
                    hex::encode(id)
                );
                let _ = std::fs::remove_file(&path);
                continue;
            }
            found.push((path, id, meta.len(), queued));
        }
        found.sort_by_key(|f| f.3);
        found
    }

    /// Queue one message (`destination hash + ciphertext`). Blocking.
    pub fn add(&self, data: &[u8]) -> Result<(Added, [u8; 32]), String> {
        let id = rns_crypto::sha::full_hash(data);
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join(file_name(&id));
        if path.exists() {
            return Ok((Added::Duplicate, id));
        }
        let used: u64 = self.scan().iter().map(|f| f.2).sum();
        if used + data.len() as u64 > self.max_bytes {
            return Err(format!("the outbox is full ({used} bytes queued)"));
        }
        write_atomic(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((Added::Queued, id))
    }

    /// Everything waiting, oldest first. Blocking.
    pub fn pending(&self) -> Vec<Queued> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.scan()
            .into_iter()
            .filter_map(|(path, transient_id, _, _)| {
                std::fs::read(&path).ok().map(|data| Queued { transient_id, data })
            })
            .collect()
    }

    /// Drop a message the upstream node has taken. Blocking.
    pub fn remove(&self, id: &[u8; 32]) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = std::fs::remove_file(self.dir.join(file_name(id)));
    }

    /// Messages and bytes waiting. Blocking.
    pub fn summary(&self) -> (usize, u64) {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let files = self.scan();
        (files.len(), files.iter().map(|f| f.2).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_dedupe_cap_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path(), 100, Duration::from_secs(3600)).unwrap();
        let (added, id) = outbox.add(&[1u8; 60]).unwrap();
        assert_eq!(added, Added::Queued);
        assert_eq!(outbox.add(&[1u8; 60]).unwrap().0, Added::Duplicate);
        assert!(outbox.add(&[2u8; 60]).is_err(), "over the cap");
        assert_eq!(outbox.summary(), (1, 60));
        let pending = outbox.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].transient_id, id);
        assert_eq!(pending[0].data, vec![1u8; 60]);
        // Survives reopening.
        let outbox = Outbox::open(dir.path(), 100, Duration::from_secs(3600)).unwrap();
        assert_eq!(outbox.pending().len(), 1);
        outbox.remove(&id);
        assert_eq!(outbox.summary(), (0, 0));
    }

    #[test]
    fn expired_messages_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path(), 1000, Duration::from_secs(0)).unwrap();
        outbox.add(&[3u8; 10]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(outbox.pending().is_empty());
    }
}
