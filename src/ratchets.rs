// SPDX-License-Identifier: LicenseRef-Reticulum
//! Decrypting propagated messages for the user: with the bouncer's own
//! ratchets (the ones it announces), with ratchets of clients that
//! announced the identity before the bouncer did, or with the identity key.

use std::path::{Path, PathBuf};

use rns_identity::identity::Identity;
use rns_identity::ratchet::RatchetRing;

/// The ring file for an LXMF address, named as Python LXMF names it.
pub fn ring_path(dir: &Path, address: &[u8; 16]) -> PathBuf {
    dir.join(format!("{}.ratchets", hex::encode(address)))
}

/// Private ratchet keys from `rings` (rings that do not load, or are not
/// signed by `identity`, are skipped with a warning).
pub fn load_keys(identity: &Identity, rings: &[PathBuf]) -> Vec<[u8; 32]> {
    let mut keys = Vec::new();
    for path in rings {
        match RatchetRing::load_verified(path, identity) {
            Ok(loaded) => keys.extend_from_slice(loaded.ring().private_keys()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("ratchet file {} not used: {e}", path.display()),
        }
    }
    keys
}

/// Decrypt `ciphertext` sent to the user: with any of `rings`' ratchets, or
/// the identity key.
pub fn decrypt(identity: &Identity, rings: &[PathBuf], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let keys = load_keys(identity, rings);
    let refs: Vec<&[u8; 32]> = keys.iter().collect();
    identity
        .decrypt(ciphertext, Some(&refs), false)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_identity::ratchet::PersistentRatchetRing;

    #[test]
    fn reads_messages_to_any_ring_or_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let public = Identity::from_public_key(&identity.get_public_key()).unwrap();
        let (own, old) = (ring_path(dir.path(), &[1; 16]), dir.path().join("client.ratchets"));
        let own_key = PersistentRatchetRing::open(&own, &identity)
            .unwrap()
            .ensure_current(&identity)
            .unwrap();
        let old_key = PersistentRatchetRing::open(&old, &identity)
            .unwrap()
            .ensure_current(&identity)
            .unwrap();
        let rings = vec![own.clone(), old.clone(), dir.path().join("missing.ratchets")];
        for key in [Some(&own_key), Some(&old_key), None] {
            let sealed = public.encrypt(b"hi", key).unwrap();
            assert_eq!(decrypt(&identity, &rings, &sealed).unwrap(), b"hi");
        }
        let sealed = public.encrypt(b"hi", Some(&old_key)).unwrap();
        assert!(decrypt(&identity, &[own], &sealed).is_err());
        // Another identity's ring is not trusted.
        assert!(load_keys(&Identity::new(), &[old]).is_empty());
    }

    /// A ring written by Python RNS (as NomadNet, MeshChat and Sideband
    /// keep theirs), for a throwaway fixture identity, and a ciphertext
    /// Python encrypted to its second ratchet.
    #[test]
    fn reads_python_ratchet_files() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let identity = Identity::from_file(&fixtures.join("python_identity")).unwrap();
        let rings = vec![fixtures.join("python.ratchets")];
        assert_eq!(load_keys(&identity, &rings).len(), 3);
        let sealed = std::fs::read(fixtures.join("python_ratchet_ciphertext")).unwrap();
        assert_eq!(
            decrypt(&identity, &rings, &sealed).unwrap(),
            b"sealed by python to a ratchet"
        );
        assert!(identity.decrypt(&sealed, None, false).is_err());
    }
}
