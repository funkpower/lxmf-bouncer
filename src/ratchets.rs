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

/// Add the private keys of `extra` rings to the end of `own` (the ring the
/// live address decrypts with), so packets encrypted to an app's old ratchet
/// can be read on arrival. `own` is created if missing; its newest key, the
/// one announced, stays first. Returns how many keys were added.
pub fn merge_into(identity: &Identity, own: &Path, extra: &[PathBuf]) -> Result<usize, String> {
    use rns_identity::destination::Destination;
    use rns_identity::ratchet::PersistentRatchetRing;
    let fail = |e: std::io::Error| format!("ratchet file {}: {e}", own.display());
    PersistentRatchetRing::open(own, identity)
        .and_then(|mut ring| ring.ensure_current(identity))
        .map_err(fail)?;
    let mut keys = RatchetRing::load_verified(own, identity)
        .map_err(fail)?
        .ring()
        .private_keys()
        .to_vec();
    let before = keys.len();
    for key in load_keys(identity, extra) {
        if keys.len() >= Destination::RATCHET_COUNT {
            break;
        }
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    let added = keys.len() - before;
    if added == 0 {
        return Ok(0);
    }
    // The file as Python RNS writes it: {signature, ratchets}, the ratchets
    // a packed list of keys signed by the identity.
    let mut packed = Vec::new();
    let list = rmpv::Value::Array(keys.iter().map(|k| rmpv::Value::Binary(k.to_vec())).collect());
    rmpv::encode::write_value(&mut packed, &list).map_err(|e| e.to_string())?;
    let signature = identity.sign(&packed).ok_or("the identity can't sign")?;
    let file = rmpv::Value::Map(vec![
        ("signature".into(), rmpv::Value::Binary(signature.to_vec())),
        ("ratchets".into(), rmpv::Value::Binary(packed)),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &file).map_err(|e| e.to_string())?;
    crate::store::write_atomic(own, &data).map_err(fail)?;
    RatchetRing::load_verified(own, identity).map_err(fail)?;
    Ok(added)
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

    #[test]
    fn merges_app_ratchets_into_the_live_ring() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::new();
        let public = Identity::from_public_key(&identity.get_public_key()).unwrap();
        let (own, app) = (dir.path().join("own.ratchets"), dir.path().join("app.ratchets"));
        let app_key = PersistentRatchetRing::open(&app, &identity)
            .unwrap()
            .ensure_current(&identity)
            .unwrap();
        // A missing ring is created, then the app's key goes after its own.
        assert_eq!(merge_into(&identity, &own, std::slice::from_ref(&app)).unwrap(), 1);
        let mut ring = PersistentRatchetRing::open(&own, &identity).unwrap();
        assert_eq!(ring.len(), 2);
        let current = ring.ensure_current(&identity).unwrap();
        assert_ne!(current, app_key);
        let sealed = public.encrypt(b"hi", Some(&app_key)).unwrap();
        assert_eq!(decrypt(&identity, std::slice::from_ref(&own), &sealed).unwrap(), b"hi");
        // Merging again adds nothing.
        assert_eq!(merge_into(&identity, &own, &[app]).unwrap(), 0);
        // Python's ring file merges the same way.
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let python = Identity::from_file(&fixtures.join("python_identity")).unwrap();
        let own = dir.path().join("python-own.ratchets");
        assert_eq!(merge_into(&python, &own, &[fixtures.join("python.ratchets")]).unwrap(), 3);
        let sealed = std::fs::read(fixtures.join("python_ratchet_ciphertext")).unwrap();
        assert_eq!(decrypt(&python, &[own], &sealed).unwrap(), b"sealed by python to a ratchet");
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
