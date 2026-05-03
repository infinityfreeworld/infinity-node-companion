//! Tests d'intégration `infinity-identity`.
//!
//! Ces tests utilisent `MemoryKeyring` (impl in-memory du `SecretStore`)
//! au lieu d'`OsKeyring` parce que :
//!   - Le CI n'a pas de Keychain OS configuré.
//!   - On ne veut JAMAIS polluer le vrai Keychain de la machine de
//!     build avec des entrées de test.
//!   - Le contrat testé reste identique : tant que `OsKeyring` respecte
//!     le trait `SecretStore`, les tests garantissent le même
//!     comportement applicatif.
//!
//! Un test optionnel `#[ignore] os_keyring_smoke_test` peut être lancé
//! manuellement (`cargo test -p infinity-identity -- --ignored`) pour
//! valider l'OsKeyring sur la machine du dev (Mac : Touch ID prompt).

use infinity_identity::{
    Identity, IdentityError, MemoryKeyring, OsKeyring, PublicKey, SecretStore,
    SECRET_STORE_SERVICE,
};
use infinity_vault::Vault;
use secrecy::SecretString;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────────

fn fresh_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.ifv");
    let vault = Vault::create(
        path,
        SecretString::new("correcthorsebatterystaple".to_string()),
    )
    .expect("vault create");
    (dir, vault)
}

// ── Création + chargement ────────────────────────────────────────────

#[test]
fn create_then_sign_and_verify() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    let id = Identity::create(&vault, &kc, "default", "Mon Bâtisseur").unwrap();
    let msg = b"hello infinity";
    let sig = id.sign(msg);

    Identity::verify(&id.public_key(), msg, &sig).expect("verify ok");
}

#[test]
fn create_persists_pubkey_and_metadata_to_vault() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    let id = Identity::create(&vault, &kc, "default", "Mon label").unwrap();
    let pubkey_before = id.public_key();
    drop(id); // Drop = wipe seed RAM

    // Le vault doit contenir la pubkey (pour load() future)
    let identities = Identity::list(&vault).unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].name, "default");
    assert_eq!(identities[0].label, "Mon label");
    assert_eq!(identities[0].public_key_hex, pubkey_before.to_hex());

    // Le Keychain doit contenir le seed
    let seed = kc.get(SECRET_STORE_SERVICE, "default").unwrap().unwrap();
    assert_eq!(seed.len(), 32);
}

#[test]
fn load_reconstructs_same_identity() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    let id1 = Identity::create(&vault, &kc, "default", "Mon Bâtisseur").unwrap();
    let pubkey1 = id1.public_key();
    let sig1 = id1.sign(b"persistence test");
    drop(id1);

    // Recharge depuis vault + Keychain
    let id2 = Identity::load(&vault, &kc, "default").unwrap();
    let pubkey2 = id2.public_key();
    let sig2 = id2.sign(b"persistence test");

    // Ed25519 signatures sont déterministes → mêmes bytes
    assert_eq!(pubkey1.to_bytes(), pubkey2.to_bytes());
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn load_returns_not_found_if_never_created() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();
    let err = Identity::load(&vault, &kc, "ghost").unwrap_err();
    assert!(matches!(err, IdentityError::NotFound));
}

#[test]
fn load_returns_not_found_if_secret_store_empty_but_vault_has_meta() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();
    // Crée puis efface uniquement la partie Keychain — situation possible
    // si l'utilisateur a perdu son Keychain (réinit OS, etc.)
    Identity::create(&vault, &kc, "default", "test").unwrap();
    kc.delete(SECRET_STORE_SERVICE, "default").unwrap();

    let err = Identity::load(&vault, &kc, "default").unwrap_err();
    assert!(matches!(err, IdentityError::NotFound));
}

// ── Sécurité : detection KeyMismatch ─────────────────────────────────

#[test]
fn load_detects_key_mismatch_if_secret_substituted() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    Identity::create(&vault, &kc, "default", "test").unwrap();

    // Simule une attaque : quelqu'un substitue le seed dans le Keychain
    // sans toucher la pubkey du vault. Le load doit détecter.
    let fake_seed = [0xDEu8; 32];
    kc.set(SECRET_STORE_SERVICE, "default", &fake_seed).unwrap();

    let err = Identity::load(&vault, &kc, "default").unwrap_err();
    assert!(
        matches!(err, IdentityError::KeyMismatch),
        "expected KeyMismatch, got {err:?}"
    );
}

// ── AlreadyExists ────────────────────────────────────────────────────

#[test]
fn create_fails_if_identity_exists_in_vault() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    Identity::create(&vault, &kc, "default", "first").unwrap();
    let err = Identity::create(&vault, &kc, "default", "second").unwrap_err();
    assert!(matches!(err, IdentityError::AlreadyExists));
}

#[test]
fn create_fails_if_secret_store_already_has_entry() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();
    // Simule un état zombie : Keychain a une entrée mais vault est vide
    // (crash mid-create précédent par exemple). On refuse pour ne pas
    // écraser un secret potentiel.
    kc.set(SECRET_STORE_SERVICE, "default", &[0x00; 32]).unwrap();
    let err = Identity::create(&vault, &kc, "default", "test").unwrap_err();
    assert!(matches!(err, IdentityError::AlreadyExists));
}

// ── Multi-identités ──────────────────────────────────────────────────

#[test]
fn supports_multiple_named_identities() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    let alice = Identity::create(&vault, &kc, "alice", "Alice").unwrap();
    let bob = Identity::create(&vault, &kc, "bob", "Bob").unwrap();

    assert_ne!(alice.public_key().to_bytes(), bob.public_key().to_bytes());

    let listed = Identity::list(&vault).unwrap();
    assert_eq!(listed.len(), 2);
    let names: Vec<_> = listed.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"alice"));
    assert!(names.contains(&"bob"));
}

#[test]
fn signature_bound_to_identity() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    let alice = Identity::create(&vault, &kc, "alice", "Alice").unwrap();
    let bob = Identity::create(&vault, &kc, "bob", "Bob").unwrap();

    let sig_from_alice = alice.sign(b"shared msg");
    // La signature d'alice ne doit PAS vérifier contre la pubkey de bob
    let result = Identity::verify(&bob.public_key(), b"shared msg", &sig_from_alice);
    assert!(matches!(result, Err(IdentityError::BadSignature)));
}

// ── Suppression ──────────────────────────────────────────────────────

#[test]
fn delete_removes_identity_from_both_stores() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();

    Identity::create(&vault, &kc, "default", "test").unwrap();
    Identity::delete(&vault, &kc, "default").unwrap();

    assert!(Identity::list(&vault).unwrap().is_empty());
    assert!(kc.get(SECRET_STORE_SERVICE, "default").unwrap().is_none());

    // Idempotent
    Identity::delete(&vault, &kc, "default").unwrap();
}

// ── Atomicité create() ───────────────────────────────────────────────

/// SecretStore qui pète à `set()` — pour tester rollback de `create`.
struct FailingSetStore;
impl SecretStore for FailingSetStore {
    fn set(&self, _: &str, _: &str, _: &[u8]) -> Result<(), IdentityError> {
        Err(IdentityError::SecretStoreUnavailable)
    }
    fn get(&self, _: &str, _: &str) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(None)
    }
    fn delete(&self, _: &str, _: &str) -> Result<(), IdentityError> {
        Ok(())
    }
}

#[test]
fn create_fails_cleanly_if_secret_store_set_fails() {
    let (_dir, vault) = fresh_vault();
    let kc = FailingSetStore;
    let err = Identity::create(&vault, &kc, "default", "test").unwrap_err();
    assert!(matches!(err, IdentityError::SecretStoreUnavailable));
    // Le vault ne doit RIEN contenir (rollback : pas de leftover metadata)
    assert!(Identity::list(&vault).unwrap().is_empty());
}

// ── Hex roundtrip pubkey (utile pour challenge-response Phase 2.D) ──

#[test]
fn pubkey_hex_roundtrip_works_across_processes() {
    let (_dir, vault) = fresh_vault();
    let kc = MemoryKeyring::new();
    let id = Identity::create(&vault, &kc, "default", "test").unwrap();
    let hex_str = id.public_key().to_hex();

    // Simule la PWA qui reçoit le hex via HTTP et veut vérifier une sig
    let received = PublicKey::from_hex(&hex_str).unwrap();
    let sig = id.sign(b"challenge from PWA");
    assert!(received.verify(b"challenge from PWA", &sig).is_ok());
}

// ── Smoke test OS Keychain (manuel — ignoré par défaut) ──────────────

#[test]
#[ignore = "talks to real OS Keychain — run manually with --ignored"]
fn os_keyring_smoke_test() {
    let (_dir, vault) = fresh_vault();
    let kc = OsKeyring::new();

    // Use un nom unique pour éviter de polluer le Keychain avec des
    // entrées résiduelles entre runs.
    let test_name = format!("test_{}", std::process::id());

    let id = Identity::create(&vault, &kc, &test_name, "Smoke Test").unwrap();
    let sig = id.sign(b"smoke test message");
    assert!(id.public_key().verify(b"smoke test message", &sig).is_ok());

    // Cleanup
    Identity::delete(&vault, &kc, &test_name).expect("cleanup");
}
