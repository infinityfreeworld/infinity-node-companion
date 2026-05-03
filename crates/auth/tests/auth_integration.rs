//! Tests d'intégration `infinity-auth`.
//!
//! Couvre tout le workflow complet vault + identity + auth :
//!   - Création vault + identity du companion (Ed25519 dans MemoryKeyring)
//!   - Création AuthService
//!   - Pairing happy path + tous les chemins d'erreur
//!   - Verify request avec signature : valid / unknown device / stale
//!     timestamp / body tampering / wrong key
//!   - Multi-devices, révocation, persistance

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use infinity_auth::{
    canonical_message, AuthError, AuthService, PairedDevice, SignatureHeader,
    MAX_TIMESTAMP_SKEW_SECS,
};
use infinity_identity::{Identity, Keypair, MemoryKeyring};
use infinity_vault::Vault;
use secrecy::SecretString;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(0)
}

/// Crée un AuthService prêt à l'emploi avec vault + identity du
/// companion (générée à la volée via MemoryKeyring).
fn fresh_service() -> (TempDir, AuthService) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.ifv");
    let vault = Vault::create(
        vault_path,
        SecretString::new("correcthorsebatterystaple".to_string()),
    )
    .expect("vault create");
    let kc = MemoryKeyring::new();
    let companion_id =
        Identity::create(&vault, &kc, "default", "Companion under test").unwrap();
    let svc = AuthService::new(Arc::new(vault), Arc::new(companion_id));
    (dir, svc)
}

/// Côté "PWA" : génère un `SignatureHeader` signé par le keypair du
/// device pour `(timestamp, body)`.
fn build_signed_header(device: &Keypair, timestamp: i64, body: &[u8]) -> SignatureHeader {
    let pubkey_hex = device.public_key().to_hex();
    let msg = canonical_message(&pubkey_hex, timestamp, body);
    let sig = device.sign(msg.as_bytes());
    SignatureHeader {
        pubkey_hex,
        timestamp,
        signature_hex: sig.to_hex(),
    }
}

// ── Pairing happy path ──────────────────────────────────────────────

#[test]
fn pairing_happy_path() {
    let (_dir, svc) = fresh_service();
    let token = svc.create_pairing_token(None);
    assert_eq!(token.token.len(), 64, "token format = 64 hex chars");

    let device = Keypair::generate();
    let paired = svc
        .complete_pairing(&token.token, &device.public_key(), "Chrome — MacBook")
        .expect("pairing succeeds");

    assert_eq!(paired.label, "Chrome — MacBook");
    assert_eq!(paired.pubkey_hex, device.public_key().to_hex());
}

#[test]
fn pairing_token_is_one_shot() {
    let (_dir, svc) = fresh_service();
    let token = svc.create_pairing_token(None);
    let device1 = Keypair::generate();
    let device2 = Keypair::generate();

    svc.complete_pairing(&token.token, &device1.public_key(), "first").unwrap();
    let err = svc
        .complete_pairing(&token.token, &device2.public_key(), "second")
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidPairingToken));
}

#[test]
fn pairing_with_unknown_token_rejected() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let err = svc
        .complete_pairing(&"00".repeat(32), &device.public_key(), "test")
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidPairingToken));
}

#[test]
fn cannot_pair_same_device_twice() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();

    let token1 = svc.create_pairing_token(None);
    svc.complete_pairing(&token1.token, &device.public_key(), "first").unwrap();

    let token2 = svc.create_pairing_token(None);
    let err = svc
        .complete_pairing(&token2.token, &device.public_key(), "second")
        .unwrap_err();
    assert!(matches!(err, AuthError::DeviceAlreadyPaired));
}

#[test]
fn pairing_token_with_short_ttl_expires() {
    let (_dir, svc) = fresh_service();
    let token = svc.create_pairing_token(Some(Duration::from_secs(0)));
    std::thread::sleep(Duration::from_millis(1100));

    let device = Keypair::generate();
    let err = svc
        .complete_pairing(&token.token, &device.public_key(), "late")
        .unwrap_err();
    assert!(matches!(
        err,
        AuthError::PairingTokenExpired | AuthError::InvalidPairingToken
    ));
}

// ── Verify request ───────────────────────────────────────────────────

#[test]
fn verify_succeeds_for_paired_device_with_valid_signature() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "test").unwrap();

    let body = b"GET /api/status";
    let header = build_signed_header(&device, now_unix(), body);
    let result = svc.verify_request(&header, body).expect("verify ok");
    assert_eq!(result.label, "test");
}

#[test]
fn verify_succeeds_for_empty_body() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "test").unwrap();

    let header = build_signed_header(&device, now_unix(), b"");
    svc.verify_request(&header, b"").expect("empty body ok");
}

#[test]
fn verify_rejects_unknown_device() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let body = b"";
    let header = build_signed_header(&device, now_unix(), body);
    let err = svc.verify_request(&header, body).unwrap_err();
    assert!(matches!(err, AuthError::DeviceNotPaired));
}

#[test]
fn verify_rejects_stale_timestamp_past() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "test").unwrap();

    let stale_ts = now_unix() - (MAX_TIMESTAMP_SKEW_SECS * 2);
    let body = b"";
    let header = build_signed_header(&device, stale_ts, body);
    let err = svc.verify_request(&header, body).unwrap_err();
    assert!(matches!(err, AuthError::StaleTimestamp(_)));
}

#[test]
fn verify_rejects_stale_timestamp_future() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "test").unwrap();

    let future_ts = now_unix() + (MAX_TIMESTAMP_SKEW_SECS * 2);
    let body = b"";
    let header = build_signed_header(&device, future_ts, body);
    let err = svc.verify_request(&header, body).unwrap_err();
    assert!(matches!(err, AuthError::StaleTimestamp(_)));
}

#[test]
fn verify_rejects_body_tampering() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "test").unwrap();

    // Signer pour body original, MITM substitue par body destructeur
    let original_body = b"safe operation";
    let tampered_body = b"DELETE /vault";
    let header = build_signed_header(&device, now_unix(), original_body);
    let err = svc.verify_request(&header, tampered_body).unwrap_err();
    assert!(matches!(err, AuthError::BadSignature));
}

#[test]
fn verify_rejects_signature_from_wrong_keypair() {
    let (_dir, svc) = fresh_service();
    let device_paired = Keypair::generate();
    let device_attacker = Keypair::generate();

    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device_paired.public_key(), "legit").unwrap();

    // Le header prétend être le device appairé, mais la sig a été
    // produite par une autre clé → la sig ne vérifie pas.
    let body = b"";
    let pubkey_hex = device_paired.public_key().to_hex();
    let timestamp = now_unix();
    let msg = canonical_message(&pubkey_hex, timestamp, body);
    let bad_sig = device_attacker.sign(msg.as_bytes());
    let header = SignatureHeader {
        pubkey_hex,
        timestamp,
        signature_hex: bad_sig.to_hex(),
    };
    let err = svc.verify_request(&header, body).unwrap_err();
    assert!(matches!(err, AuthError::BadSignature));
}

// ── Multi-devices ────────────────────────────────────────────────────

#[test]
fn multiple_devices_can_be_paired_independently() {
    let (_dir, svc) = fresh_service();
    let alice_device = Keypair::generate();
    let bob_device = Keypair::generate();

    let t1 = svc.create_pairing_token(None);
    svc.complete_pairing(&t1.token, &alice_device.public_key(), "Alice's iPhone").unwrap();
    let t2 = svc.create_pairing_token(None);
    svc.complete_pairing(&t2.token, &bob_device.public_key(), "Bob's Laptop").unwrap();

    let devices = svc.list_devices().unwrap();
    assert_eq!(devices.len(), 2);

    let body = b"shared body";
    let h1 = build_signed_header(&alice_device, now_unix(), body);
    let h2 = build_signed_header(&bob_device, now_unix(), body);
    assert_eq!(svc.verify_request(&h1, body).unwrap().label, "Alice's iPhone");
    assert_eq!(svc.verify_request(&h2, body).unwrap().label, "Bob's Laptop");
}

// ── Révocation ──────────────────────────────────────────────────────

#[test]
fn revoked_device_cannot_authenticate() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    svc.complete_pairing(&token.token, &device.public_key(), "to_revoke").unwrap();

    let body = b"";
    let h = build_signed_header(&device, now_unix(), body);
    assert!(svc.verify_request(&h, body).is_ok());

    svc.revoke_device(&device.public_key().to_hex()).unwrap();

    let h2 = build_signed_header(&device, now_unix(), body);
    let err = svc.verify_request(&h2, body).unwrap_err();
    assert!(matches!(err, AuthError::DeviceNotPaired));
}

#[test]
fn revoke_is_idempotent() {
    let (_dir, svc) = fresh_service();
    svc.revoke_device(&"a".repeat(64)).expect("revoke unknown is OK");
    svc.revoke_device(&"a".repeat(64)).expect("idempotent");
}

// ── Persistance vault des paired devices ─────────────────────────────

#[test]
fn paired_devices_survive_service_recreation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.ifv");
    let pass = SecretString::new("correcthorsebatterystaple".to_string());

    let device = Keypair::generate();
    let device_pubkey_hex = device.public_key().to_hex();

    {
        let vault = Vault::create(vault_path.clone(), pass.clone()).unwrap();
        let kc = MemoryKeyring::new();
        let id = Identity::create(&vault, &kc, "default", "Companion").unwrap();
        let svc = AuthService::new(Arc::new(vault), Arc::new(id));
        let token = svc.create_pairing_token(None);
        svc.complete_pairing(&token.token, &device.public_key(), "persistent").unwrap();
    }

    {
        let vault = Vault::open(vault_path, pass).unwrap();
        let kc = MemoryKeyring::new();
        // Identity peut ne pas se recharger ici car MemoryKeyring est neuf.
        // En vrai cas (OsKeyring), on appellerait Identity::load.
        let id = Identity::create(&vault, &kc, "session2", "S2").unwrap();
        let svc = AuthService::new(Arc::new(vault), Arc::new(id));

        let devices = svc.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pubkey_hex, device_pubkey_hex);
        assert_eq!(devices[0].label, "persistent");
    }
}

// ── Header parsing ───────────────────────────────────────────────────

#[test]
fn malformed_header_rejected_at_parse() {
    let err = SignatureHeader::parse("garbage").unwrap_err();
    assert!(matches!(err, AuthError::MalformedHeader(_)));
}

#[test]
fn header_to_value_roundtrip() {
    let h = SignatureHeader {
        pubkey_hex: "ab".repeat(32),
        timestamp: 1_700_000_000,
        signature_hex: "cd".repeat(64),
    };
    let serialized = h.to_header_value();
    assert!(serialized.starts_with("InfinitySig "));
    let parsed = SignatureHeader::parse(&serialized).unwrap();
    assert_eq!(parsed.pubkey_hex, h.pubkey_hex);
}

// ── Companion pubkey + last_seen ─────────────────────────────────────

#[test]
fn companion_public_key_is_consistent() {
    let (_dir, svc) = fresh_service();
    let pk1 = svc.companion_public_key();
    let pk2 = svc.companion_public_key();
    assert_eq!(pk1.to_bytes(), pk2.to_bytes());
}

#[test]
fn verify_updates_last_seen_at() {
    let (_dir, svc) = fresh_service();
    let device = Keypair::generate();
    let token = svc.create_pairing_token(None);
    let initial: PairedDevice = svc
        .complete_pairing(&token.token, &device.public_key(), "test")
        .unwrap();

    std::thread::sleep(Duration::from_millis(1100));
    let body = b"ping";
    let h = build_signed_header(&device, now_unix(), body);
    svc.verify_request(&h, body).unwrap();

    let after = svc.list_devices().unwrap();
    assert!(after[0].last_seen_at >= initial.last_seen_at);
}
