//! Tests d'intégration du crate `infinity-vault`.
//!
//! Ces tests exercent UNIQUEMENT l'API publique (`Vault`, `Namespace`,
//! `VaultError`) — c'est le contrat qu'on s'engage à maintenir entre
//! versions. Si un de ces tests casse en refactorant, c'est une
//! régression observable par les consommateurs (= breaking change).
//!
//! Chaque test utilise `tempfile::TempDir` → isolation totale, pas de
//! pollution entre tests, cleanup auto à la fin.

use infinity_vault::{Vault, VaultError, MIN_PASSPHRASE_LEN};
use secrecy::SecretString;
use tempfile::TempDir;

/// Helper : crée un path de vault dans un tempdir éphémère.
/// Renvoie aussi le tempdir pour que son Drop ne se déclenche pas trop tôt.
fn fresh_vault_path() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.ifv");
    (dir, path)
}

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

// ── Round-trip basique ───────────────────────────────────────────────

#[test]
fn create_then_put_then_get_round_trip() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let ns = v.namespace("test");

    let payload = b"hello vault";
    ns.put("greeting", payload).unwrap();

    let got = ns.get("greeting").unwrap().expect("key present");
    assert_eq!(got, payload, "bytes round-trip exact");
}

#[test]
fn round_trip_handles_binary_data() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let ns = v.namespace("test");

    // Bytes incluant 0x00, 0xFF, et tout le spectre intermédiaire.
    let payload: Vec<u8> = (0u8..=255).collect();
    ns.put("binary", &payload).unwrap();
    assert_eq!(ns.get("binary").unwrap().unwrap(), payload);
}

#[test]
fn put_overwrites_existing_value() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let ns = v.namespace("test");

    ns.put("key", b"v1").unwrap();
    ns.put("key", b"v2").unwrap();
    assert_eq!(ns.get("key").unwrap().unwrap(), b"v2");
    assert_eq!(ns.len().unwrap(), 1, "still 1 key, not 2");
}

#[test]
fn get_returns_none_for_absent_key() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    assert!(v.namespace("test").get("nope").unwrap().is_none());
}

// ── Persistence : create → drop → open ───────────────────────────────

#[test]
fn data_survives_drop_and_reopen_with_correct_passphrase() {
    let (_dir, path) = fresh_vault_path();
    let pass = "correcthorsebatterystaple";

    {
        let v = Vault::create(path.clone(), pw(pass)).unwrap();
        v.namespace("ipfs").put("pin:bafy123", b"my pinned content").unwrap();
        v.namespace("identity").put("pubkey", b"\x01\x02\x03").unwrap();
        // v Drop → DB fermée, clé wiped
    }

    let v2 = Vault::open(path, pw(pass)).expect("re-open with same pass");
    assert_eq!(
        v2.namespace("ipfs").get("pin:bafy123").unwrap().unwrap(),
        b"my pinned content"
    );
    assert_eq!(
        v2.namespace("identity").get("pubkey").unwrap().unwrap(),
        b"\x01\x02\x03"
    );
}

// ── Passphrase invalide ──────────────────────────────────────────────

#[test]
fn open_with_wrong_passphrase_returns_wrong_passphrase_error() {
    let (_dir, path) = fresh_vault_path();
    {
        let v = Vault::create(path.clone(), pw("correcthorsebatterystaple")).unwrap();
        v.namespace("test").put("key", b"value").unwrap();
    }

    let err = Vault::open(path, pw("wrongpassword12345")).unwrap_err();
    assert!(
        matches!(err, VaultError::WrongPassphrase),
        "got {err:?}, expected WrongPassphrase"
    );
}

#[test]
fn weak_passphrase_rejected_at_create() {
    let (_dir, path) = fresh_vault_path();
    let too_short = "x".repeat(MIN_PASSPHRASE_LEN - 1);
    let err = Vault::create(path, pw(&too_short)).unwrap_err();
    assert!(matches!(err, VaultError::WeakPassphrase));
}

#[test]
fn weak_passphrase_rejected_at_change() {
    let (_dir, path) = fresh_vault_path();
    let mut v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let too_short = "x".repeat(MIN_PASSPHRASE_LEN - 1);
    let err = v
        .change_passphrase(pw("correcthorsebatterystaple"), pw(&too_short))
        .unwrap_err();
    assert!(matches!(err, VaultError::WeakPassphrase));
}

// ── Tampering ────────────────────────────────────────────────────────

#[test]
fn tampering_with_db_file_is_detected() {
    let (_dir, path) = fresh_vault_path();
    let pass = "correcthorsebatterystaple";

    {
        let v = Vault::create(path.clone(), pw(pass)).unwrap();
        v.namespace("test").put("k", b"v").unwrap();
    }

    // Modifier des bytes au milieu du fichier — SQLCipher HMAC doit
    // détecter et l'open doit échouer.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .read(true).write(true).open(&path).unwrap();
        // Skip le header SQLite (16 bytes "SQLite format 3" + page size)
        // pour aller dans une page chiffrée.
        f.seek(SeekFrom::Start(2048)).unwrap();
        let mut buf = [0u8; 16];
        f.read_exact(&mut buf).unwrap();
        for b in &mut buf { *b ^= 0xFF; } // flip tous les bits
        f.seek(SeekFrom::Start(2048)).unwrap();
        f.write_all(&buf).unwrap();
    }

    let err = Vault::open(path, pw(pass)).unwrap_err();
    // Selon où on a tampé, SQLCipher peut renvoyer NotADatabase
    // (= WrongPassphrase) ou Sql générique (= Corrupted-via-Sql).
    // Les deux sont acceptables : le point clé est "fail noisy".
    assert!(
        matches!(err, VaultError::WrongPassphrase | VaultError::Corrupted | VaultError::Sql(_)),
        "got {err:?}, expected fail-noisy"
    );
}

#[test]
fn tampering_with_sidecar_json_is_detected() {
    let (_dir, path) = fresh_vault_path();
    let pass = "correcthorsebatterystaple";

    {
        let v = Vault::create(path.clone(), pw(pass)).unwrap();
        v.namespace("test").put("k", b"v").unwrap();
    }

    // Corrompre le sidecar JSON (changer un char du salt hex).
    let sidecar = std::path::PathBuf::from(format!("{}.salt.json", path.display()));
    let original = std::fs::read_to_string(&sidecar).unwrap();
    let tampered = original.replace("\"argon2id\"", "\"argon99\"");
    std::fs::write(&sidecar, tampered).unwrap();

    let err = Vault::open(path, pw(pass)).unwrap_err();
    assert!(matches!(err, VaultError::Corrupted));
}

// ── Change passphrase ────────────────────────────────────────────────

#[test]
fn change_passphrase_then_old_no_longer_works() {
    let (_dir, path) = fresh_vault_path();
    let old = "oldpassword12345";
    let new = "newpassword67890";

    {
        let mut v = Vault::create(path.clone(), pw(old)).unwrap();
        v.namespace("test").put("k", b"v").unwrap();
        v.change_passphrase(pw(old), pw(new)).unwrap();
    }

    // Ancienne passphrase fail
    let err = Vault::open(path.clone(), pw(old)).unwrap_err();
    assert!(matches!(err, VaultError::WrongPassphrase));

    // Nouvelle passphrase OK + données préservées
    let v2 = Vault::open(path, pw(new)).unwrap();
    assert_eq!(v2.namespace("test").get("k").unwrap().unwrap(), b"v");
}

#[test]
fn change_passphrase_with_wrong_old_is_rejected() {
    let (_dir, path) = fresh_vault_path();
    let mut v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let err = v
        .change_passphrase(pw("wrongguess1234"), pw("newpassword67890"))
        .unwrap_err();
    assert!(matches!(err, VaultError::WrongPassphrase));
}

// ── Isolation namespaces ─────────────────────────────────────────────

#[test]
fn namespace_isolation_keys_dont_leak() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();

    v.namespace("ipfs").put("shared_key", b"ipfs_value").unwrap();
    v.namespace("identity").put("shared_key", b"identity_value").unwrap();

    // Même clé "shared_key" dans 2 namespaces → 2 valeurs distinctes
    assert_eq!(
        v.namespace("ipfs").get("shared_key").unwrap().unwrap(),
        b"ipfs_value"
    );
    assert_eq!(
        v.namespace("identity").get("shared_key").unwrap().unwrap(),
        b"identity_value"
    );

    // List ne voit que les clés de son ns
    assert_eq!(v.namespace("ipfs").list().unwrap(), vec!["shared_key"]);
    assert_eq!(v.namespace("identity").list().unwrap(), vec!["shared_key"]);
}

#[test]
fn clear_only_affects_target_namespace() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();

    v.namespace("ipfs").put("a", b"1").unwrap();
    v.namespace("ipfs").put("b", b"2").unwrap();
    v.namespace("identity").put("k", b"keep_me").unwrap();

    let cleared = v.namespace("ipfs").clear().unwrap();
    assert_eq!(cleared, 2);
    assert!(v.namespace("ipfs").is_empty().unwrap());
    // identity intact
    assert_eq!(v.namespace("identity").get("k").unwrap().unwrap(), b"keep_me");
}

#[test]
fn list_namespaces_returns_only_used_ones() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();

    v.namespace("ipfs").put("a", b"1").unwrap();
    v.namespace("identity").put("k", b"v").unwrap();
    // Création d'un handle sans put → ne doit PAS apparaître
    let _empty = v.namespace("nostr");

    let mut nss = v.namespaces().unwrap();
    nss.sort();
    assert_eq!(nss, vec!["identity", "ipfs"]);
}

// ── Edge cases ───────────────────────────────────────────────────────

#[test]
fn delete_is_idempotent_on_missing_key() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    // Pas de panic ni d'erreur sur clé inexistante
    v.namespace("test").delete("never_existed").unwrap();
}

#[test]
fn len_and_is_empty_track_correctly() {
    let (_dir, path) = fresh_vault_path();
    let v = Vault::create(path, pw("correcthorsebatterystaple")).unwrap();
    let ns = v.namespace("test");

    assert!(ns.is_empty().unwrap());
    assert_eq!(ns.len().unwrap(), 0);

    ns.put("a", b"1").unwrap();
    ns.put("b", b"2").unwrap();
    assert_eq!(ns.len().unwrap(), 2);
    assert!(!ns.is_empty().unwrap());

    ns.delete("a").unwrap();
    assert_eq!(ns.len().unwrap(), 1);
}

#[test]
fn create_fails_if_db_file_already_exists() {
    let (dir, path) = fresh_vault_path();
    std::fs::write(&path, b"some existing junk").unwrap();
    let _ = dir; // keep alive

    let err = Vault::create(path, pw("correcthorsebatterystaple")).unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists));
}

#[test]
fn create_fails_if_sidecar_exists_alone() {
    let (dir, path) = fresh_vault_path();
    let sidecar = std::path::PathBuf::from(format!("{}.salt.json", path.display()));
    std::fs::write(&sidecar, b"{}").unwrap();
    let _ = dir;

    let err = Vault::create(path, pw("correcthorsebatterystaple")).unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists));
}

#[test]
fn open_fails_if_db_file_missing() {
    let (dir, path) = fresh_vault_path();
    let _ = dir;
    let err = Vault::open(path, pw("correcthorsebatterystaple")).unwrap_err();
    assert!(matches!(err, VaultError::NotFound));
}

// ── Garantie : pas de plaintext sur disque ───────────────────────────

#[test]
fn plaintext_value_does_not_appear_in_db_file() {
    let (_dir, path) = fresh_vault_path();
    let secret_marker = b"PLAINTEXT_MARKER_SHOULD_BE_ENCRYPTED";

    {
        let v = Vault::create(path.clone(), pw("correcthorsebatterystaple")).unwrap();
        v.namespace("test").put("k", secret_marker).unwrap();
        // v Drop → flush
    }

    // Lecture brute du fichier — le marker NE DOIT PAS y apparaître.
    // Si SQLCipher est correctement actif, tout est chiffré.
    let raw = std::fs::read(&path).unwrap();
    assert!(
        raw.windows(secret_marker.len()).all(|w| w != secret_marker),
        "PLAINTEXT MARKER FOUND IN DB FILE — encryption bypass detected !"
    );
}
