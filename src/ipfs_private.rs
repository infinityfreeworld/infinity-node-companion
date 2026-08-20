//! Phase 3-IPFS-A — Mode "nœud IPFS privé" via swarm.key.
//!
//! ## Principe
//!
//! Kubo accepte une `swarm.key` (256 bits aléatoires) à la racine du
//! repo IPFS. Avec la variable d'env `LIBP2P_FORCE_PNET=1`, Kubo
//! REFUSE toute connexion à un peer qui n'a pas la même clé — formant
//! un réseau **privé fermé** (PNET = Private Network).
//!
//! ## Format swarm.key (Kubo PSK v1)
//!
//! Fichier texte 3 lignes, encodage hex base16 :
//!
//!     /key/swarm/psk/1.0.0/
//!     /base16/
//!     <64 chars hex>
//!
//! Cf. https://github.com/libp2p/specs/blob/master/pnet/Private-Networks-PSK-V1.md
//!
//! ## Fichiers gérés
//!
//! - `~/.infinity-node/ipfs/swarm.key` — fichier officiel Kubo (lu au boot)
//! - Backup chiffré dans le vault namespace `ipfs` clé `swarm-key`
//!   (permet de restaurer la swarm.key si le repo Kubo est perdu)
//!
//! ## Bootstrap public à désactiver
//!
//! En mode privé, on doit **retirer les bootstrap nodes publics**
//! sinon Kubo essaie quand même de joindre le DHT IPFS mondial
//! (qui rejettera mais consomme cycles). `ipfs bootstrap rm --all`
//! est appelé une fois au passage en mode privé.
//!
//! ## Sécurité
//!
//! - swarm.key = 32 bytes `OsRng` (randomness OS-grade)
//! - Permissions 0600 sur Unix (lisible uniquement par le user)
//! - Backup vault chiffré (Argon2id + SQLCipher de Phase 2.B)
//! - Fingerprint = 12 premiers chars du SHA-256(swarm.key) pour
//!   vérification visuelle "j'ai bien la même clé sur tous mes devices"

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::warn;

/// Wrapper sur une swarm.key 32 bytes. Pas exposée publiquement —
/// l'API renvoie hex/fingerprint, le binaire reste interne.
#[derive(Clone)]
pub struct SwarmKey {
    bytes: [u8; 32],
}

impl SwarmKey {
    /// Génère une nouvelle swarm.key via `OsRng` (entropie OS-grade).
    #[must_use]
    pub fn generate() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self { bytes: buf }
    }

    /// Reconstruit depuis hex (64 chars). Erreur si format invalide.
    pub fn from_hex(hex: &str) -> Result<Self, &'static str> {
        let trimmed = hex.trim();
        if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("swarm key must be 64 hex chars");
        }
        let bytes = hex::decode(trimmed).map_err(|_| "invalid hex")?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| "expected 32 bytes")?;
        Ok(Self { bytes: arr })
    }

    /// Hex 64 chars lowercase. Usage : API `GET /ipfs/private/swarm-key`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Format de fichier Kubo PSK v1 (à écrire dans
    /// `~/.infinity-node/ipfs/swarm.key`).
    #[must_use]
    pub fn to_kubo_file(&self) -> String {
        format!(
            "/key/swarm/psk/1.0.0/\n/base16/\n{}\n",
            self.to_hex()
        )
    }

    /// Fingerprint courte pour vérification visuelle (12 premiers chars
    /// du SHA-256 de la clé). Permet à l'user de confirmer "même clé"
    /// sur 2 devices sans exposer la clé complète dans l'UI.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.bytes);
        let digest = h.finalize();
        hex::encode(&digest[..6])  // 6 bytes = 12 chars hex
    }

    /// Wipe explicite (utilisé en cas de désactivation mode privé).
    #[allow(dead_code)]
    pub(crate) fn zeroize(&mut self) {
        self.bytes.fill(0);
    }
}

impl Drop for SwarmKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

// ── Path helpers ────────────────────────────────────────────────────────

/// Chemin du repo Kubo géré par Infinity Node.
/// Identique à `kubo.rs::repo_path()`.
#[must_use]
pub fn ipfs_repo_path() -> PathBuf {
    crate::chemins::sous_dossier("ipfs")
}

#[must_use]
fn swarm_key_path(repo: &Path) -> PathBuf {
    repo.join("swarm.key")
}

// ── Disk I/O ──────────────────────────────────────────────────────────

/// Lit la swarm.key depuis le repo Kubo. None si pas en mode privé.
pub fn read_swarm_key_from_repo(repo: &Path) -> Option<SwarmKey> {
    let path = swarm_key_path(repo);
    let content = fs::read_to_string(&path).ok()?;
    parse_kubo_file(&content)
}

fn parse_kubo_file(s: &str) -> Option<SwarmKey> {
    // Les 2 premières lignes sont les headers, la 3ᵉ est le hex.
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() < 3 {
        return None;
    }
    if !lines[0].starts_with("/key/swarm/psk") {
        return None;
    }
    SwarmKey::from_hex(lines[2].trim()).ok()
}

/// Écrit atomiquement (tmp + rename) la swarm.key dans le repo Kubo.
/// Permissions 0600 sur Unix (lisible uniquement par le user).
pub fn write_swarm_key_to_repo(repo: &Path, key: &SwarmKey) -> std::io::Result<()> {
    fs::create_dir_all(repo)?;
    let path = swarm_key_path(repo);
    let tmp  = path.with_extension("key.tmp");
    fs::write(&tmp, key.to_kubo_file().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Supprime la swarm.key du repo (= passage en mode public).
/// Idempotent : pas d'erreur si fichier absent.
pub fn delete_swarm_key_from_repo(repo: &Path) -> std::io::Result<()> {
    let path = swarm_key_path(repo);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// `true` si le repo est en mode privé (swarm.key présente).
#[must_use]
pub fn is_repo_in_private_mode(repo: &Path) -> bool {
    swarm_key_path(repo).exists()
}

// ── Bootstrap nodes management ───────────────────────────────────────

/// Désactive tous les bootstrap nodes publics (`ipfs bootstrap rm --all`).
/// Idempotent. À appeler une fois au passage en mode privé pour éviter
/// que Kubo essaie de joindre le DHT IPFS mondial (qui rejettera mais
/// consomme cycles + tentatives).
pub fn disable_public_bootstrap(repo: &Path) -> Result<(), String> {
    let out = std::process::Command::new("ipfs")
        .args(["bootstrap", "rm", "--all"])
        .env("IPFS_PATH", repo)
        .output()
        .map_err(|e| format!("ipfs bootstrap rm: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        warn!("disable_public_bootstrap: {}", err);
        // Pas fatal — Kubo refusera quand même les peers étrangers
        // grâce à LIBP2P_FORCE_PNET.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_distinct_keys() {
        let k1 = SwarmKey::generate();
        let k2 = SwarmKey::generate();
        assert_ne!(k1.to_hex(), k2.to_hex());
    }

    #[test]
    fn hex_roundtrip() {
        let k = SwarmKey::generate();
        let hex = k.to_hex();
        assert_eq!(hex.len(), 64);
        let k2 = SwarmKey::from_hex(&hex).unwrap();
        assert_eq!(k.to_hex(), k2.to_hex());
    }

    #[test]
    fn from_hex_rejects_invalid() {
        assert!(SwarmKey::from_hex("too-short").is_err());
        assert!(SwarmKey::from_hex(&"z".repeat(64)).is_err());
        assert!(SwarmKey::from_hex(&"a".repeat(63)).is_err());
    }

    #[test]
    fn fingerprint_is_12_chars_hex() {
        let k = SwarmKey::generate();
        let fp = k.fingerprint();
        assert_eq!(fp.len(), 12);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_deterministic() {
        let hex = "a".repeat(64);
        let k1 = SwarmKey::from_hex(&hex).unwrap();
        let k2 = SwarmKey::from_hex(&hex).unwrap();
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn kubo_file_format() {
        let hex = "abcdef".repeat(10) + "abcd";  // 64 chars
        let k = SwarmKey::from_hex(&hex).unwrap();
        let file = k.to_kubo_file();
        assert!(file.starts_with("/key/swarm/psk/1.0.0/\n/base16/\n"));
        assert!(file.ends_with(&format!("{hex}\n")));
    }

    #[test]
    fn parse_kubo_file_roundtrip() {
        let k1 = SwarmKey::generate();
        let file = k1.to_kubo_file();
        let k2 = parse_kubo_file(&file).unwrap();
        assert_eq!(k1.to_hex(), k2.to_hex());
    }

    #[test]
    fn parse_kubo_file_rejects_invalid_header() {
        let bad = "/key/wrong/header/\n/base16/\nabc";
        assert!(parse_kubo_file(bad).is_none());
    }

    #[test]
    fn write_then_read_in_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let k = SwarmKey::generate();
        write_swarm_key_to_repo(dir.path(), &k).unwrap();
        assert!(is_repo_in_private_mode(dir.path()));
        let k2 = read_swarm_key_from_repo(dir.path()).unwrap();
        assert_eq!(k.to_hex(), k2.to_hex());
    }

    #[test]
    fn delete_then_repo_is_public() {
        let dir = tempfile::tempdir().unwrap();
        let k = SwarmKey::generate();
        write_swarm_key_to_repo(dir.path(), &k).unwrap();
        assert!(is_repo_in_private_mode(dir.path()));
        delete_swarm_key_from_repo(dir.path()).unwrap();
        assert!(!is_repo_in_private_mode(dir.path()));
        // Idempotent : 2ᵉ delete OK
        delete_swarm_key_from_repo(dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn write_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let k = SwarmKey::generate();
        write_swarm_key_to_repo(dir.path(), &k).unwrap();
        let mode = fs::metadata(dir.path().join("swarm.key"))
            .unwrap()
            .permissions()
            .mode();
        // mode contient les bits user/group/others — on masque pour comparer
        assert_eq!(mode & 0o777, 0o600);
    }
}
