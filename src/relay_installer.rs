//! Phase 3.E — Auto-installer pour `nostr-rs-relay`.
//!
//! Au 1ᵉʳ démarrage du companion, si `nostr-rs-relay` n'est PAS trouvé
//! sur le PATH, on tente de le télécharger automatiquement depuis les
//! releases de notre repo `infinity-node-companion` (workflow CI dédié
//! qui cross-compile pour Mac/Win/Linux).
//!
//! Le binaire est stocké dans `~/.local/share/infinity-node/bin/`
//! avec permissions `0755` sur Unix. La fonction `which::which` cherche
//! d'abord sur le PATH puis dans ce dossier (qu'on ajoute en tête au
//! démarrage).
//!
//! ## Pourquoi pas l'upstream `scsibug/nostr-rs-relay` ?
//!
//! Les releases de scsibug ne distribuent QUE des images Docker, pas
//! de binaires natifs. Pour offrir une UX zéro-friction (Phase 3.B),
//! on doit héberger nos propres binaires — d'où le workflow CI à
//! ajouter dans `.github/workflows/release-relay.yml` qui :
//!
//!   1. Clone scsibug/nostr-rs-relay au tag stable (ex. v0.9.1)
//!   2. Cross-compile pour x86_64/aarch64 × Mac/Win/Linux
//!   3. Calcule SHA-256 de chaque binaire
//!   4. Upload comme assets sur une release `relay-v0.9.1` du repo companion
//!
//! Le fichier `RELAY_MANIFEST` ci-dessous référence ces assets.
//!
//! ## Vérification d'intégrité
//!
//! SHA-256 obligatoire — sans ça, un attaquant qui contrôle le DNS ou
//! le proxy de l'utilisateur pourrait substituer un binaire malveillant
//! qui aurait accès au vault chiffré (le relai tourne sous le même
//! user que le companion). Le hash est codé en dur ci-dessous, mis
//! à jour à chaque nouvelle version du workflow CI.
//!
//! ## Mode dégradé
//!
//! Si le download échoue (réseau, hash mismatch, OS non supporté),
//! on log un message clair indiquant comment installer manuellement
//! et on retourne `None` — le companion continue de tourner sans relai.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{info, warn};

/// Tag de la version du relai distribuée. À bumper quand on actualise
/// le workflow CI vers une version plus récente de nostr-rs-relay.
const RELAY_TAG: &str = "relay-v0.9.1";

/// Base URL des releases du repo companion (host les binaires).
const RELEASES_BASE: &str = "https://github.com/infinityfreeworld/infinity-node-companion/releases/download";

/// Manifeste : pour chaque (os, arch), nom du fichier asset + hash SHA-256.
///
/// **Hash placeholder pour l'instant** : à remplacer par les vrais
/// hashes calculés par le workflow CI lors de la 1ʳᵉ release `relay-v*`.
/// En attendant : la vérification SHA-256 fail → fallback sur message
/// d'install manuel (UX dégradée mais sécurité préservée).
struct RelayAsset {
    filename: &'static str,
    sha256:   &'static str,
}

fn manifest_for_target() -> Option<RelayAsset> {
    // Detection cible via cfg!(...) macros — résolu à la compilation.
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Some(RelayAsset {
            filename: "nostr-rs-relay-macos-aarch64",
            // TODO: remplacer par le vrai hash après le 1ᵉʳ workflow run
            sha256:   "0000000000000000000000000000000000000000000000000000000000000000",
        });
    }
    if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        return Some(RelayAsset {
            filename: "nostr-rs-relay-macos-x86_64",
            sha256:   "0000000000000000000000000000000000000000000000000000000000000000",
        });
    }
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Some(RelayAsset {
            filename: "nostr-rs-relay-linux-x86_64",
            sha256:   "0000000000000000000000000000000000000000000000000000000000000000",
        });
    }
    if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        return Some(RelayAsset {
            filename: "nostr-rs-relay-linux-aarch64",
            sha256:   "0000000000000000000000000000000000000000000000000000000000000000",
        });
    }
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Some(RelayAsset {
            filename: "nostr-rs-relay-windows-x86_64.exe",
            sha256:   "0000000000000000000000000000000000000000000000000000000000000000",
        });
    }
    None
}

/// Renvoie le chemin où le binaire auto-installé est (ou serait) stocké.
/// Pas d'I/O ; pure construction de path.
pub fn local_relay_path() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut p = base.join("infinity-node").join("bin");
    #[cfg(target_os = "windows")]
    {
        p.push("nostr-rs-relay.exe");
    }
    #[cfg(not(target_os = "windows"))]
    {
        p.push("nostr-rs-relay");
    }
    p
}

/// Cherche un nostr-rs-relay utilisable :
///   1. dans le dossier auto-install local (téléchargé précédemment)
///   2. dans le PATH système (`which`)
///
/// Renvoie le path absolu si trouvé, None sinon.
pub fn find_existing() -> Option<PathBuf> {
    let local = local_relay_path();
    if local.exists() {
        return Some(local);
    }
    which::which("nostr-rs-relay").ok()
}

/// Tente l'auto-download du binaire si pas trouvé.
///
/// Renvoie `Some(path)` si succès ou si déjà présent localement.
/// Renvoie `None` si :
///   - OS/arch non supporté par notre manifeste
///   - Download échoue (réseau down, 404, etc.)
///   - Hash SHA-256 ne matche pas (corruption / MITM)
///   - Permissions d'écriture refusées
///
/// Tous les cas d'échec sont loggés avec un message exploitable.
pub fn ensure_installed() -> Option<PathBuf> {
    if let Some(p) = find_existing() {
        info!("nostr-rs-relay trouvé : {}", p.display());
        return Some(p);
    }

    let asset = match manifest_for_target() {
        Some(a) => a,
        None => {
            warn!(
                "nostr-rs-relay : OS/arch non supporté par l'auto-installer. \
                 Installe manuellement : `cargo install nostr-rs-relay` \
                 puis ajoute-le à ton PATH."
            );
            return None;
        }
    };

    let dest = local_relay_path();
    let url = format!("{RELEASES_BASE}/{RELAY_TAG}/{}", asset.filename);

    info!("nostr-rs-relay non trouvé — auto-download depuis {url}");

    if let Err(e) = fs::create_dir_all(dest.parent().unwrap_or(Path::new("."))) {
        warn!("auto-installer : mkdir échoue : {e}");
        return None;
    }

    // Download synchrone (bloquant) — c'est OK car on est dans la phase
    // de boot avant le runtime tokio. reqwest::blocking est plus simple
    // que reqwest async ici.
    let bytes = match download_blocking(&url, Duration::from_secs(60)) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                "auto-installer download échoué : {e}\n\
                 → installe manuellement : `cargo install nostr-rs-relay`"
            );
            return None;
        }
    };

    if !verify_sha256(&bytes, asset.sha256) {
        warn!(
            "auto-installer : hash SHA-256 NE MATCHE PAS pour {} \
             (attendu {}). Téléchargement abandonné — risque de MITM \
             ou release pas encore signée. Installe manuellement.",
            asset.filename, asset.sha256
        );
        return None;
    }

    if let Err(e) = write_binary(&dest, &bytes) {
        warn!("auto-installer : écriture {} échoue : {e}", dest.display());
        return None;
    }

    info!("nostr-rs-relay installé : {} ({} bytes)", dest.display(), bytes.len());
    Some(dest)
}

// ── Helpers internes ────────────────────────────────────────────────────

fn download_blocking(url: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(format!("infinity-node/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let resp = client.get(url).send().map_err(|e| format!("GET: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().map_err(|e| format!("body read: {e}"))?;
    Ok(bytes.to_vec())
}

fn verify_sha256(bytes: &[u8], expected_hex: &str) -> bool {
    // Hash placeholder "00..." → on refuse explicitement (sécurité) au
    // lieu d'accepter par erreur. Quand le workflow CI publie le vrai
    // hash, on le mettra dans manifest_for_target().
    if expected_hex.chars().all(|c| c == '0') {
        warn!("auto-installer : hash placeholder, refusé pour sécurité.");
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex::encode(hasher.finalize());
    // Comparaison normale OK : `expected_hex` vient du code source (constante,
    // pas un secret), donc le timing leak ne donne aucune info à l'attaquant.
    actual.eq_ignore_ascii_case(expected_hex)
}

fn write_binary(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = File::create(dest)?;
    f.write_all(bytes)?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_relay_path_is_under_data_dir() {
        let p = local_relay_path();
        // Pas null, contient infinity-node/bin
        assert!(p.to_string_lossy().contains("infinity-node"));
        assert!(p.to_string_lossy().contains("bin"));
    }

    #[test]
    fn verify_sha256_rejects_placeholder() {
        let bytes = b"hello";
        let placeholder = "0".repeat(64);
        assert!(!verify_sha256(bytes, &placeholder));
    }

    #[test]
    fn verify_sha256_accepts_correct_hash() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let bytes = b"hello";
        let correct = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(bytes, correct));
    }

    #[test]
    fn verify_sha256_rejects_mismatch() {
        let bytes = b"hello";
        let wrong = "ffff24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(!verify_sha256(bytes, wrong));
    }
}
