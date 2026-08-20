//! Initialisation de la security stack du companion :
//! `Vault` chiffré + `Identity` Ed25519 + `AuthService`.
//!
//! ## Boot sans interaction utilisateur
//!
//! Pour qu'Infinity Node soit utilisable comme un daemon (autostart au
//! boot session), on ne peut PAS demander une passphrase à chaque
//! démarrage. Solution : **boot passphrase auto-générée** stockée dans
//! le Keychain OS au 1ᵉʳ run.
//!
//!   1ᵉʳ run :
//!     - Vérifie si le Keychain a une boot passphrase pour notre service.
//!     - Sinon : génère 32 bytes random → hex 64 chars → stocke.
//!     - Crée le vault `~/.infinity-node/vault.ifv` avec cette passphrase.
//!     - Crée l'identity Ed25519 "default" du companion.
//!
//!   Runs suivants :
//!     - Lit la boot passphrase du Keychain.
//!     - Ouvre le vault existant.
//!     - Charge l'identity.
//!
//! ## Trade-off sécurité
//!
//! Cette boot passphrase vit dans le Keychain OS (Apple Keychain /
//! Win Credential Manager / Linux Secret Service). L'OS gère le
//! déverrouillage : sur Mac elle est protégée par le mdp de session,
//! sur Linux par gnome-keyring/KWallet. Un attaquant qui aurait
//! l'accès root au compte utilisateur peut la lire — mais à ce
//! niveau de compromission, n'importe quoi est accessible.
//!
//! **Future (Phase 4)** : option pour passer en mode "passphrase
//! interactive" où l'utilisateur déverrouille manuellement à chaque
//! boot (pour les cas paranoïaques / multi-user).

use std::path::PathBuf;
use std::sync::Arc;

use infinity_auth::AuthService;
use infinity_identity::{Identity, IdentityError, OsKeyring, SecretStore, SECRET_STORE_SERVICE};
use infinity_vault::Vault;
use secrecy::SecretString;
use tracing::{info, warn};

/// Nom de l'identité principale du companion (multi-account possible
/// plus tard ; pour l'instant single par défaut).
const COMPANION_IDENTITY_NAME: &str = "default";

/// Account Keychain pour la boot passphrase du vault.
const VAULT_PASSPHRASE_ACCOUNT: &str = "vault-boot-passphrase";

/// Nom du fichier vault sur disque.
const VAULT_FILENAME: &str = "vault.ifv";

/// Tout ce qu'il faut au runtime — assemblé une fois au boot, partagé
/// dans `AppState` puis cloné aux handlers axum.
pub struct SecurityStack {
    pub vault:    Arc<Vault>,
    pub identity: Arc<Identity>,
    pub auth:     Arc<AuthService>,
    /// Chemin du dossier de données (pour info/logs).
    pub data_dir: PathBuf,
}

/// Erreur de boot security. Convertie en `Box<dyn Error>` côté main
/// (boot fail → exit 1, le user verra le message en console).
#[derive(thiserror::Error, Debug)]
pub enum SecurityInitError {
    #[error("OS data dir not available")]
    NoDataDir,
    #[error("data dir IO error: {0}")]
    DataDirIo(#[from] std::io::Error),
    #[error("OS keychain unavailable — install gnome-keyring/KWallet on Linux")]
    KeychainUnavailable,
    #[error("vault error: {0}")]
    Vault(#[from] infinity_vault::VaultError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("boot passphrase corrupted in keychain (not valid UTF-8)")]
    BootPassphraseCorrupted,
}

/// Empreinte courte et stable d'un dossier d'état — sert à nommer l'identité
/// d'une instance isolée sans qu'elle puisse collider avec une autre.
fn empreinte_dossier(dir: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(dir.to_string_lossy().as_bytes());
    hex::encode(h.finalize())[..8].to_string()
}

/// Initialise tout : crée le dossier data, le vault, l'identity,
/// le service auth. Idempotent — relancer l'app n'écrase rien.
pub fn init() -> Result<SecurityStack, SecurityInitError> {
    let data_dir = ensure_data_dir()?;
    info!(?data_dir, "security data dir ready");

    let kc = OsKeyring::new();
    let passphrase = ensure_boot_passphrase(&kc)?;

    let vault_path = data_dir.join(VAULT_FILENAME);
    let vault = if vault_path.exists() {
        Vault::open(vault_path.clone(), passphrase)?
    } else {
        info!(?vault_path, "creating new vault");
        Vault::create(vault_path.clone(), passphrase)?
    };
    let vault = Arc::new(vault);

    /* Nom de l'identité dans le trousseau. Une instance dont l'état a été
       déplacé (INFINITY_DATA_DIR) reçoit SA PROPRE identité : elle ouvre un
       vault neuf, donc `load` ne trouve rien, donc elle tente de créer
       « default »… que le trousseau refuse, puisqu'il appartient déjà au
       nœud de production. Résultat sans ce garde : l'instance d'essai ne
       démarre pas du tout (`identity already exists with this name`).
       Un nœud d'essai NE DOIT DE TOUTE FAÇON PAS emprunter l'identité du
       nœud de production — l'isolation vaut aussi pour la clé. */
    let nom_identite = if crate::chemins::dossier_deplace() {
        format!("{COMPANION_IDENTITY_NAME}-{}", empreinte_dossier(&data_dir))
    } else {
        COMPANION_IDENTITY_NAME.to_string()
    };

    // Identity du companion : load si existe, create sinon.
    let identity = match Identity::load(&vault, &kc, &nom_identite) {
        Ok(id) => {
            info!(pubkey = %id.public_key(), "companion identity loaded");
            id
        }
        Err(IdentityError::NotFound) => {
            let id = Identity::create(
                &vault,
                &kc,
                &nom_identite,
                "Infinity Node Companion",
            )?;
            info!(pubkey = %id.public_key(), "new companion identity created");
            id
        }
        Err(e) => return Err(SecurityInitError::Identity(e)),
    };
    let identity = Arc::new(identity);

    let auth = Arc::new(AuthService::new(vault.clone(), identity.clone()));
    Ok(SecurityStack { vault, identity, auth, data_dir })
}

/// Crée `~/.local/share/infinity-node/` (ou équivalent OS) avec
/// permissions 0700 sur Unix. Ce dossier contient le vault chiffré
/// + tout state futur lié à la sécurité.
fn ensure_data_dir() -> Result<PathBuf, SecurityInitError> {
    // dirs::data_local_dir :
    //   macOS  → ~/Library/Application Support
    //   Linux  → ~/.local/share
    //   Win    → %LOCALAPPDATA%
    /* Le vault suit l'état du nœud QUAND on l'a explicitement déplacé
       (INFINITY_DATA_DIR) : une instance d'essai ne doit pas écrire dans le
       coffre du nœud de production. Sans la variable, rien ne bouge — le
       chemin historique reste le chemin historique. */
    let dir = if crate::chemins::dossier_deplace() {
        crate::chemins::sous_dossier("securite")
    } else {
        let base = dirs::data_local_dir().ok_or(SecurityInitError::NoDataDir)?;
        base.join("infinity-node")
    };
    std::fs::create_dir_all(&dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort : si on ne peut pas chmod (FS exotique) on ignore.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    Ok(dir)
}

/// Lit la boot passphrase du Keychain ; la génère si absente.
///
/// Format stocké : 32 bytes random hex-encoded (= 64 chars ASCII).
/// Largement au-dessus de `MIN_PASSPHRASE_LEN` (8) requis par le vault.
fn ensure_boot_passphrase(kc: &OsKeyring) -> Result<SecretString, SecurityInitError> {
    use rand::RngCore;

    match kc.get(SECRET_STORE_SERVICE, VAULT_PASSPHRASE_ACCOUNT) {
        Ok(Some(bytes)) => {
            let s = String::from_utf8(bytes)
                .map_err(|_| SecurityInitError::BootPassphraseCorrupted)?;
            Ok(SecretString::new(s))
        }
        Ok(None) => {
            // Génère une nouvelle boot passphrase forte (32B random hex).
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            let s = hex::encode(buf);
            kc.set(SECRET_STORE_SERVICE, VAULT_PASSPHRASE_ACCOUNT, s.as_bytes())
                .map_err(|e| match e {
                    IdentityError::SecretStoreUnavailable => {
                        SecurityInitError::KeychainUnavailable
                    }
                    other => SecurityInitError::Identity(other),
                })?;
            warn!("first run : generated new boot passphrase in OS keychain");
            Ok(SecretString::new(s))
        }
        Err(IdentityError::SecretStoreUnavailable) => {
            Err(SecurityInitError::KeychainUnavailable)
        }
        Err(e) => Err(SecurityInitError::Identity(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn lempreinte_dun_dossier_est_stable_et_distincte() {
        let a = PathBuf::from("/tmp/noeud-essai");
        let b = PathBuf::from("/tmp/noeud-essai-2");
        assert_eq!(empreinte_dossier(&a), empreinte_dossier(&a));
        assert_ne!(empreinte_dossier(&a), empreinte_dossier(&b));
        assert_eq!(empreinte_dossier(&a).len(), 8);
    }
}
