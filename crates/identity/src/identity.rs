//! Orchestration : pont entre `Keypair` (crypto), `SecretStore`
//! (Keychain OS) et `Vault` (pubkey + metadata chiffrées).
//!
//! ## Modèle de stockage hybride
//!
//! Pour une identité nommée `name` (ex. "default", ou nom user-choisi
//! pour multi-account future) :
//!
//! ```text
//! ┌─────────────────────────────────┐    ┌───────────────────────────────┐
//! │ Keychain OS                     │    │ Vault (namespace "identity")  │
//! │   service: SECRET_STORE_SERVICE │    │   <name>:public_key  → 32B    │
//! │   account: <name>               │    │   <name>:created_at  → i64    │
//! │   secret:  32B Ed25519 seed     │    │   <name>:label       → str    │
//! └─────────────────────────────────┘    └───────────────────────────────┘
//! ```
//!
//! Le SEED ne quitte jamais le Keychain OS sauf au moment de signer
//! (fenêtre RAM courte, wipe immédiat via Drop sur Keypair).
//!
//! La PUBKEY est dupliquée dans le vault pour permettre :
//!   - identification offline (savoir QUI on est même si Keychain
//!     est temporairement inaccessible)
//!   - sanity check à `load()` : on re-dérive la pubkey depuis le seed
//!     et on compare avec celle du vault → détecte une attaque où
//!     quelqu'un aurait substitué le secret dans le Keychain.

use std::time::{SystemTime, UNIX_EPOCH};

use infinity_vault::Vault;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    keypair::{Keypair, PublicKey, Signature},
    secret_store::SecretStore,
    IdentityError,
};

/// Service identifier global pour toutes les entrées Keychain de
/// l'app. Reverse-DNS pour éviter collisions avec d'autres apps.
pub const SECRET_STORE_SERVICE: &str = "world.infinityfree.node";

/// Namespace vault dédié aux identités.
const VAULT_NAMESPACE: &str = "identity";

/// Metadata d'une identité — partie publique stockée dans le vault.
/// Le secret seed est dans le Keychain OS, pas ici.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// Nom de l'identité (clé interne — "default" pour la principale,
    /// ou nom user-choisi pour multi-account future).
    pub name: String,
    /// Clé publique encodée en hex (64 chars).
    pub public_key_hex: String,
    /// Timestamp Unix (secondes) de création.
    pub created_at: i64,
    /// Label user-display (peut être différent de `name`).
    /// Ex. name="default", label="Mon Bâtisseur principal".
    pub label: String,
}

/// Identité chargée — capable de signer.
///
/// Tient le `Keypair` en mémoire (donc le seed). Drop = wipe via
/// le `ZeroizeOnDrop` de `SigningKey` dans `ed25519-dalek`.
///
/// `Debug` est implémenté à la main pour ne JAMAIS exposer le
/// keypair (le seed est secret) — uniquement les metadata publiques.
pub struct Identity {
    keypair: Keypair,
    metadata: IdentityMetadata,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Génère une nouvelle identité et la persiste atomiquement :
    ///   1. Génère keypair (seed 32B + pubkey 32B).
    ///   2. Stocke seed dans Keychain OS via `secret_store`.
    ///   3. Stocke metadata (pubkey + created_at + label) dans `vault`.
    ///   4. Si étape 3 fail, supprime la clé du Keychain (rollback).
    ///
    /// # Errors
    /// - [`IdentityError::AlreadyExists`] si une identité `name` existe déjà
    /// - [`IdentityError::SecretStoreUnavailable`] si Keychain OS indispo
    /// - [`IdentityError::Vault`] si le vault refuse l'écriture
    pub fn create(
        vault: &Vault,
        secret_store: &dyn SecretStore,
        name: &str,
        label: &str,
    ) -> Result<Self, IdentityError> {
        // Refuse si une identité du même nom existe déjà (évite l'écrasement
        // accidentel d'une clé maître).
        let ns = vault.namespace(VAULT_NAMESPACE);
        let key_pubkey = format!("{name}:public_key");
        if ns.get(&key_pubkey)?.is_some() {
            return Err(IdentityError::AlreadyExists);
        }
        if secret_store.get(SECRET_STORE_SERVICE, name)?.is_some() {
            // Le vault ne sait pas mais le Keychain a déjà une entrée :
            // état incohérent (peut-être un crash mid-create précédent).
            // On refuse pour ne pas écraser un secret potentiellement
            // utilisé par une autre install.
            return Err(IdentityError::AlreadyExists);
        }

        let kp = Keypair::generate();
        let pubkey = kp.public_key();
        let mut seed = kp.seed();

        // Étape 2 : Keychain OS d'abord. Si fail → on rollback rien
        // (rien n'a été persisté côté vault).
        if let Err(e) = secret_store.set(SECRET_STORE_SERVICE, name, &seed) {
            seed.zeroize();
            return Err(e);
        }

        // Étape 3 : metadata vault. Si fail → rollback Keychain.
        let metadata = IdentityMetadata {
            name: name.to_string(),
            public_key_hex: pubkey.to_hex(),
            created_at: now_unix(),
            label: label.to_string(),
        };
        if let Err(e) = persist_metadata(&ns, &metadata) {
            // Rollback : enlève la clé du Keychain, sinon état incohérent.
            let _ = secret_store.delete(SECRET_STORE_SERVICE, name);
            seed.zeroize();
            return Err(e);
        }

        seed.zeroize();
        Ok(Self { keypair: kp, metadata })
    }

    /// Charge une identité existante :
    ///   1. Lit metadata du vault → récupère pubkey attendue.
    ///   2. Lit seed du Keychain OS.
    ///   3. Reconstruit le keypair depuis le seed.
    ///   4. **Sanity check** : pubkey re-dérivée == pubkey du vault.
    ///      Sinon → `KeyMismatch` (substitution détectée).
    ///
    /// # Errors
    /// - [`IdentityError::NotFound`] si pas de metadata vault OU pas
    ///   de secret Keychain
    /// - [`IdentityError::KeyMismatch`] si la pubkey re-dérivée diffère
    /// - [`IdentityError::Vault`] / [`IdentityError::SecretStoreUnavailable`]
    pub fn load(
        vault: &Vault,
        secret_store: &dyn SecretStore,
        name: &str,
    ) -> Result<Self, IdentityError> {
        let ns = vault.namespace(VAULT_NAMESPACE);
        let metadata = load_metadata(&ns, name)?.ok_or(IdentityError::NotFound)?;
        let expected_pubkey = PublicKey::from_hex(&metadata.public_key_hex)?;

        let seed = secret_store
            .get(SECRET_STORE_SERVICE, name)?
            .ok_or(IdentityError::NotFound)?;
        let kp = Keypair::from_seed(&seed)?;
        // Wipe le seed lu juste après reconstruction du keypair.
        let mut seed_to_wipe = seed;
        seed_to_wipe.zeroize();

        if kp.public_key() != expected_pubkey {
            return Err(IdentityError::KeyMismatch);
        }

        Ok(Self { keypair: kp, metadata })
    }

    /// Supprime une identité : wipe Keychain + retire metadata vault.
    /// Idempotent — pas d'erreur si une partie était déjà absente.
    /// Best-effort : si l'une des 2 ops fail, on continue l'autre.
    ///
    /// # Errors
    /// Renvoie l'erreur la plus prioritaire (vault > keychain) si l'une
    /// des 2 ops fail proprement.
    pub fn delete(
        vault: &Vault,
        secret_store: &dyn SecretStore,
        name: &str,
    ) -> Result<(), IdentityError> {
        let ns = vault.namespace(VAULT_NAMESPACE);
        let vault_res = ns
            .delete(&format!("{name}:public_key"))
            .and_then(|()| ns.delete(&format!("{name}:metadata")))
            .map_err(IdentityError::from);
        let kc_res = secret_store.delete(SECRET_STORE_SERVICE, name);
        // Renvoie la 1ʳᵉ erreur si une des 2 ops a échoué.
        vault_res?;
        kc_res?;
        Ok(())
    }

    /// Liste les identités présentes dans le vault.
    /// (Pas de cross-check Keychain — on ne veut pas leak les noms en
    /// scannant le Keychain entier.)
    ///
    /// # Errors
    /// - [`IdentityError::Vault`] si la lecture échoue
    pub fn list(vault: &Vault) -> Result<Vec<IdentityMetadata>, IdentityError> {
        let ns = vault.namespace(VAULT_NAMESPACE);
        let mut out = Vec::new();
        for key in ns.list()? {
            // On ne lit que les entrées ":metadata" (les ":public_key"
            // sont juste un cache pour le sanity check de load).
            if let Some(name) = key.strip_suffix(":metadata") {
                if let Some(meta) = load_metadata(&ns, name)? {
                    out.push(meta);
                }
            }
        }
        Ok(out)
    }

    /// Signe `message` avec la clé privée. Signature déterministe
    /// (RFC 8032).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Clé publique de cette identité.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Metadata (nom, label, created_at, pubkey_hex). Lecture seule.
    #[must_use]
    pub fn metadata(&self) -> &IdentityMetadata {
        &self.metadata
    }

    /// Vérifie une signature contre un message + une pubkey.
    /// Statique — ne nécessite pas de charger l'identité.
    pub fn verify(
        public_key: &PublicKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), IdentityError> {
        public_key.verify(message, signature)
    }
}

// ── Helpers persistance ──────────────────────────────────────────────

fn persist_metadata(
    ns: &infinity_vault::Namespace<'_>,
    metadata: &IdentityMetadata,
) -> Result<(), IdentityError> {
    let json = serde_json::to_vec(metadata)
        .map_err(|e| IdentityError::Serde(e.to_string()))?;
    ns.put(&format!("{}:metadata", metadata.name), &json)?;
    // Cache pubkey à part en bytes (lecture rapide sans parser le json).
    let pubkey_bytes = hex::decode(&metadata.public_key_hex)
        .map_err(|_| IdentityError::Corrupted)?;
    ns.put(&format!("{}:public_key", metadata.name), &pubkey_bytes)?;
    Ok(())
}

fn load_metadata(
    ns: &infinity_vault::Namespace<'_>,
    name: &str,
) -> Result<Option<IdentityMetadata>, IdentityError> {
    let Some(bytes) = ns.get(&format!("{name}:metadata"))? else {
        return Ok(None);
    };
    let metadata: IdentityMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| IdentityError::Corrupted)?;
    Ok(Some(metadata))
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}
