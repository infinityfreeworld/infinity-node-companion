//! Orchestration du vault : `create`, `open`, `change_passphrase`.
//!
//! Coordonne :
//!   - `crypto::KdfHeader` (sidecar `.salt.json`)
//!   - `crypto::derive_key` (Argon2id passphrase → 32-byte key)
//!   - `store::Store` (SQLCipher avec raw key)
//!
//! ## Atomicité
//!
//! `create()` peut échouer entre l'écriture du sidecar et la création
//! de la DB. Pour éviter un état zombie (sidecar sans DB ou inversement),
//! on suit cet ordre :
//!   1. Vérifier que NI le `.ifv` NI le `.salt.json` n'existe (sinon
//!      `AlreadyExists`).
//!   2. Générer le header KDF + dériver la clé EN RAM uniquement.
//!   3. Créer la DB SQLCipher + init schema.
//!   4. Écrire le sidecar `.salt.json` (write atomique : tmp + rename).
//!   5. Si étape 4 échoue → supprimer la DB créée à l'étape 3 (rollback).
//!
//! Le coût d'un échec mid-create est donc soit "rien créé" soit "tout
//! créé". Pas de fichier orphelin.

use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::{
    crypto::{derive_key, KdfHeader},
    namespace::Namespace,
    store::Store,
    VaultError,
};

/// Coffre-fort chiffré ouvert. Drop = ferme la base et wipe la clé.
///
/// `Debug` est implémenté à la main (au lieu de `derive(Debug)`) pour
/// ne JAMAIS fuir le contenu du store ni la connexion SQLCipher dans
/// les logs. On expose uniquement le path (déjà public via `path()`).
pub struct Vault {
    /// Chemin du fichier `.ifv` (la DB SQLCipher).
    db_path: PathBuf,
    /// Chemin du sidecar `.salt.json` (header KDF en clair).
    sidecar_path: PathBuf,
    /// Wrapper sur la connexion SQLCipher (clé déjà appliquée).
    store: Store,
}

impl Vault {
    /// Crée un nouveau vault. `path` est le chemin du fichier `.ifv` ;
    /// le sidecar `.salt.json` est créé à côté automatiquement.
    ///
    /// # Errors
    /// - [`VaultError::AlreadyExists`] si le fichier ou le sidecar existe
    /// - [`VaultError::WeakPassphrase`] si passphrase < `MIN_PASSPHRASE_LEN`
    /// - [`VaultError::Io`] / [`VaultError::Sql`] selon ce qui plante
    pub fn create(path: PathBuf, passphrase: SecretString) -> Result<Self, VaultError> {
        let sidecar_path = sidecar_for(&path);
        if path.exists() || sidecar_path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        // Étape 2 : KDF + dérivation (peut renvoyer WeakPassphrase tôt).
        let header = KdfHeader::new_default();
        let key = derive_key(&passphrase, &header)?;

        // Étape 3 : crée la DB + applique la clé + init schema.
        // Si fail ici → on n'a écrit nulle part (pas besoin de rollback).
        let store = Store::open_with_key(&path, &key)?;
        store.init_schema()?;

        // Étape 4 : écrit le sidecar atomiquement (tmp + rename).
        if let Err(e) = write_sidecar_atomic(&sidecar_path, &header) {
            // Rollback : la DB existe mais sans sidecar = inutilisable.
            // Best-effort cleanup, on ignore les erreurs du rm (un user
            // peut nettoyer manuellement si vraiment besoin).
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }

        Ok(Self { db_path: path, sidecar_path, store })
    }

    /// Ouvre un vault existant. Vérifie la passphrase.
    ///
    /// # Errors
    /// - [`VaultError::NotFound`] si le `.ifv` ou le `.salt.json` manque
    /// - [`VaultError::WrongPassphrase`] si la passphrase est fausse
    /// - [`VaultError::Corrupted`] si le sidecar JSON est mal formé ou
    ///   si SQLCipher détecte du tampering
    pub fn open(path: PathBuf, passphrase: SecretString) -> Result<Self, VaultError> {
        let sidecar_path = sidecar_for(&path);
        if !path.exists() || !sidecar_path.exists() {
            return Err(VaultError::NotFound);
        }

        let header_json = std::fs::read_to_string(&sidecar_path)?;
        let header = KdfHeader::from_json(&header_json)?;
        let key = derive_key(&passphrase, &header)?;

        let store = Store::open_with_key(&path, &key)?;
        // schema init est idempotent → safe à appeler à chaque open
        // (couvre le cas où on aurait migré le schéma entre versions).
        store.init_schema()?;

        Ok(Self { db_path: path, sidecar_path, store })
    }

    /// Renvoie un handle sur le namespace `name`.
    ///
    /// Convention de nommage recommandée :
    ///   - `identity`     : clés cryptographiques user (Phase 2.C)
    ///   - `ipfs`         : pinning, métadonnées IPFS
    ///   - `nostr`        : cache events, tokens, configs relais
    ///   - `module:<nom>` : settings d'un module (ex. `module:cube`)
    ///   - `app`          : préférences globales app
    pub fn namespace(&self, name: &str) -> Namespace<'_> {
        Namespace { vault: self, name: name.to_string() }
    }

    /// Liste les namespaces avec ≥ 1 clé.
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si la lecture échoue
    pub fn namespaces(&self) -> Result<Vec<String>, VaultError> {
        self.store.list_namespaces()
    }

    /// Change la passphrase. Atomique : si fail à mi-chemin, le vault
    /// reste sur l'ancienne passphrase.
    ///
    /// Process :
    ///   1. Vérifier `old` en redérivant et en testant l'ouverture.
    ///   2. Générer nouveau header (nouveau salt) + dériver nouvelle clé.
    ///   3. `PRAGMA rekey` SQLCipher (re-chiffre toutes les pages).
    ///   4. Écrire le nouveau sidecar (atomique).
    ///
    /// Si l'étape 3 réussit mais l'étape 4 échoue, la DB est sur la
    /// nouvelle clé mais le sidecar pointe sur l'ancien salt → vault
    /// inutilisable. On rekey en arrière vers l'ancienne clé pour
    /// rester cohérent.
    ///
    /// # Errors
    /// - [`VaultError::WrongPassphrase`] si `old` est fausse
    /// - [`VaultError::WeakPassphrase`] si `new` < `MIN_PASSPHRASE_LEN`
    /// - [`VaultError::Sql`] / [`VaultError::Io`] selon le mid-fail
    pub fn change_passphrase(
        &mut self,
        old: SecretString,
        new: SecretString,
    ) -> Result<(), VaultError> {
        // Étape 1 : valide old en relisant le sidecar courant.
        let old_header_json = std::fs::read_to_string(&self.sidecar_path)?;
        let old_header = KdfHeader::from_json(&old_header_json)?;
        let old_key = derive_key(&old, &old_header)?;
        // On ne peut pas "tester" la clé contre self.store sans rouvrir.
        // Stratégie : tenter une 2ᵉ ouverture éphémère. Si elle marche,
        // old est bonne ; sinon WrongPassphrase.
        {
            let _check = Store::open_with_key(&self.db_path, &old_key)?;
            // _check Drop → ferme cette 2ᵉ connexion. self.store reste
            // ouvert avec la même clé (Drop ne wipe que cette instance).
        }

        // Étape 2 : nouveau header + nouvelle clé (peut WeakPassphrase).
        let new_header = KdfHeader::new_default();
        let new_key = derive_key(&new, &new_header)?;

        // Étape 3 : rekey SQLCipher (atomique côté DB).
        self.store.rekey(&new_key)?;

        // Étape 4 : sidecar update atomique. Si fail, rekey back.
        if let Err(e) = write_sidecar_atomic(&self.sidecar_path, &new_header) {
            let _ = self.store.rekey(&old_key); // best-effort rollback
            return Err(e);
        }

        Ok(())
    }

    /// Chemin du fichier vault (pour info/audit, jamais pour bypass).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.db_path
    }

    /// Accès au store interne pour les `Namespace` handles. Crate-private.
    pub(crate) fn store(&self) -> &Store {
        &self.store
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("db_path", &self.db_path)
            .field("sidecar_path", &self.sidecar_path)
            .finish_non_exhaustive()
    }
}

// ── Helpers fichier ──────────────────────────────────────────────────

/// Renvoie le chemin du sidecar `.salt.json` à partir du path `.ifv`.
fn sidecar_for(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_owned();
    s.push(".salt.json");
    PathBuf::from(s)
}

/// Écriture atomique d'un fichier : write to tmp + rename.
/// Sur les FS POSIX, rename() est atomique (ou tout ou rien).
fn write_sidecar_atomic(path: &Path, header: &KdfHeader) -> Result<(), VaultError> {
    let json = header.to_json()?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    std::fs::write(&tmp_path, json.as_bytes())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
