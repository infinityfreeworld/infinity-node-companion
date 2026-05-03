//! Handle vers un sous-espace logique du vault.
//!
//! Un `Namespace<'a>` borrow le `Vault` (`'a`) — impossible de garder
//! un handle après que le vault soit fermé, garanti par le borrow
//! checker à zéro coût runtime.

use crate::{Vault, VaultError};

/// Handle scopé sur un namespace (`identity`, `ipfs`, `module:cube`...).
/// Toutes les opérations sont isolées du reste du vault.
#[must_use = "creating a namespace handle without using it does nothing"]
pub struct Namespace<'a> {
    pub(crate) vault: &'a Vault,
    pub(crate) name: String,
}

impl Namespace<'_> {
    /// Stocke `value` (bytes opaques) sous la clé `key`.
    /// Écrase si la clé existait déjà (UPSERT atomique).
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si l'écriture échoue
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), VaultError> {
        self.vault.store().put(&self.name, key, value)
    }

    /// Lit la valeur sous `key`. `None` si absente.
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si la lecture échoue
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
        self.vault.store().get(&self.name, key)
    }

    /// Liste les clés du namespace, triées (pour résultats déterministes).
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si la lecture échoue
    pub fn list(&self) -> Result<Vec<String>, VaultError> {
        self.vault.store().list(&self.name)
    }

    /// Compte les clés du namespace (sans charger les valeurs en RAM).
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si la lecture échoue
    pub fn len(&self) -> Result<usize, VaultError> {
        self.vault.store().count_ns(&self.name)
    }

    /// `true` si le namespace ne contient aucune clé.
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si la lecture échoue
    pub fn is_empty(&self) -> Result<bool, VaultError> {
        Ok(self.len()? == 0)
    }

    /// Supprime la clé. Idempotent (pas d'erreur si absente).
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si l'écriture échoue
    pub fn delete(&self, key: &str) -> Result<(), VaultError> {
        self.vault.store().delete(&self.name, key)
    }

    /// Vide TOUT le namespace. Renvoie le nombre de clés supprimées.
    /// Idempotent (0 si déjà vide).
    ///
    /// # Errors
    /// - [`VaultError::Sql`] si l'écriture échoue
    pub fn clear(&self) -> Result<usize, VaultError> {
        self.vault.store().clear_ns(&self.name)
    }

    /// Nom du namespace (debug/audit). Jamais loggé en prod.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}
