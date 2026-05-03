//! Argon2id KDF + salt generation + sidecar header.
//!
//! ## Architecture du fichier vault
//!
//! Sur disque, un vault = **2 fichiers** :
//!   - `<name>.ifv`       : base SQLite chiffrée (SQLCipher 4)
//!   - `<name>.salt.json` : header KDF en clair (salt + paramètres)
//!
//! Pourquoi 2 fichiers ? SQLCipher chiffre tout depuis le 1ᵉʳ byte
//! (sauf l'option `cipher_plaintext_header_size` qu'on évite pour
//! garder le format SQLCipher standard). Le salt Argon2id n'étant
//! PAS secret (juste anti rainbow-table), on le persiste à côté
//! en JSON lisible — facilite l'audit + futures migrations de
//! paramètres KDF.
//!
//! ## Pourquoi notre propre KDF au lieu de PBKDF2 SQLCipher ?
//!
//! SQLCipher utilise PBKDF2-HMAC-SHA512 par défaut (256k iter).
//! C'est solide mais **parallélisable sur GPU** : un attaquant
//! avec rig moderne peut tester ~10⁹ passphrases/sec.
//!
//! Argon2id est **memory-hard** : chaque tentative requiert 64 MiB
//! d'allocation séquentielle, impossible à paralléliser efficacement.
//! Réduit le throughput attaquant à ~10⁶/sec → **1000× plus cher**.
//!
//! On dérive donc nous-mêmes la clé via Argon2id, et on passe le
//! résultat 32-byte à SQLCipher en **raw key mode** (`PRAGMA key =
//! "x'<hex>'"`) — SQLCipher saute son PBKDF2 et utilise la clé telle
//! quelle. Le best-of-both : KDF moderne + storage battle-tested.

use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{kdf_params, VaultError, MIN_PASSPHRASE_LEN};

/// Header KDF persisté en sidecar JSON `<vault>.salt.json`.
///
/// Format public, jamais secret. Les attaquants connaissent le salt
/// — c'est le but : chaque vault a un salt unique pour empêcher les
/// rainbow tables précalculées (ex. "azerty123" → toujours même hash).
///
/// `version` permet la migration : si on change les params Argon2 ou
/// l'algo KDF (Argon3 quand il existera), on incrémente version et
/// `open()` saura quoi faire.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct KdfHeader {
    /// Version du format header. 1 = Argon2id avec params OWASP 2024.
    pub version: u32,
    /// Identifiant lisible de l'algo. "argon2id" pour version 1.
    pub kdf: String,
    /// Salt en hex (32 bytes encodés = 64 chars). Public.
    pub salt_hex: String,
    /// Memory cost (KiB). Stocké pour permettre des migrations vers
    /// des params plus forts sans casser les vaults existants.
    pub memory_kib: u32,
    /// Nombre d'itérations Argon2.
    pub iterations: u32,
    /// Parallélisme (nombre de lanes).
    pub parallelism: u32,
}

impl KdfHeader {
    /// Génère un nouveau header avec salt aléatoire (`OsRng`) et les
    /// paramètres recommandés OWASP 2024.
    pub fn new_default() -> Self {
        let mut salt = [0u8; kdf_params::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            version: 1,
            kdf: "argon2id".to_string(),
            salt_hex: hex::encode(salt),
            memory_kib: kdf_params::MEMORY_KIB,
            iterations: kdf_params::ITERATIONS,
            parallelism: kdf_params::PARALLELISM,
        }
    }

    /// Décode le salt depuis le hex. Erreur si malformé (corruption).
    pub fn salt(&self) -> Result<Vec<u8>, VaultError> {
        hex::decode(&self.salt_hex).map_err(|_| VaultError::Corrupted)
    }

    /// Sérialise en JSON pretty-print (lisible humainement → audit).
    pub fn to_json(&self) -> Result<String, VaultError> {
        serde_json::to_string_pretty(self).map_err(|_| VaultError::Corrupted)
    }

    /// Parse depuis JSON. Erreur si format invalide ou version
    /// inconnue (futur > 1 → on demande l'utilisateur de mettre à jour).
    pub fn from_json(s: &str) -> Result<Self, VaultError> {
        let h: Self = serde_json::from_str(s).map_err(|_| VaultError::Corrupted)?;
        if h.version != 1 {
            return Err(VaultError::Corrupted);
        }
        if h.kdf != "argon2id" {
            return Err(VaultError::Corrupted);
        }
        Ok(h)
    }
}

/// Clé maître dérivée 32 bytes — wipe automatique au drop.
///
/// `ZeroizeOnDrop` garantit que la clé est écrasée en mémoire dès
/// que le vault est fermé (ou si la stack panic). Best practice
/// crypto pour limiter la fenêtre d'exposition mémoire.
#[derive(ZeroizeOnDrop)]
pub(crate) struct DerivedKey {
    bytes: [u8; kdf_params::OUTPUT_LEN],
}

impl DerivedKey {
    /// Encode la clé en hex pour `PRAGMA key = "x'<hex>'"` SQLCipher.
    /// Allocation locale + Drop → la string hex disparaît rapidement
    /// du heap.
    pub(crate) fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Accès aux bytes (tests uniquement — jamais exposé en prod).
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; kdf_params::OUTPUT_LEN] {
        &self.bytes
    }
}

/// Dérive la clé maître via Argon2id depuis (passphrase, salt, params).
///
/// Cette fonction est **lente par design** (~250-500 ms sur ARM Mac
/// avec params OWASP 2024). C'est le coût de la sécurité : un
/// attaquant subit le même délai pour CHAQUE tentative de brute-force.
///
/// # Errors
/// - [`VaultError::WeakPassphrase`] si la passphrase < `MIN_PASSPHRASE_LEN` chars
/// - [`VaultError::Corrupted`] si les params Argon2 sont invalides
///   (ne devrait pas arriver avec `KdfHeader::new_default`)
pub(crate) fn derive_key(
    passphrase: &SecretString,
    header: &KdfHeader,
) -> Result<DerivedKey, VaultError> {
    let pw = passphrase.expose_secret();
    if pw.len() < MIN_PASSPHRASE_LEN {
        return Err(VaultError::WeakPassphrase);
    }

    let salt = header.salt()?;

    let params = argon2::Params::new(
        header.memory_kib,
        header.iterations,
        header.parallelism,
        Some(kdf_params::OUTPUT_LEN),
    )
    .map_err(|_| VaultError::Corrupted)?;

    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut out = [0u8; kdf_params::OUTPUT_LEN];
    argon
        .hash_password_into(pw.as_bytes(), &salt, &mut out)
        .map_err(|_| VaultError::Corrupted)?;

    Ok(DerivedKey { bytes: out })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn header_roundtrip_json() {
        let h1 = KdfHeader::new_default();
        let json = h1.to_json().unwrap();
        let h2 = KdfHeader::from_json(&json).unwrap();
        assert_eq!(h1.salt_hex, h2.salt_hex);
        assert_eq!(h1.iterations, h2.iterations);
        assert_eq!(h1.memory_kib, h2.memory_kib);
    }

    #[test]
    fn header_rejects_unknown_version() {
        let bad = r#"{
            "version": 99,
            "kdf": "argon2id",
            "salt_hex": "00",
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 4
        }"#;
        assert!(matches!(KdfHeader::from_json(bad), Err(VaultError::Corrupted)));
    }

    #[test]
    fn weak_passphrase_rejected() {
        let header = KdfHeader::new_default();
        let pw = SecretString::new("short".to_string());
        assert!(matches!(
            derive_key(&pw, &header),
            Err(VaultError::WeakPassphrase)
        ));
    }

    #[test]
    fn same_passphrase_same_salt_same_key() {
        let header = KdfHeader::new_default();
        let pw = SecretString::new("correcthorsebatterystaple".to_string());
        let k1 = derive_key(&pw, &header).unwrap();
        let k2 = derive_key(&pw, &header).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salt_different_key() {
        let h1 = KdfHeader::new_default();
        let h2 = KdfHeader::new_default(); // salt aléatoire différent
        assert_ne!(h1.salt_hex, h2.salt_hex);
        let pw = SecretString::new("correcthorsebatterystaple".to_string());
        let k1 = derive_key(&pw, &h1).unwrap();
        let k2 = derive_key(&pw, &h2).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_passphrase_different_key() {
        let header = KdfHeader::new_default();
        let pw1 = SecretString::new("correcthorsebatterystaple".to_string());
        let pw2 = SecretString::new("anotherpassphrase12345".to_string());
        let k1 = derive_key(&pw1, &header).unwrap();
        let k2 = derive_key(&pw2, &header).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
