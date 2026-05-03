//! Wrapper minimal sur `ed25519-dalek` v2.
//!
//! Pourquoi un wrapper plutôt que d'exposer `SigningKey` directement :
//!   - On contrôle l'API publique (impossible d'extraire le seed par
//!     erreur depuis le consommateur — pas d'`as_bytes()` exposé).
//!   - Drop = `zeroize` du seed automatiquement (déjà fait par
//!     ed25519-dalek v2 grâce à la feature `zeroize` dans Cargo.toml,
//!     mais on documente l'intention ici).
//!   - On encapsule la sérialisation seed/pubkey/signature.
//!
//! Format Ed25519 (RFC 8032) :
//!   - Secret seed : 32 bytes
//!   - Public key  : 32 bytes (point sur la courbe, dérivé du seed)
//!   - Signature   : 64 bytes (deterministic)

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::IdentityError;

/// Taille du seed Ed25519 (= clé privée). Constante RFC 8032.
pub const SECRET_SEED_LEN: usize = 32;
/// Taille de la clé publique Ed25519. Constante RFC 8032.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Taille d'une signature Ed25519. Constante RFC 8032.
pub const SIGNATURE_LEN: usize = 64;

/// Keypair Ed25519 complet — capable de signer.
///
/// Le seed est stocké dans `SigningKey`, qui implémente `ZeroizeOnDrop`
/// (via la feature `zeroize` de `ed25519-dalek`). Drop = wipe mémoire.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Génère un nouveau keypair via `OsRng` (entropie OS-grade).
    #[must_use]
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    /// Reconstruit un keypair depuis un seed 32-byte (typiquement
    /// récupéré du Keychain OS via `SecretStore::get`).
    pub fn from_seed(seed: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; SECRET_SEED_LEN] = seed
            .try_into()
            .map_err(|_| IdentityError::InvalidSeedLength {
                expected: SECRET_SEED_LEN,
                got: seed.len(),
            })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// Renvoie une copie du seed (32 bytes). Usage : persister dans
    /// le Keychain OS au moment de `Identity::create`. Le retour est
    /// `[u8; 32]` (stack-allocated) — caller doit zeroize après.
    #[must_use]
    pub fn seed(&self) -> [u8; SECRET_SEED_LEN] {
        self.signing.to_bytes()
    }

    /// Clé publique 32 bytes — peut être loggée, partagée, persistée
    /// en clair (c'est l'identité publique du Bâtisseur).
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Signe un message arbitraire. Signature déterministe (RFC 8032)
    /// — même message + même clé → même signature, toujours.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            inner: self.signing.sign(message),
        }
    }
}

/// Clé publique Ed25519 — sérialisable, partageable.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicKey {
    verifying: VerifyingKey,
}

impl PublicKey {
    /// Construit depuis 32 bytes raw (typiquement lus depuis le vault).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; PUBLIC_KEY_LEN] =
            bytes
                .try_into()
                .map_err(|_| IdentityError::InvalidPublicKeyLength {
                    expected: PUBLIC_KEY_LEN,
                    got: bytes.len(),
                })?;
        let verifying = VerifyingKey::from_bytes(&arr)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self { verifying })
    }

    /// Sérialise en 32 bytes (format RFC 8032).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.verifying.to_bytes()
    }

    /// Vérifie que `signature` provient bien de la clé privée
    /// associée à cette pubkey, sur ce `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), IdentityError> {
        self.verifying
            .verify(message, &signature.inner)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Encode hex (64 chars) — pour display, log, partage textuel.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode depuis hex.
    pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
        let bytes = hex::decode(s).map_err(|_| IdentityError::InvalidPublicKey)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_hex()).finish()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Signature Ed25519 — 64 bytes, déterministe, vérifiable contre
/// `(public_key, message)`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Signature {
    inner: ed25519_dalek::Signature,
}

impl Signature {
    /// Construit depuis 64 bytes raw.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; SIGNATURE_LEN] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidSignatureLength {
                expected: SIGNATURE_LEN,
                got: bytes.len(),
            })?;
        Ok(Self {
            inner: ed25519_dalek::Signature::from_bytes(&arr),
        })
    }

    /// Sérialise en 64 bytes (format RFC 8032).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.inner.to_bytes()
    }

    /// Encode hex (128 chars) — pour transmission textuelle (challenge-response).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode depuis hex.
    pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
        let bytes = hex::decode(s).map_err(|_| IdentityError::InvalidSignatureLength {
            expected: SIGNATURE_LEN,
            got: 0,
        })?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Signature").field(&self.to_hex()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_sign_and_verify() {
        let kp = Keypair::generate();
        let msg = b"hello infinity";
        let sig = kp.sign(msg);
        kp.public_key().verify(msg, &sig).expect("verify ok");
    }

    #[test]
    fn signature_is_deterministic() {
        let kp = Keypair::generate();
        let msg = b"deterministic check";
        let s1 = kp.sign(msg);
        let s2 = kp.sign(msg);
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn from_seed_then_pubkey_matches() {
        let kp1 = Keypair::generate();
        let seed = kp1.seed();
        let kp2 = Keypair::from_seed(&seed).unwrap();
        assert_eq!(kp1.public_key().to_bytes(), kp2.public_key().to_bytes());
    }

    #[test]
    fn wrong_message_rejected() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"original");
        let result = kp.public_key().verify(b"tampered", &sig);
        assert!(matches!(result, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"msg");
        let result = kp2.public_key().verify(b"msg", &sig);
        assert!(matches!(result, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let hex = pk.to_hex();
        assert_eq!(hex.len(), 64);
        let pk2 = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn signature_hex_roundtrip() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hex test");
        let hex = sig.to_hex();
        assert_eq!(hex.len(), 128);
        let sig2 = Signature::from_hex(&hex).unwrap();
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn invalid_seed_length_rejected() {
        let result = Keypair::from_seed(b"too short");
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength { .. })));
    }
}
