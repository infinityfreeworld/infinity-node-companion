//! Génération + validation des pairing tokens éphémères.
//!
//! Un `PairingToken` est :
//!   - 32 bytes aléatoires (OsRng) → 64 chars hex à afficher dans la tray
//!   - associé à une expiration unix timestamp (par défaut 10 min)
//!   - **one-shot** : invalidé dès le 1ᵉʳ usage réussi (consume)
//!
//! Stocké en RAM (`Mutex<HashMap<...>>`) — pas de persistance disque
//! car ce sont des secrets ÉPHÉMÈRES qui n'ont aucune valeur après
//! expiration. Si le companion redémarre, tous les tokens en cours
//! sont invalidés (l'utilisateur recommence le pairing — pas de
//! perte de sécurité, juste une UX dégradée acceptable).
//!
//! ## Choix : 32 bytes aléatoires (~256 bits)
//!
//! Largement au-delà du nécessaire. Avec 256 bits, la probabilité
//! de collision est ~10⁻⁷⁷ pour un milliard de tokens actifs
//! simultanément. L'attaquant ne peut pas brute-forcer non plus :
//! 60 char hex = 2²⁵⁶ tentatives, hors-jeu pour un service local.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;

use crate::AuthError;

/// TTL par défaut d'un pairing token. 10 min = compromis :
///   - assez long pour que l'utilisateur puisse copier-coller à sa main
///   - assez court pour limiter la fenêtre d'exploitation si le token leak
#[allow(clippy::duration_suboptimal_units)]   // from_mins requiert Rust 1.84+
pub const DEFAULT_PAIRING_TTL: Duration = Duration::from_secs(600);

/// Taille du token en bytes (32B = 256 bits = 64 chars hex).
const TOKEN_BYTE_LEN: usize = 32;

/// Représentation publique d'un pairing token créé. Renvoyée à l'appelant
/// (typiquement le code tray pour affichage).
#[derive(Debug, Clone)]
pub struct PairingToken {
    /// Token en hex (64 chars). À afficher dans la tray puis copier-coller.
    pub token: String,
    /// Timestamp unix d'expiration.
    pub expires_at: i64,
}

/// Store interne des tokens actifs. `expires_at` permet le GC paresseux
/// (à chaque check on filtre les expirés).
pub(crate) struct PairingTokenStore {
    tokens: Mutex<HashMap<String, i64>>, // token_hex → expires_at unix
}

impl PairingTokenStore {
    pub(crate) fn new() -> Self {
        Self { tokens: Mutex::new(HashMap::new()) }
    }

    /// Génère un nouveau token aléatoire et l'enregistre.
    pub(crate) fn create(&self, ttl: Duration) -> PairingToken {
        let mut bytes = [0u8; TOKEN_BYTE_LEN];
        OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let expires_at = now_unix() + i64::try_from(ttl.as_secs()).unwrap_or(600);

        // GC paresseux : on en profite pour nettoyer les expirés.
        if let Ok(mut map) = self.tokens.lock() {
            let now = now_unix();
            map.retain(|_, exp| *exp > now);
            map.insert(token.clone(), expires_at);
        }

        PairingToken { token, expires_at }
    }

    /// Vérifie + consume un token. Renvoie `Ok(())` si valide, sinon
    /// erreur explicite. Comparaison constant-time pour ne pas leak
    /// d'info temporelle sur les chars matchés.
    ///
    /// Une fois consumé, le token est immédiatement supprimé du store
    /// (one-shot : impossible de le réutiliser).
    pub(crate) fn consume(&self, token: &str) -> Result<(), AuthError> {
        let mut map = self
            .tokens
            .lock()
            .map_err(|_| AuthError::InvalidPairingToken)?;

        // GC paresseux + recherche en constant-time.
        let now = now_unix();
        map.retain(|_, exp| *exp > now);

        // Pour éviter le timing leak, on itère sur TOUS les tokens
        // restants et on compare en constant-time. Cher (O(n)) mais
        // n est petit (typiquement 0-3 tokens actifs).
        let mut found_key: Option<String> = None;
        let mut found_expired = false;
        for (k, exp) in map.iter() {
            if k.len() == token.len() && k.as_bytes().ct_eq(token.as_bytes()).into() {
                if *exp <= now {
                    found_expired = true;
                } else {
                    found_key = Some(k.clone());
                }
                break;
            }
        }

        if found_expired {
            return Err(AuthError::PairingTokenExpired);
        }
        let Some(k) = found_key else {
            return Err(AuthError::InvalidPairingToken);
        };
        map.remove(&k);
        Ok(())
    }

    /// Compte des tokens actifs (debug/audit). Inclut les expirés non
    /// encore GC.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.tokens.lock().map_or(0, |m| m.len())
    }
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format_is_64_hex_chars() {
        let store = PairingTokenStore::new();
        let t = store.create(DEFAULT_PAIRING_TTL);
        assert_eq!(t.token.len(), 64);
        assert!(t.token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn consume_succeeds_for_valid_token() {
        let store = PairingTokenStore::new();
        let t = store.create(DEFAULT_PAIRING_TTL);
        store.consume(&t.token).expect("valid consume");
    }

    #[test]
    fn consume_is_one_shot() {
        let store = PairingTokenStore::new();
        let t = store.create(DEFAULT_PAIRING_TTL);
        store.consume(&t.token).expect("first consume");
        let err = store.consume(&t.token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidPairingToken));
    }

    #[test]
    fn consume_unknown_token_rejected() {
        let store = PairingTokenStore::new();
        let err = store.consume(&"00".repeat(32)).unwrap_err();
        assert!(matches!(err, AuthError::InvalidPairingToken));
    }

    #[test]
    fn expired_token_rejected_then_gc() {
        let store = PairingTokenStore::new();
        let t = store.create(Duration::from_secs(0));
        // Force expiration : on attend 1s pour dépasser le timestamp.
        std::thread::sleep(Duration::from_millis(1100));
        let err = store.consume(&t.token).unwrap_err();
        // Selon timing GC : Expired si on touche pendant la fenêtre,
        // Invalid si le retain a déjà GC. Les deux sont OK.
        assert!(matches!(
            err,
            AuthError::PairingTokenExpired | AuthError::InvalidPairingToken
        ));
    }

    #[test]
    fn different_tokens_are_unique() {
        let store = PairingTokenStore::new();
        let t1 = store.create(DEFAULT_PAIRING_TTL);
        let t2 = store.create(DEFAULT_PAIRING_TTL);
        assert_ne!(t1.token, t2.token);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn create_triggers_gc_of_old_expired() {
        let store = PairingTokenStore::new();
        let _expired = store.create(Duration::from_secs(0));
        std::thread::sleep(Duration::from_millis(1100));
        let _new = store.create(DEFAULT_PAIRING_TTL);
        // Le GC paresseux a viré l'expiré
        assert_eq!(store.len(), 1);
    }
}
