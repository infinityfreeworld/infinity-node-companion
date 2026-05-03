//! Vérification des requêtes HTTP/WS authentifiées par signature.
//!
//! Cf. doc lib.rs pour le format complet du header `Authorization`.
//!
//! ## Anti-replay : pourquoi ±60 s suffit
//!
//! Sans nonce stockée côté serveur, on ne peut pas détecter le replay
//! exact d'une requête capturée. Mais une fenêtre étroite limite le
//! danger : attaquant doit capturer ET rejouer dans les 60 s. C'est
//! suffisant pour notre menace (CSRF / extension malveillante) qui
//! ne peut pas observer le trafic localhost en temps réel sans déjà
//! avoir compromis la machine.
//!
//! Pour passer à de la défense forte (anti-replay parfait), il faudra
//! une nonce-store côté serveur (TTL = window) et l'inclure dans le
//! message signé. Phase 4 : on en discutera quand on activera Tor.

use std::time::{SystemTime, UNIX_EPOCH};

use infinity_identity::{PublicKey, Signature};
use sha2::{Digest, Sha256};

use crate::AuthError;

/// Fenêtre de tolérance du timestamp (secondes).
/// ±60 s = absorbe le drift NTP courant + latence WS sans être laxiste.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 60;

/// Préfixe attendu du header `Authorization`.
const AUTH_SCHEME: &str = "InfinitySig ";

/// Header de signature parsé.
#[derive(Debug, Clone)]
pub struct SignatureHeader {
    /// Pubkey hex 64 chars du device qui a signé.
    pub pubkey_hex: String,
    /// Timestamp unix secondes inclus dans le message signé.
    pub timestamp: i64,
    /// Signature hex 128 chars.
    pub signature_hex: String,
}

impl SignatureHeader {
    /// Parse depuis la valeur brute du header `Authorization`.
    /// Format attendu : `InfinitySig <pubkey>:<ts>:<sig>`
    pub fn parse(header_value: &str) -> Result<Self, AuthError> {
        let payload = header_value
            .strip_prefix(AUTH_SCHEME)
            .ok_or_else(|| AuthError::MalformedHeader("missing InfinitySig scheme".into()))?;
        let parts: Vec<&str> = payload.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(AuthError::MalformedHeader(format!(
                "expected 3 parts (pubkey:ts:sig), got {}",
                parts.len()
            )));
        }
        let pubkey_hex = parts[0].to_string();
        let timestamp: i64 = parts[1]
            .parse()
            .map_err(|_| AuthError::MalformedHeader("timestamp not an integer".into()))?;
        let signature_hex = parts[2].to_string();

        if pubkey_hex.len() != 64 {
            return Err(AuthError::MalformedHeader(format!(
                "pubkey must be 64 hex chars, got {}",
                pubkey_hex.len()
            )));
        }
        if signature_hex.len() != 128 {
            return Err(AuthError::MalformedHeader(format!(
                "signature must be 128 hex chars, got {}",
                signature_hex.len()
            )));
        }

        Ok(Self { pubkey_hex, timestamp, signature_hex })
    }

    /// Sérialise au format header `Authorization` pour usage côté client.
    /// (Utile dans les tests + side-side examples.)
    #[must_use]
    pub fn to_header_value(&self) -> String {
        format!(
            "{AUTH_SCHEME}{}:{}:{}",
            self.pubkey_hex, self.timestamp, self.signature_hex
        )
    }
}

/// Construit le message canonique à signer pour une requête donnée.
/// Format : `<pubkey_hex>:<timestamp>:<sha256(body)_hex>`
///
/// Body vide → SHA-256 du vide (constant `e3b0c44...`). Permet aux
/// requêtes GET sans body d'avoir un format uniforme.
#[must_use]
pub fn canonical_message(pubkey_hex: &str, timestamp: i64, body: &[u8]) -> String {
    let body_hash = Sha256::digest(body);
    let body_hash_hex = hex::encode(body_hash);
    format!("{pubkey_hex}:{timestamp}:{body_hash_hex}")
}

/// Vérifie la signature d'une requête.
///
/// Étapes :
///   1. Vérifie la fenêtre temporelle (`MAX_TIMESTAMP_SKEW_SECS`).
///   2. Parse pubkey hex → `PublicKey` (rejette si pas un point valide).
///   3. Parse signature hex → `Signature`.
///   4. Reconstruit le message canonique avec `body`.
///   5. Vérifie la signature via `PublicKey::verify`.
///
/// **Important** : ce module ne sait PAS si la pubkey est appairée.
/// C'est `AuthService::verify_request` qui fait la vérif "device dans
/// vault". Ici on ne fait que la crypto pure.
pub(crate) fn verify_signature(
    header: &SignatureHeader,
    body: &[u8],
) -> Result<(), AuthError> {
    let now = now_unix();
    let skew = (now - header.timestamp).abs();
    if skew > MAX_TIMESTAMP_SKEW_SECS {
        return Err(AuthError::StaleTimestamp(MAX_TIMESTAMP_SKEW_SECS));
    }

    let pubkey = PublicKey::from_hex(&header.pubkey_hex)
        .map_err(|_| AuthError::BadSignature)?;
    let signature = Signature::from_hex(&header.signature_hex)
        .map_err(|_| AuthError::BadSignature)?;

    let msg = canonical_message(&header.pubkey_hex, header.timestamp, body);
    pubkey
        .verify(msg.as_bytes(), &signature)
        .map_err(|_| AuthError::BadSignature)?;
    Ok(())
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
    fn header_roundtrip_parse() {
        let h = SignatureHeader {
            pubkey_hex: "a".repeat(64),
            timestamp: 1_700_000_000,
            signature_hex: "b".repeat(128),
        };
        let serialized = h.to_header_value();
        let parsed = SignatureHeader::parse(&serialized).unwrap();
        assert_eq!(parsed.pubkey_hex, h.pubkey_hex);
        assert_eq!(parsed.timestamp, h.timestamp);
        assert_eq!(parsed.signature_hex, h.signature_hex);
    }

    #[test]
    fn header_parse_rejects_missing_scheme() {
        let err = SignatureHeader::parse("Bearer abc:123:def").unwrap_err();
        assert!(matches!(err, AuthError::MalformedHeader(_)));
    }

    #[test]
    fn header_parse_rejects_wrong_part_count() {
        let err = SignatureHeader::parse("InfinitySig only_one_part").unwrap_err();
        assert!(matches!(err, AuthError::MalformedHeader(_)));
    }

    #[test]
    fn header_parse_rejects_short_pubkey() {
        let err = SignatureHeader::parse(&format!(
            "InfinitySig {}:{}:{}",
            "a".repeat(63), // 1 char trop court
            1_700_000_000,
            "b".repeat(128)
        ))
        .unwrap_err();
        assert!(matches!(err, AuthError::MalformedHeader(_)));
    }

    #[test]
    fn canonical_message_includes_body_hash() {
        let m1 = canonical_message("aa", 1, b"body1");
        let m2 = canonical_message("aa", 1, b"body2");
        assert_ne!(m1, m2, "different body → different message");
    }

    #[test]
    fn canonical_message_empty_body_hash_constant() {
        let m = canonical_message("aa", 1, b"");
        // SHA-256 du vide = e3b0c44... (RFC well-known)
        assert!(m.ends_with("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
