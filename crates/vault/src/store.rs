//! SQLCipher wrapper — couche storage du vault.
//!
//! Encapsule `rusqlite::Connection` configuré avec SQLCipher 4 :
//!   - Chiffrement page-level AES-256-CBC
//!   - HMAC-SHA512 par page (détection tampering)
//!   - Clé maître passée en raw 32-byte (notre Argon2id-derived key)
//!
//! Schéma v1 : une seule table `kv(namespace, key, value, ts...)` avec
//! PRIMARY KEY composite. Pas de DDL dynamique → migrations stables.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::{crypto::DerivedKey, VaultError};

pub(crate) struct Store {
    conn: Connection,
}

impl Store {
    /// Ouvre (ou crée) la base SQLCipher à `path` avec la clé `key`.
    ///
    /// Ordre des opérations CRUCIAL pour SQLCipher :
    ///   1. `Connection::open(path)` — ouvre le file handle
    ///   2. `PRAGMA key = "x'<hex>'"` — set la clé AVANT toute autre op
    ///   3. Lecture test (`SELECT count(*) FROM sqlite_master`) — fail
    ///      avec SqliteFailure si la clé est mauvaise (ou si le fichier
    ///      est valide mais pas chiffré, ou inversement)
    ///
    /// Si la clé est fausse → [`VaultError::WrongPassphrase`].
    /// Si le fichier est altéré → [`VaultError::Corrupted`].
    pub fn open_with_key(path: &Path, key: &DerivedKey) -> Result<Self, VaultError> {
        let conn = Connection::open(path)?;

        // PRAGMA key = "x'<hex>'" : raw key mode SQLCipher.
        // execute_batch est plus simple ici que pragma_update qui
        // double-quote l'argument et casse le format hex.
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.to_hex()))?;

        // Sanity check : si la clé est fausse, cette query plante.
        // SQLITE_NOTADB ou SqliteFailure générique → WrongPassphrase.
        // Toute autre erreur → propagée telle quelle (problème SQL réel).
        let res: Result<i64, rusqlite::Error> =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
        match res {
            Ok(_) => Ok(Self { conn }),
            Err(rusqlite::Error::SqliteFailure(e, _)) => {
                // SQLCipher renvoie SQLITE_NOTADB (26) pour clé fausse
                // sur un fichier existant. Pour un fichier neuf vide,
                // ça passe (on peut INSERT direct).
                if e.code == rusqlite::ErrorCode::NotADatabase {
                    Err(VaultError::WrongPassphrase)
                } else {
                    Err(VaultError::Sql(rusqlite::Error::SqliteFailure(e, None)))
                }
            }
            Err(e) => Err(VaultError::Sql(e)),
        }
    }

    /// Crée le schéma v1 si la base est vide. Idempotent.
    pub fn init_schema(&self) -> Result<(), VaultError> {
        self.conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS kv (
              namespace  TEXT NOT NULL,
              key        TEXT NOT NULL,
              value      BLOB NOT NULL,
              created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
              updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
              PRIMARY KEY (namespace, key)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS kv_ns_idx ON kv(namespace);
            ",
        )?;
        Ok(())
    }

    /// INSERT or UPDATE (UPSERT) atomique sur (namespace, key).
    pub fn put(&self, ns: &str, key: &str, value: &[u8]) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO kv (namespace, key, value, updated_at)
             VALUES (?1, ?2, ?3, strftime('%s','now'))
             ON CONFLICT (namespace, key) DO UPDATE
                SET value = excluded.value,
                    updated_at = excluded.updated_at",
            params![ns, key, value],
        )?;
        Ok(())
    }

    /// Lecture clé. None si absente.
    pub fn get(&self, ns: &str, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
        match self.conn.query_row(
            "SELECT value FROM kv WHERE namespace = ?1 AND key = ?2",
            params![ns, key],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(VaultError::Sql(e)),
        }
    }

    /// Liste les clés d'un namespace, triées (ORDER BY pour résultats
    /// déterministes — utile pour les tests et l'audit).
    pub fn list(&self, ns: &str) -> Result<Vec<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key FROM kv WHERE namespace = ?1 ORDER BY key")?;
        let rows = stmt.query_map(params![ns], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Compte les clés d'un namespace (sans charger les valeurs).
    pub fn count_ns(&self, ns: &str) -> Result<usize, VaultError> {
        let n: i64 = self.conn.query_row(
            "SELECT count(*) FROM kv WHERE namespace = ?1",
            params![ns],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Supprime une clé. Idempotent (pas d'erreur si absente).
    pub fn delete(&self, ns: &str, key: &str) -> Result<(), VaultError> {
        self.conn
            .execute("DELETE FROM kv WHERE namespace = ?1 AND key = ?2", params![ns, key])?;
        Ok(())
    }

    /// Vide tout un namespace. Renvoie le nombre de lignes supprimées.
    pub fn clear_ns(&self, ns: &str) -> Result<usize, VaultError> {
        let n = self
            .conn
            .execute("DELETE FROM kv WHERE namespace = ?1", params![ns])?;
        Ok(n)
    }

    /// Liste les namespaces avec ≥ 1 clé.
    pub fn list_namespaces(&self) -> Result<Vec<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT namespace FROM kv ORDER BY namespace")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Re-chiffre toute la base avec une nouvelle clé. SQLCipher fait
    /// ça atomiquement (en interne via VACUUM-like). Si fail → la base
    /// reste sur l'ancienne clé.
    pub fn rekey(&self, new_key: &DerivedKey) -> Result<(), VaultError> {
        self.conn
            .execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", new_key.to_hex()))?;
        Ok(())
    }
}
