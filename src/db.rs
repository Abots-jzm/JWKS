// This project was developed with assistance from GitHub Copilot
// SQLite database initialization and key storage utilities

use chrono::Utc;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};
use rusqlite::{Connection, OptionalExtension};

const DB_FILE: &str = "totally_not_my_privateKeys.db";

/// Create/open the SQLite database and ensure schema exists.
/// Also ensures at least one expired and one valid key are present.
pub fn init_db_and_seed() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(DB_FILE)?;

    // Create table if not exists per requirements
    conn.execute(
        "CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )",
        [],
    )?;

    let now = Utc::now().timestamp();

    // Check presence of at least one expired key (exp <= now)
    let expired_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?",
            rusqlite::params![now],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if expired_count == 0 {
        let pem = generate_rsa_pkcs1_pem()?;
        let exp = now - 1; // already expired
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            rusqlite::params![pem.as_bytes(), exp],
        )?;
    }

    // Check presence of at least one valid key (exp > now)
    let valid_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM keys WHERE exp > ?",
            rusqlite::params![now],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if valid_count == 0 {
        let pem = generate_rsa_pkcs1_pem()?;
        let exp = now + 3600; // valid for 1 hour
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            rusqlite::params![pem.as_bytes(), exp],
        )?;
    }

    Ok(())
}

/// Generate a 2048-bit RSA private key and serialize to PKCS#1 PEM.
fn generate_rsa_pkcs1_pem() -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
    Ok(pem.to_string())
}

/// Open a new SQLite connection to the app's database file.
pub fn open_connection() -> Result<Connection, rusqlite::Error> {
    Connection::open(DB_FILE)
}

/// Fetch a single key from the DB based on expiry selection.
pub fn select_one_key(want_expired: bool) -> Result<Option<(i64, Vec<u8>, i64)>, rusqlite::Error> {
    let now = Utc::now().timestamp();
    let conn = open_connection()?;

    if want_expired {
        conn.query_row(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
            rusqlite::params![now],
            |row| {
                let kid: i64 = row.get(0)?;
                let key: Vec<u8> = row.get(1)?;
                let exp: i64 = row.get(2)?;
                Ok((kid, key, exp))
            },
        )
        .optional()
    } else {
        conn.query_row(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
            rusqlite::params![now],
            |row| {
                let kid: i64 = row.get(0)?;
                let key: Vec<u8> = row.get(1)?;
                let exp: i64 = row.get(2)?;
                Ok((kid, key, exp))
            },
        )
        .optional()
    }
}

/// Fetch all valid (non-expired) keys as (kid, pem, exp)
pub fn select_all_valid_keys() -> Result<Vec<(i64, Vec<u8>, i64)>, rusqlite::Error> {
    let now = Utc::now().timestamp();
    let conn = open_connection()?;
    let mut stmt = conn.prepare("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid")?;
    let rows = stmt.query_map(rusqlite::params![now], |row| {
        let kid: i64 = row.get(0)?;
        let key: Vec<u8> = row.get(1)?;
        let exp: i64 = row.get(2)?;
        Ok((kid, key, exp))
    })?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_init_db_and_seed_creates_file_and_table() {
        // Initialize (idempotent)
        init_db_and_seed().expect("db init failed");

        // DB file exists
        assert!(Path::new(super::DB_FILE).exists(), "DB file should exist");

        // Table exists
        let conn = open_connection().expect("open failed");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "keys table should exist");
    }

    #[test]
    fn test_select_one_key_valid_and_expired() {
        init_db_and_seed().expect("db init failed");

        let valid = select_one_key(false).expect("query failed");
        assert!(valid.is_some(), "should have at least one valid key");

        let expired = select_one_key(true).expect("query failed");
        assert!(expired.is_some(), "should have at least one expired key");
    }

    #[test]
    fn test_select_all_valid_keys_nonempty_and_future_exp() {
        init_db_and_seed().expect("db init failed");
        let rows = select_all_valid_keys().expect("query failed");
        assert!(!rows.is_empty(), "should return at least one valid key");

        let now = Utc::now().timestamp();
        for (_kid, _pem, exp) in rows {
            assert!(exp > now, "valid keys must have exp in the future");
        }
    }
}
