//! SQLite-backed token store + admin user management for the STARK API.
//!
//! This crate exposes:
//!   * `AuthDb` — connection wrapper with the schema migrations baked in
//!   * Users table (admin web login) with Argon2 password hashing
//!   * `api_tokens` table holding opaque bearer tokens (SHA3-256 hashed)
//!   * `sessions` table for cookie-based admin web sessions
//!   * High-level operations: `bootstrap_admin`, `verify_login`,
//!     `create_token`, `revoke_token`, `list_tokens`, `validate_bearer`,
//!     `create_session`, `validate_session`, `delete_session`.
//!
//! The bearer-token format is `stark_<random_32_bytes_hex>` (66 ASCII chars).
//! The token plaintext is shown to the user **once** at creation time;
//! only the SHA3-256 hash is stored in the database.

use std::path::Path;
use std::sync::Mutex;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
//  Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("database error: {0}")] Db(#[from] rusqlite::Error),
    #[error("password hash error: {0}")] Hash(String),
    #[error("user not found: {0}")] UserNotFound(String),
    #[error("invalid credentials")] InvalidCredentials,
    #[error("invalid token")] InvalidToken,
    #[error("token expired")] TokenExpired,
    #[error("token revoked")] TokenRevoked,
    #[error("session not found or expired")] SessionInvalid,
    #[error("internal: {0}")] Internal(String),
}

// ─────────────────────────────────────────────────────────────────────────────
//  Models (returned to callers)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id:         i64,
    pub username:   String,
    pub created_at: DateTime<Utc>,
    pub is_admin:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenInfo {
    pub id:         i64,
    pub name:       String,
    pub scope:      String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked:    bool,
    pub last_used:  Option<DateTime<Utc>>,
    pub created_by: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedToken {
    pub info:   ApiTokenInfo,
    /// The plaintext bearer string — shown to the user once, never stored.
    pub bearer: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub token_id: i64,
    pub scope:    String,
    pub user_id:  i64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id:    i64,
    pub username:   String,
    pub is_admin:   bool,
    pub expires_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Database
// ─────────────────────────────────────────────────────────────────────────────

pub struct AuthDb {
    conn: Mutex<Connection>,
}

impl AuthDb {
    /// Open the database at `path`, creating it and applying schema migrations
    /// if it does not yet exist.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, AuthError> {
        let conn = Connection::open(path)?;
        Self::migrate(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn migrate(conn: &Connection) -> Result<(), AuthError> {
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(())
    }

    // ─── Users ─────────────────────────────────────────────────────────────

    pub fn create_user(&self, username: &str, password: &str, is_admin: bool) -> Result<User, AuthError> {
        let now = Utc::now();
        let hash = hash_password(password)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
            params![username, hash, now.timestamp(), is_admin as i64],
        )?;
        let id = conn.last_insert_rowid();
        Ok(User { id, username: username.into(), created_at: now, is_admin })
    }

    pub fn find_user_by_name(&self, username: &str) -> Result<Option<User>, AuthError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, String, i64, i64)> = conn.query_row(
            "SELECT id, username, created_at, is_admin FROM users WHERE username = ?",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).optional()?;
        Ok(row.map(|(id, username, ts, is_admin)| User {
            id, username,
            created_at: DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now),
            is_admin: is_admin != 0,
        }))
    }

    pub fn count_users(&self) -> Result<i64, AuthError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        Ok(n)
    }

    pub fn verify_login(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, String, String, i64, i64)> = conn.query_row(
            "SELECT id, username, password_hash, created_at, is_admin FROM users WHERE username = ?",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional()?;
        let (id, username, hash, ts, is_admin) = row.ok_or(AuthError::InvalidCredentials)?;
        verify_password(password, &hash)?;
        Ok(User {
            id, username,
            created_at: DateTime::<Utc>::from_timestamp(ts, 0).unwrap_or_else(Utc::now),
            is_admin: is_admin != 0,
        })
    }

    // ─── API tokens ────────────────────────────────────────────────────────

    /// Create a new bearer token.  Returns the plaintext `bearer` exactly
    /// once — it is **not** retrievable afterwards.
    pub fn create_token(
        &self,
        user_id:    i64,
        name:       &str,
        scope:      &str,
        ttl_secs:   Option<i64>,
    ) -> Result<CreatedToken, AuthError> {
        let bearer = generate_bearer_string();
        let token_hash = hash_bearer(&bearer);
        let now = Utc::now();
        let expires_at = ttl_secs.map(|s| now + chrono::Duration::seconds(s));

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO api_tokens \
                (name, scope, token_hash, created_at, expires_at, revoked, created_by) \
             VALUES (?, ?, ?, ?, ?, 0, ?)",
            params![
                name, scope, token_hash, now.timestamp(),
                expires_at.map(|d| d.timestamp()),
                user_id,
            ],
        )?;
        let id = conn.last_insert_rowid();

        Ok(CreatedToken {
            info: ApiTokenInfo {
                id, name: name.into(), scope: scope.into(),
                created_at: now, expires_at, revoked: false,
                last_used: None, created_by: user_id,
            },
            bearer,
        })
    }

    pub fn list_tokens(&self) -> Result<Vec<ApiTokenInfo>, AuthError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, scope, created_at, expires_at, revoked, last_used, created_by \
             FROM api_tokens ORDER BY id DESC"
        )?;
        let rows = stmt.query_map([], |r| {
            let exp: Option<i64> = r.get(4)?;
            let last_used: Option<i64> = r.get(6)?;
            Ok(ApiTokenInfo {
                id:         r.get(0)?,
                name:       r.get(1)?,
                scope:      r.get(2)?,
                created_at: DateTime::<Utc>::from_timestamp(r.get(3)?, 0).unwrap_or_else(Utc::now),
                expires_at: exp.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0)),
                revoked:    {
                    let v: i64 = r.get(5)?;
                    v != 0
                },
                last_used:  last_used.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0)),
                created_by: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows { out.push(row?); }
        Ok(out)
    }

    pub fn revoke_token(&self, token_id: i64) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ?", params![token_id])?;
        Ok(())
    }

    /// Validate a bearer string presented by an API caller.
    /// Updates `last_used` on success.  Returns `InvalidToken` if missing,
    /// `TokenRevoked` if revoked, `TokenExpired` if past expiry.
    pub fn validate_bearer(&self, bearer: &str) -> Result<ValidatedToken, AuthError> {
        let token_hash = hash_bearer(bearer);
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, String, i64, Option<i64>, i64, i64)> = conn.query_row(
            "SELECT id, scope, revoked, expires_at, created_by, created_at \
             FROM api_tokens WHERE token_hash = ?",
            params![token_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).optional()?;
        let (id, scope, revoked, expires_at, user_id, _created) =
            row.ok_or(AuthError::InvalidToken)?;
        if revoked != 0 { return Err(AuthError::TokenRevoked); }
        if let Some(exp_ts) = expires_at {
            if exp_ts < Utc::now().timestamp() { return Err(AuthError::TokenExpired); }
        }
        // Update last_used (best-effort).
        let _ = conn.execute(
            "UPDATE api_tokens SET last_used = ? WHERE id = ?",
            params![Utc::now().timestamp(), id],
        );
        Ok(ValidatedToken { token_id: id, scope, user_id })
    }

    // ─── Sessions (admin web UI) ───────────────────────────────────────────

    pub fn create_session(&self, user_id: i64, ttl_hours: i64) -> Result<String, AuthError> {
        let session_id = generate_session_id();
        let now = Utc::now();
        let expires = now + chrono::Duration::hours(ttl_hours);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            params![session_id, user_id, now.timestamp(), expires.timestamp()],
        )?;
        Ok(session_id)
    }

    pub fn validate_session(&self, session_id: &str) -> Result<Session, AuthError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, i64, String, i64)> = conn.query_row(
            "SELECT s.user_id, s.expires_at, u.username, u.is_admin \
             FROM sessions s JOIN users u ON s.user_id = u.id \
             WHERE s.id = ?",
            params![session_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).optional()?;
        let (user_id, exp_ts, username, is_admin) =
            row.ok_or(AuthError::SessionInvalid)?;
        let expires_at = DateTime::<Utc>::from_timestamp(exp_ts, 0)
            .ok_or(AuthError::SessionInvalid)?;
        if expires_at < Utc::now() {
            // Best-effort cleanup
            let _ = conn.execute("DELETE FROM sessions WHERE id = ?", params![session_id]);
            return Err(AuthError::SessionInvalid);
        }
        Ok(Session { user_id, username, is_admin: is_admin != 0, expires_at })
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE id = ?", params![session_id])?;
        Ok(())
    }

    /// Bootstrap: ensure an admin user exists and (optionally) a bootstrap
    /// API token exists. Idempotent — safe to call on every startup.
    /// Returns `(user, Option<created_token>)` where `created_token` is `Some`
    /// iff a fresh bootstrap token was just minted.
    pub fn bootstrap_admin(
        &self,
        admin_username: &str,
        admin_password: &str,
        bootstrap_token_name: &str,
    ) -> Result<(User, Option<CreatedToken>), AuthError> {
        let user = match self.find_user_by_name(admin_username)? {
            Some(u) => u,
            None => self.create_user(admin_username, admin_password, true)?,
        };

        // Mint a bootstrap token only if no live (non-revoked) tokens exist.
        let any_live: i64 = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM api_tokens WHERE revoked = 0",
                [], |r| r.get(0),
            )?
        };
        let token = if any_live == 0 {
            Some(self.create_token(
                user.id,
                bootstrap_token_name,
                "stark:prove stark:verify stark:read",
                None,
            )?)
        } else {
            None
        };
        Ok((user, token))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Swarm device pool
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus { Idle, Busy, Offline }

impl DeviceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceStatus::Idle    => "idle",
            DeviceStatus::Busy    => "busy",
            DeviceStatus::Offline => "offline",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "busy"    => DeviceStatus::Busy,
            "offline" => DeviceStatus::Offline,
            _         => DeviceStatus::Idle,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmDevice {
    pub id:             i64,
    pub name:           String,
    pub address:        String,
    pub bearer_token:   Option<String>,
    pub max_trace_log2: u32,
    pub ram_mb:         u32,
    pub status:         DeviceStatus,
    pub last_seen:      Option<DateTime<Utc>>,
    pub registered_at:  DateTime<Utc>,
    pub registered_by:  Option<i64>,
    pub notes:          Option<String>,
}

impl AuthDb {
    pub fn register_device(
        &self,
        name:           &str,
        address:        &str,
        bearer_token:   Option<&str>,
        max_trace_log2: u32,
        ram_mb:         u32,
        registered_by:  Option<i64>,
        notes:          Option<&str>,
    ) -> Result<SwarmDevice, AuthError> {
        let now = Utc::now();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO swarm_devices (name, address, bearer_token, max_trace_log2, \
                 ram_mb, status, registered_at, registered_by, notes) \
             VALUES (?, ?, ?, ?, ?, 'idle', ?, ?, ?)",
            params![
                name, address, bearer_token, max_trace_log2 as i64, ram_mb as i64,
                now.timestamp(), registered_by, notes,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(SwarmDevice {
            id, name: name.into(), address: address.into(),
            bearer_token: bearer_token.map(|s| s.to_string()),
            max_trace_log2, ram_mb,
            status: DeviceStatus::Idle, last_seen: None,
            registered_at: now, registered_by,
            notes: notes.map(|s| s.to_string()),
        })
    }

    pub fn list_devices(&self) -> Result<Vec<SwarmDevice>, AuthError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, address, bearer_token, max_trace_log2, ram_mb, \
                    status, last_seen, registered_at, registered_by, notes \
             FROM swarm_devices ORDER BY id ASC"
        )?;
        let rows = stmt.query_map([], |r| {
            let last_seen: Option<i64> = r.get(7)?;
            let status_s: String = r.get(6)?;
            let max_t: i64 = r.get(4)?;
            let ram: i64 = r.get(5)?;
            Ok(SwarmDevice {
                id:           r.get(0)?,
                name:         r.get(1)?,
                address:      r.get(2)?,
                bearer_token: r.get(3)?,
                max_trace_log2: max_t as u32,
                ram_mb:         ram as u32,
                status:       DeviceStatus::parse(&status_s),
                last_seen:    last_seen.and_then(|t| DateTime::<Utc>::from_timestamp(t, 0)),
                registered_at: DateTime::<Utc>::from_timestamp(r.get(8)?, 0).unwrap_or_else(Utc::now),
                registered_by: r.get(9)?,
                notes:         r.get(10)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows { out.push(row?); }
        Ok(out)
    }

    pub fn list_idle_devices(&self) -> Result<Vec<SwarmDevice>, AuthError> {
        Ok(self.list_devices()?
            .into_iter()
            .filter(|d| d.status == DeviceStatus::Idle)
            .collect())
    }

    pub fn remove_device(&self, id: i64) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM swarm_devices WHERE id = ?", params![id])?;
        Ok(())
    }

    pub fn set_device_status(&self, id: i64, status: DeviceStatus) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE swarm_devices SET status = ?, last_seen = ? WHERE id = ?",
            params![status.as_str(), Utc::now().timestamp(), id],
        )?;
        Ok(())
    }

    pub fn touch_device_heartbeat(&self, id: i64) -> Result<(), AuthError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE swarm_devices SET last_seen = ? WHERE id = ?",
            params![Utc::now().timestamp(), id],
        )?;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hashing helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon.hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Hash(e.to_string()))?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<(), AuthError> {
    let parsed = PasswordHash::new(hash).map_err(|e| AuthError::Hash(e.to_string()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AuthError::InvalidCredentials)
}

/// Generate the user-visible bearer string: `stark_` + 64 lowercase hex chars
/// (32 random bytes).  This is shown once at token creation time.
fn generate_bearer_string() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    format!("stark_{}", hex::encode(buf))
}

fn generate_session_id() -> String {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Hash the bearer string with SHA3-256 (FIPS-202 family — same as the
/// rest of the verifier path).  We store this hash, never the plaintext.
fn hash_bearer(bearer: &str) -> String {
    let mut h = sha3::Sha3_256::new();
    Digest::update(&mut h, b"STARK-API-BEARER-V1");
    Digest::update(&mut h, bearer.as_bytes());
    hex::encode(Digest::finalize(h))
}

// ─────────────────────────────────────────────────────────────────────────────
//  SQL schema (applied on every open; idempotent via IF NOT EXISTS)
// ─────────────────────────────────────────────────────────────────────────────

const SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    revoked     INTEGER NOT NULL DEFAULT 0,
    last_used   INTEGER,
    created_by  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Swarm prover device pool: each registered device can take a shard of
-- a partitioned prove job.  See docs/swarm-prover.md.
CREATE TABLE IF NOT EXISTS swarm_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE,
    address         TEXT NOT NULL,                 -- "host:port" form
    bearer_token    TEXT,                          -- optional per-device bearer
    max_trace_log2  INTEGER NOT NULL DEFAULT 18,   -- max log2(trace) the device can handle
    ram_mb          INTEGER NOT NULL DEFAULT 1024, -- declared RAM budget
    status          TEXT NOT NULL DEFAULT 'idle',  -- idle | busy | offline
    last_seen       INTEGER,                        -- Unix timestamp of last heartbeat
    registered_at   INTEGER NOT NULL,
    registered_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_swarm_status ON swarm_devices(status);
"#;

// ─────────────────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> AuthDb {
        let path = std::env::temp_dir().join(format!("auth-test-{}.sqlite",
            uuid::Uuid::new_v4()));
        AuthDb::open(&path).unwrap()
    }

    #[test]
    fn create_and_verify_user() {
        let db = tmp_db();
        let _u = db.create_user("alice", "hunter2", true).unwrap();
        let v = db.verify_login("alice", "hunter2").unwrap();
        assert_eq!(v.username, "alice");
        assert!(v.is_admin);
        assert!(matches!(
            db.verify_login("alice", "wrong"),
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[test]
    fn create_token_then_validate() {
        let db = tmp_db();
        let u = db.create_user("alice", "hunter2", true).unwrap();
        let t = db.create_token(u.id, "ci", "stark:prove", None).unwrap();
        assert!(t.bearer.starts_with("stark_"));
        let v = db.validate_bearer(&t.bearer).unwrap();
        assert_eq!(v.scope, "stark:prove");
        assert_eq!(v.user_id, u.id);
    }

    #[test]
    fn revoke_token_invalidates_it() {
        let db = tmp_db();
        let u = db.create_user("alice", "hunter2", true).unwrap();
        let t = db.create_token(u.id, "ci", "stark:prove", None).unwrap();
        db.revoke_token(t.info.id).unwrap();
        assert!(matches!(
            db.validate_bearer(&t.bearer),
            Err(AuthError::TokenRevoked)
        ));
    }

    #[test]
    fn expired_token_rejected() {
        let db = tmp_db();
        let u = db.create_user("alice", "hunter2", true).unwrap();
        let t = db.create_token(u.id, "ci", "stark:prove", Some(-1)).unwrap();
        assert!(matches!(
            db.validate_bearer(&t.bearer),
            Err(AuthError::TokenExpired)
        ));
    }

    #[test]
    fn invalid_bearer_string_rejected() {
        let db = tmp_db();
        assert!(matches!(
            db.validate_bearer("stark_deadbeef"),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn bootstrap_idempotent() {
        let db = tmp_db();
        let (u1, t1) = db.bootstrap_admin("admin", "init", "bootstrap").unwrap();
        assert!(t1.is_some(), "bootstrap should mint a token on first call");
        let (u2, t2) = db.bootstrap_admin("admin", "init", "bootstrap").unwrap();
        assert_eq!(u1.id, u2.id);
        assert!(t2.is_none(), "bootstrap should not double-mint tokens");
    }

    #[test]
    fn session_lifecycle() {
        let db = tmp_db();
        let u = db.create_user("alice", "hunter2", true).unwrap();
        let sid = db.create_session(u.id, 1).unwrap();
        let s = db.validate_session(&sid).unwrap();
        assert_eq!(s.username, "alice");
        assert!(s.is_admin);
        db.delete_session(&sid).unwrap();
        assert!(matches!(
            db.validate_session(&sid),
            Err(AuthError::SessionInvalid)
        ));
    }

    #[test]
    fn register_device_and_list() {
        let db = tmp_db();
        let u = db.create_user("admin", "p", true).unwrap();
        let d1 = db.register_device(
            "rpi-01", "192.168.1.10:3000", Some("dev_secret"), 18, 1024,
            Some(u.id), Some("kitchen rpi"),
        ).unwrap();
        assert_eq!(d1.status, DeviceStatus::Idle);
        let _d2 = db.register_device(
            "rpi-02", "192.168.1.11:3000", None, 16, 512, Some(u.id), None,
        ).unwrap();
        let all = db.list_devices().unwrap();
        assert_eq!(all.len(), 2);
        let idle = db.list_idle_devices().unwrap();
        assert_eq!(idle.len(), 2);

        db.set_device_status(d1.id, DeviceStatus::Busy).unwrap();
        let idle = db.list_idle_devices().unwrap();
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].name, "rpi-02");
    }

    #[test]
    fn remove_device_works() {
        let db = tmp_db();
        let u = db.create_user("admin", "p", true).unwrap();
        let d = db.register_device(
            "x", "1.2.3.4:1", None, 14, 256, Some(u.id), None,
        ).unwrap();
        assert_eq!(db.list_devices().unwrap().len(), 1);
        db.remove_device(d.id).unwrap();
        assert!(db.list_devices().unwrap().is_empty());
    }

    #[test]
    fn list_tokens_returns_all_in_order() {
        let db = tmp_db();
        let u = db.create_user("alice", "hunter2", true).unwrap();
        let _a = db.create_token(u.id, "a", "x", None).unwrap();
        let _b = db.create_token(u.id, "b", "y", None).unwrap();
        let list = db.list_tokens().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "b");          // DESC by id
        assert_eq!(list[1].name, "a");
    }
}
