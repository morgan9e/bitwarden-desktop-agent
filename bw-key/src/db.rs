
use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

pub const STATE_PENDING: &str = "pending";
pub const STATE_ACTIVE: &str = "active";
pub const STATE_REVOKED: &str = "revoked";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
    device_id    BLOB PRIMARY KEY,          -- 16 bytes
    static_pub   BLOB UNIQUE,               -- 32 bytes; NULL until enrolled
    oprf_key     BLOB,                      -- 32 bytes; NULL once revoked
    enroll_hash  BLOB,                      -- SHA-256(token); NULL after use
    enroll_exp   INTEGER,
    label        TEXT,
    state        TEXT NOT NULL,             -- 'pending' | 'active' | 'revoked'
    tokens       REAL    NOT NULL DEFAULT 6.0,
    tokens_ts    INTEGER NOT NULL,
    lifetime     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    last_seen    INTEGER,
    revoked_at   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_static_pub ON devices(static_pub);

-- Operator-facing scratch, never key material: it lives here rather than in a
-- second file so the state directory stays devices.db plus server.key.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

pub const META_LISTEN: &str = "listen";

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T, String>) -> Result<T, String> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub device_id: Vec<u8>,
    pub label: String,
    pub state: String,
    pub tokens: f64,
    pub tokens_ts: i64,
    pub lifetime: i64,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>, String> {
    use rusqlite::OptionalExtension;
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn list(conn: &Connection) -> Result<Vec<DeviceRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT device_id, label, state, tokens, tokens_ts, lifetime,
                    created_at, last_seen, revoked_at
             FROM devices ORDER BY created_at",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(DeviceRow {
                device_id: r.get(0)?,
                label: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                state: r.get(2)?,
                tokens: r.get(3)?,
                tokens_ts: r.get(4)?,
                lifetime: r.get(5)?,
                created_at: r.get(6)?,
                last_seen: r.get(7)?,
                revoked_at: r.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn find_by_prefix(conn: &Connection, prefix: &str) -> Result<Vec<u8>, String> {
    let want = hex::decode(prefix).map_err(|_| "device id must be hex".to_string())?;
    let all = list(conn)?;
    let mut hits: Vec<Vec<u8>> = all
        .into_iter()
        .map(|d| d.device_id)
        .filter(|id| id.starts_with(&want))
        .collect();
    match hits.len() {
        0 => Err(format!("no device matching {prefix}")),
        1 => Ok(hits.remove(0)),
        n => Err(format!("{n} devices match {prefix}; be more specific")),
    }
}

pub fn revoke(conn: &mut Connection, device_id: &[u8]) -> Result<(), String> {
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE devices SET oprf_key = NULL, state = ?1, revoked_at = ?2 WHERE device_id = ?3",
        rusqlite::params![STATE_REVOKED, now(), device_id],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    conn.execute_batch("VACUUM").map_err(|e| e.to_string())?;
    Ok(())
}
