use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Result, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    userid TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    backend_url TEXT NOT NULL DEFAULT '',
    app_secret TEXT NOT NULL DEFAULT '',
    verify_token TEXT NOT NULL DEFAULT '',
    waba_id TEXT NOT NULL DEFAULT '',
    phone_number_id TEXT NOT NULL DEFAULT '',
    display_phone_number TEXT NOT NULL DEFAULT '15550001234',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    kind TEXT NOT NULL,
    url TEXT NOT NULL,
    signature TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    body TEXT NOT NULL,
    status INTEGER,
    response TEXT,
    error TEXT,
    duration_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS deliveries_by_user ON deliveries(user_id, id);
";

pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)
}

/// Where a user's webhooks go and the WhatsApp identity they claim to come from.
#[derive(Default)]
pub struct Settings {
    pub backend_url: String,
    pub app_secret: String,
    pub verify_token: String,
    pub waba_id: String,
    pub phone_number_id: String,
    pub display_phone_number: String,
}

pub struct User {
    pub id: i64,
    pub userid: String,
    pub settings: Settings,
}

pub struct Delivery {
    pub id: i64,
    pub created_at: String,
    pub kind: String,
    pub url: String,
    pub signature: String,
    pub request_headers: String,
    pub body: String,
    pub status: Option<i64>,
    pub response: Option<String>,
    pub error: Option<String>,
    pub duration_ms: i64,
}

/// The new user's id, or None when the user ID is taken.
pub fn create_user(conn: &Connection, userid: &str, password_hash: &str) -> Result<Option<i64>> {
    match conn.execute(
        "INSERT INTO users (userid, password_hash) VALUES (?1, ?2)",
        params![userid, password_hash],
    ) {
        Ok(_) => Ok(Some(conn.last_insert_rowid())),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => Ok(None),
        Err(e) => Err(e),
    }
}

/// (id, password hash) for a user ID.
pub fn credentials(conn: &Connection, userid: &str) -> Result<Option<(i64, String)>> {
    conn.query_row(
        "SELECT id, password_hash FROM users WHERE userid = ?1",
        [userid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

pub fn create_session(conn: &Connection, token_hash: &str, user_id: i64, now: i64) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash, user_id, now + crate::auth::SESSION_SECONDS],
    )?;
    Ok(())
}

pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
    Ok(())
}

pub fn session_user(conn: &Connection, token_hash: &str, now: i64) -> Result<Option<User>> {
    conn.query_row(
        "SELECT u.id, u.userid, u.backend_url, u.app_secret, u.verify_token, u.waba_id, u.phone_number_id,
                u.display_phone_number
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1 AND s.expires_at > ?2",
        params![token_hash, now],
        |r| {
            Ok(User {
                id: r.get(0)?,
                userid: r.get(1)?,
                settings: Settings {
                    backend_url: r.get(2)?,
                    app_secret: r.get(3)?,
                    verify_token: r.get(4)?,
                    waba_id: r.get(5)?,
                    phone_number_id: r.get(6)?,
                    display_phone_number: r.get(7)?,
                },
            })
        },
    )
    .optional()
}

pub fn save_settings(conn: &Connection, user_id: i64, s: &Settings) -> Result<()> {
    conn.execute(
        "UPDATE users SET backend_url = ?2, app_secret = ?3, verify_token = ?4, waba_id = ?5,
                          phone_number_id = ?6, display_phone_number = ?7
         WHERE id = ?1",
        params![
            user_id,
            s.backend_url,
            s.app_secret,
            s.verify_token,
            s.waba_id,
            s.phone_number_id,
            s.display_phone_number
        ],
    )?;
    Ok(())
}

pub fn insert_delivery(conn: &Connection, user_id: i64, d: &Delivery) -> Result<i64> {
    conn.execute(
        "INSERT INTO deliveries (user_id, kind, url, signature, request_headers, body, status, response, error, duration_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            user_id,
            d.kind,
            d.url,
            d.signature,
            d.request_headers,
            d.body,
            d.status,
            d.response,
            d.error,
            d.duration_ms
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

const DELIVERY_COLUMNS: &str =
    "id, created_at, kind, url, signature, request_headers, body, status, response, error, duration_ms";

fn delivery_row(r: &rusqlite::Row) -> Result<Delivery> {
    Ok(Delivery {
        id: r.get(0)?,
        created_at: r.get(1)?,
        kind: r.get(2)?,
        url: r.get(3)?,
        signature: r.get(4)?,
        request_headers: r.get(5)?,
        body: r.get(6)?,
        status: r.get(7)?,
        response: r.get(8)?,
        error: r.get(9)?,
        duration_ms: r.get(10)?,
    })
}

pub fn deliveries(conn: &Connection, user_id: i64, limit: i64) -> Result<Vec<Delivery>> {
    let sql = format!("SELECT {DELIVERY_COLUMNS} FROM deliveries WHERE user_id = ?1 ORDER BY id DESC LIMIT ?2");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![user_id, limit], delivery_row)?;
    rows.collect()
}

pub fn delivery(conn: &Connection, user_id: i64, id: i64) -> Result<Option<Delivery>> {
    let sql = format!("SELECT {DELIVERY_COLUMNS} FROM deliveries WHERE user_id = ?1 AND id = ?2");
    conn.query_row(&sql, params![user_id, id], delivery_row).optional()
}

pub fn clear_deliveries(conn: &Connection, user_id: i64) -> Result<()> {
    conn.execute("DELETE FROM deliveries WHERE user_id = ?1", [user_id])?;
    Ok(())
}
