use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use sha2::{Digest, Sha256};

pub const SESSION_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const COOKIE: &str = "sid";

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system random source");
    buf
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn argon2(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("valid argon2 parameters");
    out
}

/// Stored as `argon2id$<salt>$<hash>`, both hex.
pub fn hash_password(password: &str) -> String {
    let salt = random_bytes::<16>();
    format!("argon2id${}${}", hex(&salt), hex(&argon2(password, &salt)))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    let (Some("argon2id"), Some(salt), Some(expected), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(salt) = unhex(salt) else { return false };
    constant_time_eq(hex(&argon2(password, &salt)).as_bytes(), expected.as_bytes())
}

/// Spend the same time as a real check, so a missing user ID is not revealed by timing.
pub fn burn_password_check(password: &str) {
    argon2(password, &[0u8; 16]);
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A new session token for the cookie; only its hash is stored.
pub fn new_session_token() -> String {
    hex(&random_bytes::<32>())
}

pub fn session_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}")
}

pub fn expired_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

pub fn token_from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

pub fn valid_userid(userid: &str) -> bool {
    (3..=32).contains(&userid.len())
        && userid.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn valid_password(password: &str) -> bool {
    (8..=128).contains(&password.chars().count())
}
