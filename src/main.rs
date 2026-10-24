//! OpenPing webhook simulator: one binary, one SQLite file, plain HTML forms.
//!
//! ADDR (default 127.0.0.1:8080) and DATABASE_PATH (default webhook-simulator.db) configure it.

mod auth;
mod db;
mod html;
mod webhooks;

use std::collections::HashMap;
use std::error::Error;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::thread;

use rusqlite::Connection;
use tiny_http::{Header, Request, Response, Server};

use db::{Delivery, User};
use html::{AppView, AuthKind};
use webhooks::Form;

type Resp = Response<Cursor<Vec<u8>>>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MAX_FORM_BYTES: u64 = 1024 * 1024;

fn main() {
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let db_path = Arc::new(std::env::var("DATABASE_PATH").unwrap_or_else(|_| "webhook-simulator.db".into()));

    let conn = db::open(&db_path).expect("open database");
    db::migrate(&conn).expect("create tables");
    drop(conn);

    let server = Server::http(&addr).unwrap_or_else(|e| panic!("listen on {addr}: {e}"));
    println!("Webhook simulator on http://{addr} (database {db_path})");
    for request in server.incoming_requests() {
        let db_path = Arc::clone(&db_path);
        // A thread per request: deliveries block for up to the 20 s client timeout.
        thread::spawn(move || handle(request, &db_path));
    }
}

fn handle(mut request: Request, db_path: &str) {
    let response = route(&mut request, db_path).unwrap_or_else(|e| {
        eprintln!("{} {}: {e}", request.method(), request.url());
        text(500, "Internal error")
    });
    let _ = request.respond(response);
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn html(status: u16, body: String) -> Resp {
    Response::from_string(body)
        .with_status_code(status)
        .with_header(header("Content-Type", "text/html; charset=utf-8"))
}

fn text(status: u16, body: &str) -> Resp {
    Response::from_string(body).with_status_code(status).with_header(header("Content-Type", "text/plain; charset=utf-8"))
}

fn redirect(location: &str) -> Resp {
    Response::from_string("").with_status_code(303).with_header(header("Location", location))
}

fn read_form(request: &mut Request) -> Result<HashMap<String, String>> {
    let mut body = Vec::new();
    request.as_reader().take(MAX_FORM_BYTES).read_to_end(&mut body)?;
    Ok(form_urlencoded::parse(&body).into_owned().collect())
}

fn session_hash(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .filter(|h| h.field.equiv("Cookie"))
        .find_map(|h| auth::token_from_cookie_header(h.value.as_str()))
        .map(|token| auth::sha256_hex(token.as_bytes()))
}

fn route(request: &mut Request, db_path: &str) -> Result<Resp> {
    let conn = db::open(db_path)?;
    let method = request.method().to_string();
    let url = request.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let session = session_hash(request);
    let user = match &session {
        Some(hash) => db::session_user(&conn, hash, auth::now())?,
        None => None,
    };
    let form = if method == "POST" { read_form(request)? } else { HashMap::new() };
    let field = |name: &str| form.get(name).map_or("", |v| v.as_str());

    match (method.as_str(), path) {
        ("GET", "/") => return Ok(redirect(if user.is_some() { "/app" } else { "/login" })),
        ("GET", "/register") => return Ok(html(200, html::auth_page(AuthKind::Register, "", None))),
        ("GET", "/login") => return Ok(html(200, html::auth_page(AuthKind::Login, "", None))),
        ("POST", "/register") => return register(&conn, field("userid"), field("password")),
        ("POST", "/login") => return login(&conn, field("userid"), field("password")),
        ("POST", "/logout") => {
            if let Some(hash) = &session {
                db::delete_session(&conn, hash)?;
            }
            return Ok(redirect("/login").with_header(header("Set-Cookie", &auth::expired_cookie())));
        }
        _ => {}
    }

    let Some(user) = user else { return Ok(redirect("/login")) };
    let app = |view: AppView| Ok(html(200, html::app_page(&user, view)));
    let send_form = Form::new(form.clone());

    match (method.as_str(), path) {
        ("GET", "/app") => {
            let notice = (query == "saved").then_some("Settings saved.");
            app(AppView { form: &Form::new(HashMap::new()), notice, error: None, preview: None, result: None })
        }
        ("POST", "/settings") => {
            let settings = db::Settings {
                backend_url: field("backend_url").trim().into(),
                app_secret: field("app_secret").trim().into(),
                verify_token: field("verify_token").trim().into(),
                waba_id: field("waba_id").trim().into(),
                phone_number_id: field("phone_number_id").trim().into(),
                display_phone_number: field("display_phone_number").trim().into(),
            };
            if !settings.backend_url.is_empty() && !is_http_url(&settings.backend_url) {
                let error = Some("Backend URL must start with http:// or https://");
                return app(AppView { form: &send_form, notice: None, error, preview: None, result: None });
            }
            db::save_settings(&conn, user.id, &settings)?;
            Ok(redirect("/app?saved"))
        }
        ("POST", "/verify") => {
            let outcome = check_url(&user).and_then(|url| webhooks::verify(url, &user.settings.verify_token));
            let (notice, error) = match &outcome {
                Ok(message) => (Some(message.as_str()), None),
                Err(message) => (None, Some(message.as_str())),
            };
            app(AppView { form: &send_form, notice, error, preview: None, result: None })
        }
        ("POST", "/preview") => match webhooks::build(&send_form, &user.settings) {
            Ok(payload) => {
                let json = serde_json::to_string_pretty(&payload)?;
                app(AppView { form: &send_form, notice: None, error: None, preview: Some(&json), result: None })
            }
            Err(e) => app(AppView { form: &send_form, notice: None, error: Some(&e), preview: None, result: None }),
        },
        ("POST", "/send") => {
            let sent = webhooks::build(&send_form, &user.settings)
                .and_then(|payload| send(&conn, &user, send_form.get("type"), &payload.to_string(), send_form.get("signature")));
            match sent {
                Ok(delivery) => app(AppView { form: &send_form, notice: None, error: None, preview: None, result: Some(&delivery) }),
                Err(e) => app(AppView { form: &send_form, notice: None, error: Some(&e), preview: None, result: None }),
            }
        }
        ("POST", "/send-raw") => {
            let raw = field("payload");
            let sent = serde_json::from_str::<serde_json::Value>(raw)
                .map_err(|e| format!("The JSON is not valid: {e}"))
                .and_then(|payload| send(&conn, &user, send_form.get("type"), &payload.to_string(), send_form.get("signature")));
            let (result, error) = match &sent {
                Ok(delivery) => (Some(delivery), None),
                Err(e) => (None, Some(e.as_str())),
            };
            app(AppView { form: &send_form, notice: None, error, preview: Some(raw), result })
        }
        ("GET", "/history") => Ok(html(200, html::history_page(&user, &db::deliveries(&conn, user.id, 100)?))),
        ("POST", "/history/clear") => {
            db::clear_deliveries(&conn, user.id)?;
            Ok(redirect("/history"))
        }
        _ => delivery_routes(&conn, &user, &method, path),
    }
}

/// `GET /deliveries/{id}` and `POST /deliveries/{id}/replay`.
fn delivery_routes(conn: &Connection, user: &User, method: &str, path: &str) -> Result<Resp> {
    let not_found = || Ok(html(404, html::not_found()));
    let Some(rest) = path.strip_prefix("/deliveries/") else { return not_found() };
    let (id, replay) = match rest.strip_suffix("/replay") {
        Some(id) => (id, true),
        None => (rest, false),
    };
    let Ok(id) = id.parse::<i64>() else { return not_found() };
    let Some(original) = db::delivery(conn, user.id, id)? else { return not_found() };
    match (method, replay) {
        ("GET", false) => Ok(html(200, html::delivery_page(user, &original))),
        ("POST", true) => match send(conn, user, &original.kind, &original.body, &original.signature) {
            Ok(delivery) => Ok(redirect(&format!("/deliveries/{}", delivery.id))),
            Err(e) => Ok(html(400, html::app_page(user, AppView {
                form: &Form::new(HashMap::new()),
                notice: None,
                error: Some(&e),
                preview: None,
                result: None,
            }))),
        },
        _ => not_found(),
    }
}

fn register(conn: &Connection, userid: &str, password: &str) -> Result<Resp> {
    let userid = userid.trim();
    let error = if !auth::valid_userid(userid) {
        Some("User ID must be 3 to 32 letters, digits, dots, dashes or underscores.")
    } else if !auth::valid_password(password) {
        Some("Password must be 8 to 128 characters.")
    } else {
        None
    };
    if let Some(error) = error {
        return Ok(html(400, html::auth_page(AuthKind::Register, userid, Some(error))));
    }
    match db::create_user(conn, userid, &auth::hash_password(password))? {
        Some(user_id) => start_session(conn, user_id),
        None => Ok(html(409, html::auth_page(AuthKind::Register, userid, Some("That user ID is taken.")))),
    }
}

fn login(conn: &Connection, userid: &str, password: &str) -> Result<Resp> {
    let userid = userid.trim();
    match db::credentials(conn, userid)? {
        Some((user_id, hash)) if auth::verify_password(password, &hash) => start_session(conn, user_id),
        found => {
            if found.is_none() {
                auth::burn_password_check(password);
            }
            Ok(html(401, html::auth_page(AuthKind::Login, userid, Some("Wrong user ID or password."))))
        }
    }
}

fn start_session(conn: &Connection, user_id: i64) -> Result<Resp> {
    let token = auth::new_session_token();
    db::create_session(conn, &auth::sha256_hex(token.as_bytes()), user_id, auth::now())?;
    Ok(redirect("/app").with_header(header("Set-Cookie", &auth::session_cookie(&token))))
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn check_url(user: &User) -> std::result::Result<&str, String> {
    match user.settings.backend_url.as_str() {
        "" => Err("Set a backend URL first.".into()),
        url if is_http_url(url) => Ok(url),
        _ => Err("Backend URL must start with http:// or https://".into()),
    }
}

/// Deliver a body to the user's backend and record the attempt.
fn send(conn: &Connection, user: &User, kind: &str, body: &str, signature: &str) -> std::result::Result<Delivery, String> {
    let url = check_url(user)?;
    let signature = match signature {
        "valid" | "invalid" | "missing" => signature,
        _ => "valid",
    };
    let outcome = webhooks::deliver(url, &user.settings.app_secret, body, signature);
    let delivery = Delivery {
        id: 0,
        created_at: String::new(),
        kind: kind.into(),
        url: url.into(),
        signature: signature.into(),
        request_headers: outcome.request_headers.iter().map(|(n, v)| format!("{n}: {v}")).collect::<Vec<_>>().join("\n"),
        body: body.into(),
        status: outcome.status.map(i64::from),
        response: outcome.response,
        error: outcome.error,
        duration_ms: outcome.duration_ms,
    };
    let saved = db::insert_delivery(conn, user.id, &delivery)
        .and_then(|id| db::delivery(conn, user.id, id))
        .map_err(|e| e.to_string())?;
    saved.ok_or_else(|| "Delivery was not saved".into())
}
