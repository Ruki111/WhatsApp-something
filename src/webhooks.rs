//! Builds, signs and delivers Meta WhatsApp Cloud API webhooks.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::auth::{hex, now, random_bytes};
use crate::db::Settings;

/// (key, label). The key is stored with each delivery.
pub const KINDS: &[(&str, &str)] = &[
    ("text", "Customer sends a text message"),
    ("image", "Customer sends an image"),
    ("audio", "Customer sends a voice note"),
    ("document", "Customer sends a document"),
    ("location", "Customer shares a location"),
    ("button", "Customer taps a template quick-reply button"),
    ("button_reply", "Customer taps an interactive reply button"),
    ("list_reply", "Customer picks an interactive list row"),
    ("reaction", "Customer reacts to a message"),
    ("status", "Message status update (sent / delivered / read / failed)"),
    ("template_status", "Template status update"),
    ("template_quality", "Template quality update"),
    ("template_category", "Template category update"),
    ("user_preferences", "Customer stops or resumes marketing messages"),
];

pub const STATUSES: &[(&str, &str)] =
    &[("sent", "sent"), ("delivered", "delivered"), ("read", "read"), ("failed", "failed")];
pub const TEMPLATE_EVENTS: &[(&str, &str)] = &[
    ("APPROVED", "APPROVED"),
    ("REJECTED", "REJECTED"),
    ("PENDING", "PENDING"),
    ("PAUSED", "PAUSED"),
    ("DISABLED", "DISABLED"),
    ("REINSTATED", "REINSTATED"),
    ("FLAGGED", "FLAGGED"),
    ("PENDING_DELETION", "PENDING_DELETION"),
    ("DELETED", "DELETED"),
    ("IN_APPEAL", "IN_APPEAL"),
];
pub const QUALITIES: &[(&str, &str)] = &[("GREEN", "GREEN"), ("YELLOW", "YELLOW"), ("RED", "RED")];
pub const CATEGORIES: &[(&str, &str)] =
    &[("MARKETING", "MARKETING"), ("UTILITY", "UTILITY"), ("AUTHENTICATION", "AUTHENTICATION")];
pub const PREFERENCES: &[(&str, &str)] = &[("stop", "stop"), ("resume", "resume")];
pub const SIGNATURES: &[(&str, &str)] = &[
    ("valid", "Valid X-Hub-Signature-256"),
    ("invalid", "Invalid signature (wrong secret)"),
    ("missing", "No signature header"),
];

/// Every send-form field except the signature choice.
pub const FIELDS: &[&str] = &[
    "type", "wa_id", "name", "text", "ref_wamid", "emoji", "latitude", "longitude", "status", "callback_data",
    "template_id", "template_name", "language", "event", "reason", "quality", "category", "preference",
];

/// The send form's fields, falling back to defaults for anything not submitted.
pub struct Form(HashMap<String, String>);

impl Form {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Form(fields)
    }

    pub fn get(&self, key: &str) -> &str {
        self.0.get(key).map_or_else(|| default(key), |v| v.trim())
    }
}

fn default(key: &str) -> &'static str {
    match key {
        "type" => "text",
        "wa_id" => "919876543210",
        "name" => "Test Customer",
        "text" => "Hi, I'd like to know more",
        "emoji" => "👍",
        "latitude" => "28.6139",
        "longitude" => "77.2090",
        "status" => "delivered",
        "template_id" => "123456789",
        "template_name" => "order_update",
        "language" => "en_US",
        "event" => "APPROVED",
        "reason" => "NONE",
        "quality" => "YELLOW",
        "category" => "MARKETING",
        "preference" => "stop",
        "signature" => "valid",
        _ => "",
    }
}

pub fn label(kind: &str) -> &str {
    KINDS.iter().find(|(k, _)| *k == kind).map_or(kind, |(_, l)| l)
}

fn wamid() -> String {
    let mut bytes = vec![0x1c, 0x18, 0x0c];
    bytes.extend(random_bytes::<30>());
    format!("wamid.{}", STANDARD.encode(bytes))
}

fn media(mime: &str) -> Value {
    let n = u64::from_le_bytes(random_bytes::<8>());
    json!({
        "mime_type": mime,
        "sha256": hex(&random_bytes::<32>()),
        "id": (1_000_000_000_000_000 + n % 9_000_000_000_000_000).to_string(),
    })
}

fn slug(text: &str) -> String {
    text.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

fn required<'a>(form: &'a Form, key: &str, what: &str) -> Result<&'a str, String> {
    match form.get(key) {
        "" => Err(format!("{what} is required for this webhook.")),
        value => Ok(value),
    }
}

fn customer(form: &Form) -> Result<&str, String> {
    let wa_id = form.get("wa_id");
    if (7..=15).contains(&wa_id.len()) && wa_id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(wa_id)
    } else {
        Err("Customer WhatsApp ID must be 7 to 15 digits, with country code.".into())
    }
}

fn template_id(form: &Form) -> Result<u64, String> {
    form.get("template_id").parse().map_err(|_| "Template ID must be a number.".to_string())
}

/// The full webhook body for the chosen kind.
pub fn build(form: &Form, settings: &Settings) -> Result<Value, String> {
    let kind = form.get("type");
    let metadata = json!({
        "display_phone_number": settings.display_phone_number,
        "phone_number_id": settings.phone_number_id,
    });
    let timestamp = now();

    let (field, value) = match kind {
        "text" | "image" | "audio" | "document" | "location" | "button" | "button_reply" | "list_reply"
        | "reaction" => {
            let wa_id = customer(form)?;
            let text = form.get("text");
            let (message_type, body) = match kind {
                "text" => ("text", json!({ "body": required(form, "text", "Text")? })),
                "image" => {
                    let mut body = media("image/jpeg");
                    if !text.is_empty() {
                        body["caption"] = json!(text);
                    }
                    ("image", body)
                }
                "audio" => {
                    let mut body = media("audio/ogg; codecs=opus");
                    body["voice"] = json!(true);
                    ("audio", body)
                }
                "document" => {
                    let mut body = media("application/pdf");
                    body["filename"] = json!("document.pdf");
                    if !text.is_empty() {
                        body["caption"] = json!(text);
                    }
                    ("document", body)
                }
                "location" => {
                    let coordinate = |key: &str| form.get(key).parse::<f64>().map_err(|_| format!("{key} must be a number."));
                    ("location", json!({ "latitude": coordinate("latitude")?, "longitude": coordinate("longitude")? }))
                }
                "button" => {
                    let text = required(form, "text", "Text (the button label)")?;
                    ("button", json!({ "payload": text, "text": text }))
                }
                "button_reply" => {
                    let title = required(form, "text", "Text (the button title)")?;
                    ("interactive", json!({ "type": "button_reply", "button_reply": { "id": slug(title), "title": title } }))
                }
                "list_reply" => {
                    let title = required(form, "text", "Text (the row title)")?;
                    ("interactive", json!({ "type": "list_reply", "list_reply": { "id": slug(title), "title": title } }))
                }
                _ => (
                    "reaction",
                    json!({ "message_id": required(form, "ref_wamid", "Referenced message ID")?, "emoji": form.get("emoji") }),
                ),
            };
            let mut message = json!({
                "from": wa_id,
                "id": wamid(),
                "timestamp": timestamp.to_string(),
                "type": message_type,
            });
            message[message_type] = body;
            let ref_wamid = form.get("ref_wamid");
            if !ref_wamid.is_empty() && kind != "reaction" {
                message["context"] = json!({ "from": settings.display_phone_number, "id": ref_wamid });
            }
            let value = json!({
                "messaging_product": "whatsapp",
                "metadata": metadata,
                "contacts": [{ "profile": { "name": form.get("name") }, "wa_id": wa_id }],
                "messages": [message],
            });
            ("messages", value)
        }
        "status" => {
            let status = form.get("status");
            let mut entry = json!({
                "id": required(form, "ref_wamid", "Referenced message ID")?,
                "status": status,
                "timestamp": timestamp.to_string(),
                "recipient_id": customer(form)?,
            });
            match status {
                "failed" => {
                    entry["errors"] = json!([{
                        "code": 131026,
                        "title": "Message undeliverable",
                        "message": "Message undeliverable",
                        "error_data": { "details": "Message Undeliverable." },
                    }]);
                }
                "read" => {}
                _ => {
                    entry["conversation"] = json!({ "id": hex(&random_bytes::<16>()), "origin": { "type": "marketing" } });
                    entry["pricing"] = json!({ "billable": true, "pricing_model": "PMP", "category": "marketing" });
                }
            }
            let callback = form.get("callback_data");
            if !callback.is_empty() {
                entry["biz_opaque_callback_data"] = json!(callback);
            }
            ("messages", json!({ "messaging_product": "whatsapp", "metadata": metadata, "statuses": [entry] }))
        }
        "template_status" => (
            "message_template_status_update",
            json!({
                "event": form.get("event"),
                "message_template_id": template_id(form)?,
                "message_template_name": form.get("template_name"),
                "message_template_language": form.get("language"),
                "reason": form.get("reason"),
            }),
        ),
        "template_quality" => {
            let new = form.get("quality");
            (
                "message_template_quality_update",
                json!({
                    "previous_quality_score": if new == "GREEN" { "YELLOW" } else { "GREEN" },
                    "new_quality_score": new,
                    "message_template_id": template_id(form)?,
                    "message_template_name": form.get("template_name"),
                    "message_template_language": form.get("language"),
                }),
            )
        }
        "template_category" => {
            let new = form.get("category");
            (
                "template_category_update",
                json!({
                    "message_template_id": template_id(form)?,
                    "message_template_name": form.get("template_name"),
                    "message_template_language": form.get("language"),
                    "previous_category": if new == "UTILITY" { "MARKETING" } else { "UTILITY" },
                    "new_category": new,
                }),
            )
        }
        "user_preferences" => {
            let wa_id = customer(form)?;
            let value = form.get("preference");
            let detail = if value == "stop" { "User requested to stop marketing messages" } else { "User requested to resume marketing messages" };
            (
                "user_preferences",
                json!({
                    "messaging_product": "whatsapp",
                    "metadata": metadata,
                    "contacts": [{ "profile": { "name": form.get("name") }, "wa_id": wa_id }],
                    "user_preferences": [{
                        "wa_id": wa_id,
                        "detail": detail,
                        "category": "marketing_messages",
                        "value": value,
                        "timestamp": timestamp,
                    }],
                }),
            )
        }
        other => return Err(format!("Unknown webhook type {other}.")),
    };

    Ok(json!({
        "object": "whatsapp_business_account",
        "entry": [{ "id": settings.waba_id, "changes": [{ "value": value, "field": field }] }],
    }))
}

fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex(&mac.finalize().into_bytes()))
}

pub struct Outcome {
    pub request_headers: Vec<(&'static str, String)>,
    pub status: Option<u16>,
    pub response: Option<String>,
    pub error: Option<String>,
    pub duration_ms: i64,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .into()
}

// Keep at most this much of a receiver's reply.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// POST one webhook the way Meta does: compact JSON, signed with the app secret.
pub fn deliver(url: &str, app_secret: &str, body: &str, signature: &str) -> Outcome {
    let mut headers = vec![("Content-Type", "application/json".to_string()), ("User-Agent", "facebookexternalua".to_string())];
    match signature {
        "valid" => headers.push(("X-Hub-Signature-256", sign(app_secret.as_bytes(), body.as_bytes()))),
        "invalid" => headers.push(("X-Hub-Signature-256", sign(&random_bytes::<16>(), body.as_bytes()))),
        _ => {}
    }

    let started = Instant::now();
    let mut request = agent().post(url);
    for (name, value) in &headers {
        request = request.header(*name, value);
    }
    let (status, response, error) = match request.send(body.as_bytes()) {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let text = response
                .body_mut()
                .with_config()
                .limit(MAX_RESPONSE_BYTES)
                .read_to_string()
                .unwrap_or_else(|e| format!("(could not read response: {e})"));
            (Some(status), Some(text), None)
        }
        Err(e) => (None, None, Some(e.to_string())),
    };
    Outcome { request_headers: headers, status, response, error, duration_ms: started.elapsed().as_millis() as i64 }
}

/// Run the GET handshake Meta performs when a callback URL is saved. Ok(message) when it passes.
pub fn verify(url: &str, verify_token: &str) -> Result<String, String> {
    let challenge = (u32::from_le_bytes(random_bytes::<4>()) % 1_000_000_000).to_string();
    let mut response = agent()
        .get(url)
        .query("hub.mode", "subscribe")
        .query("hub.verify_token", verify_token)
        .query("hub.challenge", &challenge)
        .call()
        .map_err(|e| format!("Request failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response.body_mut().with_config().limit(MAX_RESPONSE_BYTES).read_to_string().unwrap_or_default();
    if status == 200 && body == challenge {
        Ok(format!("Handshake passed: HTTP 200 echoed challenge {challenge}."))
    } else {
        Err(format!("Handshake failed: HTTP {status}, expected challenge {challenge}, got: {}", body.chars().take(300).collect::<String>()))
    }
}
