//! Plain HTML pages: no CSS, no JavaScript. Every dynamic value goes through `esc`.

use crate::db::{Delivery, User};
use crate::webhooks::{self, Form};

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width\">\n\
         <title>{} - Webhook simulator</title>\n</head>\n<body>\n{body}\n</body>\n</html>\n",
        esc(title)
    )
}

fn messages(notice: Option<&str>, error: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(error) = error {
        out += &format!("<p><strong>Error:</strong> {}</p>\n", esc(error));
    }
    if let Some(notice) = notice {
        out += &format!("<p><strong>{}</strong></p>\n", esc(notice));
    }
    out
}

fn nav(user: &User) -> String {
    format!(
        "<p>Signed in as <strong>{}</strong> | <a href=\"/app\">Send</a> | <a href=\"/history\">History</a></p>\n\
         <form method=\"post\" action=\"/logout\"><button>Log out</button></form>\n<hr>\n",
        esc(&user.userid)
    )
}

fn select(name: &str, options: &[(&str, &str)], current: &str) -> String {
    let mut out = format!("<select name=\"{name}\">");
    for (value, label) in options {
        let selected = if *value == current { " selected" } else { "" };
        out += &format!("<option value=\"{}\"{selected}>{}</option>", esc(value), esc(label));
    }
    out + "</select>"
}

fn field(label: &str, control: &str, hint: &str) -> String {
    let hint = if hint.is_empty() { String::new() } else { format!("<br><small>{}</small>", esc(hint)) };
    format!("<p><label>{}<br>{control}</label>{hint}</p>\n", esc(label))
}

fn input(name: &str, value: &str, size: u32) -> String {
    format!("<input name=\"{name}\" value=\"{}\" size=\"{size}\">", esc(value))
}

pub enum AuthKind {
    Login,
    Register,
}

pub fn auth_page(kind: AuthKind, userid: &str, error: Option<&str>) -> String {
    let (title, action, button, other) = match kind {
        AuthKind::Login => ("Log in", "/login", "Log in", "<a href=\"/register\">Create an account</a>"),
        AuthKind::Register => ("Register", "/register", "Create account", "<a href=\"/login\">Log in instead</a>"),
    };
    let body = format!(
        "<h1>OpenPing webhook simulator</h1>\n<h2>{title}</h2>\n{}\
         <form method=\"post\" action=\"{action}\">\n{}{}<p><button>{button}</button></p>\n</form>\n<p>{other}</p>",
        messages(None, error),
        field(
            "User ID",
            &format!("<input name=\"userid\" value=\"{}\" required autocomplete=\"username\">", esc(userid)),
            "3 to 32 letters, digits, dots, dashes or underscores"
        ),
        field(
            "Password",
            "<input type=\"password\" name=\"password\" required autocomplete=\"current-password\">",
            "At least 8 characters"
        ),
    );
    page(title, &body)
}

pub struct AppView<'a> {
    pub form: &'a Form,
    pub notice: Option<&'a str>,
    pub error: Option<&'a str>,
    /// Pretty JSON shown for editing before it is sent.
    pub preview: Option<&'a str>,
    pub result: Option<&'a Delivery>,
}

pub fn app_page(user: &User, view: AppView) -> String {
    let s = &user.settings;
    let f = view.form;
    let mut body = nav(user);
    body += "<h1>Send a webhook</h1>\n";
    body += &messages(view.notice, view.error);

    if let Some(delivery) = view.result {
        body += "<h2>Result</h2>\n";
        body += &delivery_summary(delivery);
    }

    body += "<h2>1. Where webhooks go</h2>\n<form method=\"post\" action=\"/settings\">\n";
    body += &field("Backend URL", &input("backend_url", &s.backend_url, 70), "Your webhook endpoint, e.g. http://localhost:8000/webhooks/whatsapp for a local OpenPing");
    body += &field("App secret", &input("app_secret", &s.app_secret, 40), "Signs X-Hub-Signature-256; must match the receiver's Meta app secret");
    body += &field("Verify token", &input("verify_token", &s.verify_token, 40), "Used only by the verification handshake");
    body += &field("WABA ID", &input("waba_id", &s.waba_id, 30), "Sent as entry[].id");
    body += &field("Phone number ID", &input("phone_number_id", &s.phone_number_id, 30), "Sent as metadata.phone_number_id");
    body += &field("Display phone number", &input("display_phone_number", &s.display_phone_number, 30), "The business number customers message");
    body += "<p><button>Save settings</button></p>\n</form>\n";
    body += "<form method=\"post\" action=\"/verify\"><p><button>Test verification handshake (GET)</button></p></form>\n";

    body += "<h2>2. Choose and send a webhook</h2>\n<form method=\"post\" action=\"/send\">\n";
    body += &field("Webhook", &select("type", webhooks::KINDS, f.get("type")), "Fill in the fields that apply to it; the rest are ignored");
    body += "<fieldset>\n<legend>Customer</legend>\n";
    body += &field("Customer WhatsApp ID (wa_id)", &input("wa_id", f.get("wa_id"), 20), "Digits with country code");
    body += &field("Customer profile name", &input("name", f.get("name"), 30), "");
    body += "</fieldset>\n<fieldset>\n<legend>Message</legend>\n";
    body += &field("Text", &input("text", f.get("text"), 60), "Message body, media caption, or the button / row title");
    body += &field("Referenced message ID (wamid)", &input("ref_wamid", f.get("ref_wamid"), 60), "Reply-to context, the reaction target, or the message a status is about");
    body += &field("Reaction emoji", &input("emoji", f.get("emoji"), 6), "Empty removes the reaction");
    body += &field("Latitude", &input("latitude", f.get("latitude"), 12), "");
    body += &field("Longitude", &input("longitude", f.get("longitude"), 12), "");
    body += "</fieldset>\n<fieldset>\n<legend>Status update</legend>\n";
    body += &field("Status", &select("status", webhooks::STATUSES, f.get("status")), "");
    body += &field("Callback data (biz_opaque_callback_data)", &input("callback_data", f.get("callback_data"), 40), "Optional; echoes what the sender attached to the message");
    body += "</fieldset>\n<fieldset>\n<legend>Template</legend>\n";
    body += &field("Template ID", &input("template_id", f.get("template_id"), 20), "");
    body += &field("Template name", &input("template_name", f.get("template_name"), 30), "");
    body += &field("Language", &input("language", f.get("language"), 10), "");
    body += &field("Status event", &select("event", webhooks::TEMPLATE_EVENTS, f.get("event")), "");
    body += &field("Rejection reason", &input("reason", f.get("reason"), 30), "");
    body += &field("New quality score", &select("quality", webhooks::QUALITIES, f.get("quality")), "");
    body += &field("New category", &select("category", webhooks::CATEGORIES, f.get("category")), "");
    body += "</fieldset>\n<fieldset>\n<legend>Marketing preference</legend>\n";
    body += &field("Preference", &select("preference", webhooks::PREFERENCES, f.get("preference")), "");
    body += "</fieldset>\n";
    body += &field("Signature", &select("signature", webhooks::SIGNATURES, f.get("signature")), "");
    body += "<p><button formaction=\"/preview\">Preview JSON</button> <button>Send</button></p>\n</form>\n";

    if let Some(json) = view.preview {
        body += "<h2>3. Review and send the JSON</h2>\n<form method=\"post\" action=\"/send-raw\">\n";
        body += &format!("<p><textarea name=\"payload\" rows=\"30\" cols=\"100\">{}</textarea></p>\n", esc(json));
        // Carry the form along so it stays filled in after sending.
        for name in webhooks::FIELDS {
            body += &format!("<input type=\"hidden\" name=\"{name}\" value=\"{}\">\n", esc(f.get(name)));
        }
        body += &field("Signature", &select("signature", webhooks::SIGNATURES, f.get("signature")), "");
        body += "<p><button>Send this JSON</button></p>\n</form>\n";
    }
    page("Send", &body)
}

fn delivery_summary(d: &Delivery) -> String {
    let outcome = match (d.status, &d.error) {
        (Some(status), _) => format!("HTTP {status}"),
        (None, Some(error)) => format!("No response: {}", esc(error)),
        (None, None) => "Not sent".into(),
    };
    format!(
        "<p><strong>{outcome}</strong> in {} ms - {} - <a href=\"/deliveries/{}\">details</a></p>\n<pre>{}</pre>\n",
        d.duration_ms,
        esc(webhooks::label(&d.kind)),
        d.id,
        esc(d.response.as_deref().unwrap_or(""))
    )
}

pub fn history_page(user: &User, deliveries: &[Delivery]) -> String {
    let mut body = nav(user);
    body += "<h1>History</h1>\n";
    if deliveries.is_empty() {
        body += "<p>No webhooks sent yet.</p>\n";
    } else {
        body += "<table>\n<tr><th>#</th><th>Sent (UTC)</th><th>Webhook</th><th>Signature</th><th>Response</th><th>Time</th></tr>\n";
        for d in deliveries {
            let status = d.status.map_or_else(|| "no response".to_string(), |s| s.to_string());
            body += &format!(
                "<tr><td><a href=\"/deliveries/{0}\">{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5} ms</td></tr>\n",
                d.id,
                esc(&d.created_at),
                esc(webhooks::label(&d.kind)),
                esc(&d.signature),
                esc(&status),
                d.duration_ms
            );
        }
        body += "</table>\n<form method=\"post\" action=\"/history/clear\"><p><button>Clear history</button></p></form>\n";
    }
    page("History", &body)
}

pub fn delivery_page(user: &User, d: &Delivery) -> String {
    let pretty = serde_json::from_str::<serde_json::Value>(&d.body)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or_else(|_| d.body.clone());
    let mut body = nav(user);
    body += &format!("<h1>Webhook #{}</h1>\n", d.id);
    body += &delivery_summary(d);
    body += &format!(
        "<p>Sent {} UTC to {}<br>Webhook: {}<br>Signature: {}</p>\n",
        esc(&d.created_at),
        esc(&d.url),
        esc(webhooks::label(&d.kind)),
        esc(&d.signature)
    );
    body += &format!(
        "<form method=\"post\" action=\"/deliveries/{}/replay\"><p><button>Replay</button> \
         <small>Resends the same body and message IDs to your current backend URL</small></p></form>\n",
        d.id
    );
    body += &format!("<h2>Request headers</h2>\n<pre>{}</pre>\n", esc(&d.request_headers));
    body += &format!("<h2>Request body</h2>\n<pre>{}</pre>\n", esc(&pretty));
    page(&format!("Webhook #{}", d.id), &body)
}

pub fn not_found() -> String {
    page("Not found", "<h1>Not found</h1>\n<p><a href=\"/\">Home</a></p>")
}
