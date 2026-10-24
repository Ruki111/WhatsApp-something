# OpenPing webhook simulator

Sends fake Meta WhatsApp Cloud API webhooks, signed the way Meta signs them, to any backend URL you choose.
Built for testing [OpenPing](https://github.com/Ruki111/OpenPing)'s `/webhooks/whatsapp` without a real phone.

One Rust binary, one SQLite file, plain HTML forms (no CSS, no JavaScript). About 5 MB of memory at rest.

## Run

```bash
docker compose up --build        # http://localhost:8080
```

Without Docker (Rust is pinned in `mise.toml`):

```bash
cargo run --release              # http://127.0.0.1:8080
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADDR` | `127.0.0.1:8080` (`0.0.0.0:8080` in Docker) | Listen address |
| `DATABASE_PATH` | `webhook-simulator.db` (`/data/simulator.db` in Docker) | SQLite file |

## Use

1. **Register** with a user ID and password, or **log in**.
2. Under **Where webhooks go**, set your backend URL and the identity the webhook claims: app secret, WABA ID,
   phone number ID and display number. Each user has their own settings and history.
3. **Choose a webhook**, fill the fields it uses, then **Send**, or **Preview JSON** to edit the body before sending.
4. **History** lists every delivery with its headers, body and the backend's response. **Replay** resends one.

From the Docker container, reach services on your machine with `http://host.docker.internal:<port>/...`, not `localhost`.

For OpenPing, the app secret, WABA ID and phone number ID must match its WhatsApp connection, or it rejects the webhook.

## Webhooks

| Webhook | Meta field |
| --- | --- |
| Customer text, image, voice note, document, location | `messages` |
| Template quick-reply button, interactive reply button, list row | `messages` |
| Reaction | `messages` |
| Message status: sent, delivered, read, failed | `messages` (`statuses`) |
| Template status, quality and category updates | `message_template_*`, `template_category_update` |
| Marketing stop / resume | `user_preferences` |

Signature can be valid, invalid (wrong secret) or missing, to test rejection. **Test verification handshake** runs
Meta's `GET ?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…` check against your URL.

To add a webhook, add it to `KINDS` and `build` in `src/webhooks.rs`, plus any new fields to the form in `src/html.rs`.

## Layout

| File | Contents |
| --- | --- |
| `src/main.rs` | HTTP server and routes |
| `src/auth.rs` | Argon2id password hashes, session cookies |
| `src/db.rs` | SQLite schema and queries |
| `src/webhooks.rs` | Payload builders, signing, delivery |
| `src/html.rs` | Pages |
