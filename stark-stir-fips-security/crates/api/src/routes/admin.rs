//! Admin web UI for managing API tokens.
//!
//! Routes (HTML responses; cookie sessions):
//!   GET  /admin              — token list dashboard (requires session)
//!   GET  /admin/login        — login form
//!   POST /admin/login        — submit credentials, set session cookie
//!   POST /admin/logout       — clear session cookie
//!   POST /admin/create-token — create a new bearer (admin session)
//!   POST /admin/revoke       — revoke a bearer (admin session)
//!
//! HTML is inlined as Rust string templates — no template engine, no
//! external CSS framework, just enough to be functional.

use axum::{
    extract::{Form, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{
    routes::oauth::cookie_response,
    AppState,
};

// ─────────────────────────────────────────────────────────────────────────────
//  Dashboard
// ─────────────────────────────────────────────────────────────────────────────

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let session = match super::oauth::require_admin_session(&state, &headers) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/admin/login").into_response(),
    };
    let tokens = match state.auth_db.list_tokens() {
        Ok(t) => t,
        Err(e) => return Html(format!("DB error: {e}")).into_response(),
    };
    let devices = state.auth_db.list_devices().unwrap_or_default();
    Html(render_dashboard(&session, &tokens, &devices)).into_response()
}

fn render_dashboard(
    s: &auth::Session,
    tokens: &[auth::ApiTokenInfo],
    devices: &[auth::SwarmDevice],
) -> String {
    let mut rows = String::new();
    for t in tokens {
        let status = if t.revoked { "<span style='color:#a33'>revoked</span>" }
                      else { "<span style='color:#080'>active</span>" };
        let exp = t.expires_at
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "—".into());
        let last = t.last_used
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "—".into());
        let name_html = html_escape(&t.name);
        let scope_html = html_escape(&t.scope);
        rows.push_str(&format!(r#"
            <tr>
              <td>{id}</td>
              <td>{name}</td>
              <td><code>{scope}</code></td>
              <td>{created}</td>
              <td>{expires}</td>
              <td>{last_used}</td>
              <td>{status}</td>
              <td>
                <form method="POST" action="/admin/revoke" style="display:inline">
                  <input type="hidden" name="token_id" value="{id}"/>
                  <button {disabled} type="submit">Revoke</button>
                </form>
              </td>
            </tr>
        "#,
            id = t.id, name = name_html, scope = scope_html,
            created = t.created_at.format("%Y-%m-%d %H:%M UTC"),
            expires = exp, last_used = last, status = status,
            disabled = if t.revoked { "disabled" } else { "" },
        ));
    }

    let mut device_rows = String::new();
    for d in devices {
        let last = d.last_seen
            .map(|x| x.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "—".into());
        device_rows.push_str(&format!(r#"
            <tr>
              <td>{id}</td>
              <td>{name}</td>
              <td><code>{addr}</code></td>
              <td>2^{logt}</td>
              <td>{ram} MiB</td>
              <td>{status}</td>
              <td>{last}</td>
              <td>
                <form method="POST" action="/admin/devices/remove" style="display:inline">
                  <input type="hidden" name="device_id" value="{id}"/>
                  <button type="submit">Remove</button>
                </form>
              </td>
            </tr>
        "#,
            id = d.id, name = html_escape(&d.name),
            addr = html_escape(&d.address),
            logt = d.max_trace_log2, ram = d.ram_mb,
            status = d.status.as_str(), last = last,
        ));
    }
    if device_rows.is_empty() {
        device_rows = r#"<tr><td colspan="8"><em>(no devices registered)</em></td></tr>"#.into();
    }

    format!(r#"<!doctype html>
<html><head><title>STARK API admin</title>
<style>
body{{font-family:-apple-system,sans-serif;max-width:1100px;margin:2em auto;padding:1em;color:#222}}
table{{border-collapse:collapse;width:100%;margin:1em 0}}
th,td{{text-align:left;padding:.5em;border-bottom:1px solid #eee}}
th{{background:#fafafa}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:.9em}}
form.inline-create{{background:#f9f9f9;padding:1em;border:1px solid #ddd;border-radius:4px;margin:1em 0}}
form.inline-create input{{margin-right:.5em;padding:.4em}}
.flash{{background:#e8f5e9;border:1px solid #2e7d32;padding:.5em 1em;border-radius:4px;margin:1em 0}}
.flash code{{font-size:1em;background:#fff;padding:4px 6px}}
button{{padding:.3em .8em;cursor:pointer}}
</style></head>
<body>
<h1>STARK API — Admin</h1>
<p>Logged in as <strong>{user}</strong>{admin_badge}.
<form method="POST" action="/admin/logout" style="display:inline">
  <button type="submit">Log out</button>
</form>
</p>

<h2>Issue a new API token</h2>
<form method="POST" action="/admin/create-token" class="inline-create">
  <label>Name <input type="text" name="name" required placeholder="ci-pipeline" /></label>
  <label>Scope <input type="text" name="scope" required placeholder="stark:prove stark:verify" /></label>
  <label>TTL (seconds) <input type="number" name="ttl_secs" placeholder="(blank = no expiry)" /></label>
  <button type="submit">Create</button>
</form>

<h2>Existing tokens</h2>
<table>
<tr>
  <th>ID</th><th>Name</th><th>Scope</th><th>Created</th><th>Expires</th>
  <th>Last used</th><th>Status</th><th>Action</th>
</tr>
{rows}
</table>

<h2>Swarm prover — IoT device pool</h2>
<p>Register low-RAM devices that can take a shard of a partitioned prove
job.  See <code>docs/swarm-prover.md</code> for the architecture.</p>

<form method="POST" action="/admin/devices/register" class="inline-create">
  <label>Name <input type="text" name="name" required placeholder="rpi-01" /></label>
  <label>Address <input type="text" name="address" required placeholder="192.168.1.42:3000" /></label>
  <label>Bearer (optional) <input type="text" name="bearer_token" placeholder="dev_secret" /></label>
  <label>max log₂(trace) <input type="number" name="max_trace_log2" value="18" /></label>
  <label>RAM (MiB) <input type="number" name="ram_mb" value="1024" /></label>
  <label>Notes <input type="text" name="notes" placeholder="kitchen rpi" /></label>
  <button type="submit">Register</button>
</form>

<table>
<tr>
  <th>ID</th><th>Name</th><th>Address</th><th>Max log₂(trace)</th>
  <th>RAM</th><th>Status</th><th>Last seen</th><th>Action</th>
</tr>
{device_rows}
</table>

<h2>Quick start</h2>
<pre>curl -H "Authorization: Bearer &lt;your-token&gt;" \
     http://&lt;server&gt;/v1/security/profiles
</pre>
</body></html>"#,
        user = html_escape(&s.username),
        admin_badge = if s.is_admin { " <em>(admin)</em>" } else { "" },
        rows = rows,
        device_rows = device_rows,
    )
}

// ─── Device pool: form-driven register / remove ──────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DeviceRegisterForm {
    pub name:           String,
    pub address:        String,
    pub bearer_token:   Option<String>,
    pub max_trace_log2: Option<u32>,
    pub ram_mb:         Option<u32>,
    pub notes:          Option<String>,
}

pub async fn register_device_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceRegisterForm>,
) -> Response {
    let session = match super::oauth::require_admin_session(&state, &headers) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/admin/login").into_response(),
    };
    let trim = |s: Option<String>| s.and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() { None } else { Some(t) }
    });
    let bearer = trim(form.bearer_token);
    let notes = trim(form.notes);

    if let Err(e) = state.auth_db.register_device(
        &form.name,
        &form.address,
        bearer.as_deref(),
        form.max_trace_log2.unwrap_or(18),
        form.ram_mb.unwrap_or(1024),
        Some(session.user_id),
        notes.as_deref(),
    ) {
        return Html(format!("device register error: {e}")).into_response();
    }
    Redirect::to("/admin").into_response()
}

#[derive(Debug, Deserialize)]
pub struct DeviceRemoveForm { pub device_id: i64 }

pub async fn remove_device_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceRemoveForm>,
) -> Response {
    if super::oauth::require_admin_session(&state, &headers).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(e) = state.auth_db.remove_device(form.device_id) {
        return Html(format!("device remove error: {e}")).into_response();
    }
    Redirect::to("/admin").into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}

// ─────────────────────────────────────────────────────────────────────────────
//  Login page
// ─────────────────────────────────────────────────────────────────────────────

pub async fn login_form() -> Html<&'static str> {
    Html(LOGIN_FORM)
}

const LOGIN_FORM: &str = r#"<!doctype html>
<html><head><title>STARK admin login</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:400px;margin:6em auto;padding:1em;color:#222}
form{background:#f9f9f9;padding:1.5em;border:1px solid #ddd;border-radius:4px}
label{display:block;margin:.5em 0 .25em}
input{width:100%;padding:.5em;box-sizing:border-box}
button{padding:.5em 1em;margin-top:1em;cursor:pointer}
.err{background:#ffebee;border:1px solid #c62828;padding:.5em 1em;border-radius:4px;margin-bottom:1em}
</style></head>
<body>
<h1>STARK admin</h1>
<form method="POST" action="/admin/login">
  <label>Username</label><input type="text" name="username" required autofocus />
  <label>Password</label><input type="password" name="password" required />
  <button type="submit">Log in</button>
</form>
</body></html>"#;

#[derive(Debug, Deserialize)]
pub struct LoginForm { pub username: String, pub password: String }

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let user = match state.auth_db.verify_login(&form.username, &form.password) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Html("<p>Invalid credentials. <a href='/admin/login'>try again</a></p>"),
            ).into_response();
        }
    };
    let session_id = match state.auth_db.create_session(user.id, 12) {
        Ok(s) => s,
        Err(e) => return Html(format!("session create error: {e}")).into_response(),
    };
    let cookie = cookie_response("stark_session", &session_id, 12 * 3600);

    let mut resp = Redirect::to("/admin").into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        cookie.parse().expect("cookie value parses"),
    );
    resp
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Some(sid) = extract_session_cookie(&headers) {
        let _ = state.auth_db.delete_session(&sid);
    }
    let cookie = cookie_response("stark_session", "", 0);
    let mut resp = Redirect::to("/admin/login").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header
        .split(';')
        .find_map(|p| p.trim().strip_prefix("stark_session=").map(|s| s.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Form-driven token create / revoke (admin web UI)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    pub name:     String,
    pub scope:    String,
    /// Optional TTL in seconds.  Empty string → no expiry.
    pub ttl_secs: Option<String>,
}

pub async fn create_token_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateForm>,
) -> Response {
    let session = match super::oauth::require_admin_session(&state, &headers) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/admin/login").into_response(),
    };
    let ttl_secs = form.ttl_secs.as_ref().and_then(|s| {
        if s.trim().is_empty() { None } else { s.trim().parse::<i64>().ok() }
    });
    let issued = match state.auth_db.create_token(session.user_id, &form.name, &form.scope, ttl_secs) {
        Ok(t) => t,
        Err(e) => return Html(format!("create error: {e}")).into_response(),
    };
    let bearer_html = html_escape(&issued.bearer);
    let body = format!(r#"<!doctype html>
<html><head><title>Token issued</title>
<style>
body{{font-family:-apple-system,sans-serif;max-width:800px;margin:3em auto;padding:1em}}
.flash{{background:#e8f5e9;border:1px solid #2e7d32;padding:1em 1.5em;border-radius:4px}}
code{{font-size:1.05em;background:#fff;padding:6px 10px;border:1px solid #ccc;border-radius:3px;display:inline-block;word-break:break-all}}
</style></head>
<body>
<div class="flash">
<h2>Token created — copy it now</h2>
<p>This token is shown <strong>once</strong>; the server stores only its hash.</p>
<p><code>{bearer_html}</code></p>
<p>ID: {id} · Scope: <code>{scope}</code></p>
<p><a href="/admin">Back to dashboard</a></p>
</div>
</body></html>"#,
        id = issued.info.id,
        scope = html_escape(&issued.info.scope),
    );
    Html(body).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm { pub token_id: i64 }

pub async fn revoke_token_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    if super::oauth::require_admin_session(&state, &headers).is_err() {
        return Redirect::to("/admin/login").into_response();
    }
    if let Err(e) = state.auth_db.revoke_token(form.token_id) {
        return Html(format!("revoke error: {e}")).into_response();
    }
    Redirect::to("/admin").into_response()
}
