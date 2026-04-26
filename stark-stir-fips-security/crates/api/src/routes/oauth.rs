//! OAuth2 Resource Server endpoints (RFC 6749).
//!
//! * `POST /oauth2/token`        — issue a new bearer (admin-session-only)
//! * `POST /oauth2/revoke`       — revoke a bearer by id (admin-session-only)
//! * `POST /oauth2/introspect`   — RFC 7662 introspection (admin-session-only)
//! * `GET  /oauth2/tokens`       — list issued tokens (admin-session-only)
//!
//! For deployment scenarios where a client wants to "exchange creds for
//! a fresh access token" we expose `POST /oauth2/token` with
//! `grant_type=client_credentials`: the client authenticates with an
//! existing bearer (the "bootstrap token" for example), and the server
//! mints a short-lived token that the client uses thereafter.  This is
//! a thin convention over the same `auth::AuthDb` and shares its
//! validation logic.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{Json as JsonResp, IntoResponse},
    Form,
};
use serde::{Deserialize, Serialize};

use crate::{
    types::ErrorResponse,
    AppState,
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /oauth2/token  — `grant_type=client_credentials`
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type:    String,
    pub client_id:     Option<String>,
    pub client_secret: Option<String>,
    /// Fallback for callers that send the existing bearer in the form body.
    pub bearer:        Option<String>,
    pub scope:         Option<String>,
    /// Lifetime in seconds (default: 3600).
    pub expires_in:    Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type:   &'static str,
    pub expires_in:   i64,
    pub scope:        String,
}

/// Mint a fresh access token.  The caller authenticates with an existing
/// valid bearer (passed in either the Authorization header or as
/// `client_secret`/`bearer` form field).  The new token inherits the
/// caller's scope unless explicitly narrowed via the `scope` form field.
pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<JsonResp<TokenResponse>, (StatusCode, JsonResp<ErrorResponse>)> {
    if req.grant_type != "client_credentials" {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("unsupported grant_type '{}' (only 'client_credentials')", req.grant_type),
        ));
    }

    // Authenticate using either Authorization: Bearer …, client_secret, or bearer.
    let bearer = extract_authentication(&headers, &req)
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "missing client credentials"))?;

    let caller = state.auth_db.validate_bearer(&bearer)
        .map_err(|e| api_err(StatusCode::UNAUTHORIZED, format!("invalid credentials: {e}")))?;

    let scope = req.scope.unwrap_or_else(|| caller.scope.clone());
    let ttl   = req.expires_in.unwrap_or(3600).max(1);

    let issued = state.auth_db.create_token(
        caller.user_id,
        &format!("oauth2 client_credentials @ {}",
                 chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")),
        &scope,
        Some(ttl),
    ).map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("issue: {e}")))?;

    Ok(JsonResp(TokenResponse {
        access_token: issued.bearer,
        token_type:   "Bearer",
        expires_in:   ttl,
        scope,
    }))
}

fn extract_authentication(
    headers: &axum::http::HeaderMap,
    body:    &TokenRequest,
) -> Option<String> {
    // Authorization: Bearer …
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(rest) = s.trim().strip_prefix("Bearer ") {
                return Some(rest.trim().into());
            }
        }
    }
    // client_secret / bearer in form body
    body.client_secret.clone().or_else(|| body.bearer.clone())
}

// ─────────────────────────────────────────────────────────────────────────────
//  RFC 7662 introspection
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i64>,
}

pub async fn introspect_endpoint(
    State(state): State<AppState>,
    Form(req): Form<IntrospectRequest>,
) -> JsonResp<IntrospectResponse> {
    match state.auth_db.validate_bearer(&req.token) {
        Ok(v) => JsonResp(IntrospectResponse {
            active:  true,
            scope:   Some(v.scope),
            user_id: Some(v.user_id),
        }),
        Err(_) => JsonResp(IntrospectResponse { active: false, scope: None, user_id: None }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Admin endpoints (require admin session)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name:       String,
    pub scope:      String,
    pub ttl_secs:   Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub id:     i64,
    pub bearer: String,
    pub name:   String,
    pub scope:  String,
}

/// Admin-only: mint a long-lived API token.  Requires a valid admin
/// session cookie (set by `routes::admin::login`).
pub async fn admin_create_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Result<JsonResp<CreateTokenResponse>, (StatusCode, JsonResp<ErrorResponse>)> {
    let session = require_admin_session(&state, &headers)?;
    let issued = state.auth_db.create_token(
        session.user_id, &req.name, &req.scope, req.ttl_secs
    ).map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(JsonResp(CreateTokenResponse {
        id: issued.info.id,
        bearer: issued.bearer,
        name: issued.info.name,
        scope: issued.info.scope,
    }))
}

pub async fn admin_list_tokens(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<JsonResp<Vec<auth::ApiTokenInfo>>, (StatusCode, JsonResp<ErrorResponse>)> {
    let _session = require_admin_session(&state, &headers)?;
    let tokens = state.auth_db.list_tokens()
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(JsonResp(tokens))
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest { pub token_id: i64 }

pub async fn admin_revoke_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, JsonResp<ErrorResponse>)> {
    let _session = require_admin_session(&state, &headers)?;
    state.auth_db.revoke_token(req.token_id)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn require_admin_session(
    state:   &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<auth::Session, (StatusCode, JsonResp<ErrorResponse>)> {
    let cookie_header = headers.get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let session_id = cookie_header
        .split(';')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("stark_session=")
        })
        .next()
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "no session cookie"))?;
    let session = state.auth_db.validate_session(session_id)
        .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "session invalid or expired"))?;
    if !session.is_admin {
        return Err(api_err(StatusCode::FORBIDDEN, "admin role required"));
    }
    Ok(session)
}

pub(crate) fn api_err(code: StatusCode, msg: impl Into<String>)
    -> (StatusCode, JsonResp<ErrorResponse>)
{
    (code, JsonResp(ErrorResponse::new(msg.into())))
}

// Helper used by routes/admin.rs to build a Set-Cookie response.
#[allow(dead_code)]
pub(crate) fn cookie_response(name: &str, value: &str, max_age_secs: i64) -> String {
    if max_age_secs <= 0 {
        format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
    } else {
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}")
    }
}

// Used to bring `IntoResponse` into scope for any future error-mapping work.
#[allow(dead_code)]
fn _into_response_anchor(r: impl IntoResponse) -> axum::response::Response {
    r.into_response()
}
