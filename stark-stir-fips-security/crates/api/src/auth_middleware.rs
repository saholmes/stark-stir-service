//! Bearer-token authentication middleware for `/v1/*` routes.
//!
//! Looks for an `Authorization: Bearer <token>` header.  The token is
//! validated against the `auth::AuthDb` (SHA3-256 hash lookup, revocation
//! and expiry checks).  On success the validated token info is inserted
//! into the request extensions so downstream handlers can read the scope
//! / user_id; on failure the request is short-circuited with `401`.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};

use crate::{types::ErrorResponse, AppState};

/// Public re-export so handlers can pull the validated token from
/// request extensions if they need to inspect scope.
pub use auth::ValidatedToken;

pub async fn require_bearer(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let bearer = extract_bearer(&headers).ok_or_else(|| (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse::with_details(
            "missing or malformed Authorization header",
            "expected: Authorization: Bearer <token>",
        )),
    ))?;

    let validated = match state.auth_db.validate_bearer(&bearer) {
        Ok(v) => v,
        Err(auth::AuthError::InvalidToken) => return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("invalid bearer token")),
        )),
        Err(auth::AuthError::TokenRevoked) => return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("bearer token revoked")),
        )),
        Err(auth::AuthError::TokenExpired) => return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("bearer token expired")),
        )),
        Err(e) => return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(format!("auth error: {e}"))),
        )),
    };

    req.extensions_mut().insert(validated);
    Ok(next.run(req).await)
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let v = v.trim();
    if let Some(rest) = v.strip_prefix("Bearer ") {
        return Some(rest.trim().to_string());
    }
    if let Some(rest) = v.strip_prefix("bearer ") {
        return Some(rest.trim().to_string());
    }
    None
}
