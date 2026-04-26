//! STARK Prove/Verify REST API.
//!
//! Public endpoints (no auth required):
//!   GET  /v1/health                — liveness probe
//!   GET  /admin/login              — admin login form
//!   POST /admin/login              — submit login form
//!
//! Bearer-protected endpoints (require `Authorization: Bearer <token>`):
//!   POST /v1/prove                 — run the prover, store the proof
//!   POST /v1/verify                — verify a proof
//!   GET  /v1/proofs                — list stored proofs
//!   GET  /v1/proofs/{id}           — fetch a stored proof
//!   GET  /v1/security/profiles     — NIST profile catalogue
//!
//! OAuth2-style token management (RFC 6749 / RFC 7662 conventions):
//!   POST /oauth2/token             — issue a fresh token (caller authenticates with an existing bearer)
//!   POST /oauth2/introspect        — RFC 7662 token introspection
//!
//! Admin web UI (requires admin session cookie):
//!   GET  /admin                    — token-management dashboard
//!   POST /admin/logout
//!   POST /admin/create-token       — issue a long-lived bearer
//!   POST /admin/revoke             — revoke a bearer
//!
//! Admin JSON API (requires admin session cookie):
//!   POST /v1/admin/tokens          — issue a bearer
//!   GET  /v1/admin/tokens          — list bearers
//!   POST /v1/admin/tokens/revoke   — revoke a bearer

pub mod auth_middleware;
pub mod convert;
pub mod routes;
pub mod security;
pub mod types;

use std::sync::Arc;

use axum::{
    middleware,
    Router,
    routing::{get, post},
};
use proof_store::ProofStore;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Shared application state threaded through all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub store:   Arc<ProofStore>,
    pub auth_db: Arc<auth::AuthDb>,
}

impl AppState {
    pub fn new(store: ProofStore, auth_db: auth::AuthDb) -> Self {
        AppState {
            store:   Arc::new(store),
            auth_db: Arc::new(auth_db),
        }
    }

    pub fn store_path_for(&self, proof_id: &str) -> std::path::PathBuf {
        self.store.path_for_id(proof_id)
    }

    /// Test helper: open a fresh ephemeral auth DB in tempdir.
    /// Existing integration tests that call handlers directly (not through
    /// the router) bypass the bearer middleware anyway, so a no-op DB is
    /// sufficient.  Production callers should use `AppState::new`.
    pub fn with_in_memory_auth(store: ProofStore) -> Self {
        let db_path = std::env::temp_dir().join(format!(
            "stark-test-auth-{}.sqlite", uuid::Uuid::new_v4()));
        let auth_db = auth::AuthDb::open(&db_path)
            .expect("test auth DB open");
        AppState {
            store:   Arc::new(store),
            auth_db: Arc::new(auth_db),
        }
    }
}

/// Build the Axum router with auth-protected /v1/* routes and the
/// admin web UI at /admin*.
pub fn build_router(state: AppState) -> Router {
    // Bearer-protected /v1/* routes.
    let protected = Router::new()
        .route("/v1/prove",                post(routes::prove::handle_prove))
        .route("/v1/verify",               post(routes::verify::handle_verify))
        .route("/v1/proofs",               get(routes::proofs::list_proofs))
        .route("/v1/proofs/:id",           get(routes::proofs::get_proof))
        .route("/v1/security/profiles",    get(routes::security::list_profiles))
        // Admin JSON API (admin session required, NOT bearer)
        .route("/v1/admin/tokens",         post(routes::oauth::admin_create_token))
        .route("/v1/admin/tokens",         get(routes::oauth::admin_list_tokens))
        .route("/v1/admin/tokens/revoke",  post(routes::oauth::admin_revoke_token))
        // Swarm-prover device pool management (admin session protected)
        .route("/v1/swarm/devices",        post(routes::swarm::register_device))
        .route("/v1/swarm/devices",        get(routes::swarm::list_devices))
        .route("/v1/swarm/devices/:id",    axum::routing::delete(routes::swarm::remove_device))
        .route("/v1/swarm/devices/:id/heartbeat", post(routes::swarm::heartbeat))
        // Distributed prove orchestrator (returns shard plan + estimates;
        // HTTP dispatch is a documented next step).
        .route("/v1/swarm/prove",          post(routes::swarm::swarm_prove))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::require_bearer,
        ));

    // Open routes — no auth.
    let open = Router::new()
        .route("/v1/health",               get(routes::health::handle_health))
        .route("/oauth2/token",            post(routes::oauth::token_endpoint))
        .route("/oauth2/introspect",       post(routes::oauth::introspect_endpoint))
        .route("/admin",                   get(routes::admin::dashboard))
        .route("/admin/login",             get(routes::admin::login_form).post(routes::admin::login_submit))
        .route("/admin/logout",            post(routes::admin::logout))
        .route("/admin/create-token",      post(routes::admin::create_token_form))
        .route("/admin/revoke",            post(routes::admin::revoke_token_form))
        .route("/admin/devices/register",  post(routes::admin::register_device_form))
        .route("/admin/devices/remove",    post(routes::admin::remove_device_form));

    Router::new()
        .merge(protected)
        .merge(open)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
