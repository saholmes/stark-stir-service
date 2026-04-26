use axum::{extract::State, Json};
use serde::Serialize;
use crate::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub cached_proof_count: usize,
}

pub async fn handle_health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: "stark-stir-fips-v1",
        cached_proof_count: state.store.cache_size(),
    })
}
