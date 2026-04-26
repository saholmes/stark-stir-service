//! GET /v1/proofs and GET /v1/proofs/:id

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use crate::{AppState, types::ErrorResponse};

#[derive(Serialize)]
pub struct ProofListResponse {
    pub proof_ids: Vec<String>,
    pub count: usize,
}

pub async fn list_proofs(
    State(state): State<AppState>,
) -> Result<Json<ProofListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ids = state.store
        .list_ids()
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(format!("store error: {e}"))),
        ))?;
    let count = ids.len();
    Ok(Json(ProofListResponse { proof_ids: ids, count }))
}

pub async fn get_proof(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let bundle = state.store
        .get(&id)
        .map_err(|_| (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("proof '{id}' not found"))),
        ))?;
    Ok(Json(serde_json::to_value(&bundle).unwrap()))
}
