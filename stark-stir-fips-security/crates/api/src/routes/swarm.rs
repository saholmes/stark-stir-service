//! Swarm-prover device pool + (skeleton) distributed prove orchestrator.
//!
//! See `docs/swarm-prover.md` for the full architecture.  In short:
//!
//!   * **Coordinator** (this server) holds the device registry.
//!   * **IoT devices** run a slimmed-down `stark-server` that exposes
//!     `POST /v1/swarm/prove-shard`.  They register their IP:port +
//!     a per-device bearer with the coordinator.
//!   * On `POST /v1/swarm/prove`, the coordinator partitions records into
//!     shards small enough to fit each device's RAM, dispatches them via
//!     HTTP, collects the per-shard proofs + pi_hashes, and aggregates
//!     them into one outer rollup STARK (the existing `HashRollup` AIR
//!     from `crates/api/tests/dns_rollup.rs` and `cairo-bench`).
//!
//! Status: device registry + admin endpoints are fully wired and
//! covered by tests.  The HTTP-based dispatch step is documented and
//! has a stable shape but is currently a stub returning
//! `501 Not Implemented` until reqwest integration lands — see the
//! `dispatch_to_devices` function below for the exact next-step shape.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{routes::oauth, types::ErrorResponse, AppState};

// ─────────────────────────────────────────────────────────────────────────────
//  Device-registry endpoints (admin-session protected)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name:           String,
    /// `host:port` — e.g. `"192.168.1.42:3000"`.
    pub address:        String,
    /// Optional per-device bearer that the coordinator presents when
    /// dispatching shard work to this device.
    pub bearer_token:   Option<String>,
    /// Maximum log₂(trace) the device can handle (default 18 — fits 1 GB at blowup=32).
    pub max_trace_log2: Option<u32>,
    /// Declared RAM budget in MiB (default 1024).
    pub ram_mb:         Option<u32>,
    pub notes:          Option<String>,
}

pub async fn register_device(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<auth::SwarmDevice>), (StatusCode, Json<ErrorResponse>)> {
    let session = oauth::require_admin_session(&state, &headers)?;
    let device = state.auth_db.register_device(
        &req.name,
        &req.address,
        req.bearer_token.as_deref(),
        req.max_trace_log2.unwrap_or(18),
        req.ram_mb.unwrap_or(1024),
        Some(session.user_id),
        req.notes.as_deref(),
    ).map_err(|e| oauth::api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(device)))
}

pub async fn list_devices(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<auth::SwarmDevice>>, (StatusCode, Json<ErrorResponse>)> {
    let _ = oauth::require_admin_session(&state, &headers)?;
    let devices = state.auth_db.list_devices()
        .map_err(|e| oauth::api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(devices))
}

pub async fn remove_device(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let _ = oauth::require_admin_session(&state, &headers)?;
    state.auth_db.remove_device(id)
        .map_err(|e| oauth::api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Heartbeat (called by IoT devices, bearer-protected at router level)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    state.auth_db.touch_device_heartbeat(id)
        .map_err(|e| oauth::api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────────────
//  Distributed prove orchestrator (skeleton)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SwarmProveRequest {
    /// Total record count to prove (the orchestrator partitions them).
    pub total_records:  u64,
    /// Optional override for shard size.  If absent, computed per device's
    /// `max_trace_log2`.
    pub shard_records:  Option<u64>,
    /// NIST level + q-budget (same shape as /v1/prove config).
    pub nist_level:           u8,
    pub quantum_budget_log2:  u32,
    /// Optional fallback to local single-machine proof when the device
    /// pool is empty.
    #[serde(default)]
    pub fallback_local: bool,
}

#[derive(Debug, Serialize)]
pub struct SwarmProveResponse {
    pub status:           &'static str,
    pub shard_count:      usize,
    pub devices_used:     usize,
    pub records_per_shard: u64,
    pub estimated_walls:  EstimatedWalls,
    /// When the actual dispatch is implemented this field carries the
    /// outer-rollup proof_id and the per-shard proof_ids.  For now the
    /// skeleton returns the *plan* it would have executed.
    pub plan:             Vec<ShardAssignment>,
}

#[derive(Debug, Serialize)]
pub struct EstimatedWalls {
    pub sequential_secs: u64,
    pub parallel_secs:   u64,
}

#[derive(Debug, Serialize)]
pub struct ShardAssignment {
    pub shard_index:    usize,
    pub records_in_shard: u64,
    pub device_id:      i64,
    pub device_name:    String,
    pub device_address: String,
}

pub async fn swarm_prove(
    State(state): State<AppState>,
    Json(req): Json<SwarmProveRequest>,
) -> Result<Json<SwarmProveResponse>, (StatusCode, Json<ErrorResponse>)> {
    // ── 1. Discover available devices ─────────────────────────────────────
    let devices = state.auth_db.list_idle_devices()
        .map_err(|e| oauth::api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if devices.is_empty() {
        if req.fallback_local {
            return Err(oauth::api_err(
                StatusCode::NOT_IMPLEMENTED,
                "fallback_local=true: route the request through /v1/prove instead",
            ));
        }
        return Err(oauth::api_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no idle devices in swarm pool — register at least one or set fallback_local=true",
        ));
    }

    // ── 2. Decide shard size based on smallest device ─────────────────────
    let smallest_log2 = devices.iter().map(|d| d.max_trace_log2).min().unwrap_or(18);
    // n_trace ≤ 2^smallest_log2  →  records ≤ n_trace / 4   (HashRollup AIR: 4 leaves/record)
    let max_records_per_shard = (1u64 << smallest_log2) / 4;
    let records_per_shard = req.shard_records
        .unwrap_or(max_records_per_shard)
        .min(max_records_per_shard);

    // ── 3. Compute shard plan ─────────────────────────────────────────────
    let shard_count = ((req.total_records + records_per_shard - 1) / records_per_shard) as usize;
    let mut plan = Vec::with_capacity(shard_count);
    for i in 0..shard_count {
        let dev = &devices[i % devices.len()];
        let remaining_after = (i as u64 + 1) * records_per_shard;
        let shard_size = if remaining_after <= req.total_records {
            records_per_shard
        } else {
            req.total_records - (i as u64) * records_per_shard
        };
        plan.push(ShardAssignment {
            shard_index: i,
            records_in_shard: shard_size,
            device_id: dev.id,
            device_name: dev.name.clone(),
            device_address: dev.address.clone(),
        });
    }

    // ── 4. Estimate wall-clock (extrapolated from docs/scaling-analysis.md) ──
    // Linear: ~50 s per 65K records at NIST L1, blowup=32, on 1 GB device.
    let secs_per_shard = (records_per_shard as f64 / 65_536.0 * 50.0).max(1.0) as u64;
    let est = EstimatedWalls {
        sequential_secs: shard_count as u64 * secs_per_shard,
        parallel_secs:   secs_per_shard
            .saturating_add( (shard_count as u64).div_ceil(devices.len() as u64).saturating_mul(secs_per_shard) - secs_per_shard )
            .max(secs_per_shard),  // ≥ a single shard's time
    };

    // ── 5. Dispatch (stub — see `dispatch_to_devices` for next-step shape) ─
    //
    // Returning the plan lets clients see exactly what would happen.  The
    // actual HTTP-based dispatch is the next development step:
    //
    //   for shard in plan {
    //       let proof = dispatch_to_devices(&shard, ...).await?;
    //       proofs.push(proof);
    //   }
    //   let outer_rollup = aggregate_into_rollup(&proofs).await?;
    //   return Ok(Json(SwarmProveResponse { ..., outer_rollup }));
    //
    Ok(Json(SwarmProveResponse {
        status: "plan-only (dispatch not yet implemented)",
        shard_count,
        devices_used: shard_count.min(devices.len()),
        records_per_shard,
        estimated_walls: est,
        plan,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
//  HTTP dispatch helper (shape ready, body to be filled with reqwest)
// ─────────────────────────────────────────────────────────────────────────────
//
// When wiring up actual dispatch, this is the function to fill in:
//
//   async fn dispatch_to_devices(
//       shard:  &ShardAssignment,
//       state:  &AppState,
//   ) -> Result<ShardProofResult, DispatchError> {
//       let device = state.auth_db.find_device_by_id(shard.device_id)?;
//       let url = format!("http://{}/v1/swarm/prove-shard", device.address);
//       let client = reqwest::Client::builder()
//           .timeout(std::time::Duration::from_secs(600))
//           .build()?;
//       let req = client.post(&url)
//           .header("Authorization",
//                   format!("Bearer {}", device.bearer_token.unwrap_or_default()))
//           .json(&shard_records);
//       let resp = req.send().await?.error_for_status()?;
//       Ok(resp.json::<ShardProofResult>().await?)
//   }
//
// State transitions to coordinate:
//   1. set_device_status(id, Busy) before dispatch
//   2. set_device_status(id, Idle) after success / Offline after failure
//   3. on retry-able failures, cycle to next device in pool
