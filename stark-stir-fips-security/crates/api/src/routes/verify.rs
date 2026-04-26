//! POST /v1/verify — Verify a stored or inline STARK proof.

use std::time::Instant;

use axum::{extract::State, http::StatusCode, Json};

use deep_ali::{
    fri::{deep_fri_verify, DeepFriParams},
    octic_ext::OcticExt,
    sextic_ext::SexticExt,
};
use proof_store::{JsonProofBundle, ProofStore};
use public_inputs::CairoPublicInputs;

use crate::{
    AppState,
    convert::deserialize_proof,
    types::{ErrorResponse, VerifyRequest, VerifyResponse},
};

pub async fn handle_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let t0 = Instant::now();

    // ── 1. Load the proof bundle from one of four sources ──────────────────
    let bundle = load_bundle(&state, &req)?;
    let proof_id = Some(bundle.proof_id.clone());

    // ── 2. Resolve & validate public inputs ────────────────────────────────
    let public_inputs = resolve_public_inputs(&req, &bundle)?;

    // ── 3. Verify public inputs match the stored commitment ────────────────
    let expected_pi_hash = &bundle.params.public_inputs_hash;
    let provided_pi_hash = hex::encode(public_inputs.to_commitment_bytes());
    if expected_pi_hash != &provided_pi_hash {
        return Ok(Json(VerifyResponse {
            valid: false,
            proof_id,
            verify_time_ms: t0.elapsed().as_millis() as u64,
            message: "public inputs mismatch: commitment hash does not match stored proof".into(),
        }));
    }

    // ── 4. Hash-feature compatibility check ────────────────────────────────
    let build_hash = crate::security::SecurityProfile::build_hash().label();
    if !bundle.params.hash_alg.is_empty() && bundle.params.hash_alg != build_hash {
        return Ok(Json(VerifyResponse {
            valid: false,
            proof_id,
            verify_time_ms: t0.elapsed().as_millis() as u64,
            message: format!(
                "hash mismatch: proof was generated with {} but verifier is built with {}. \
                 Rebuild the verifier with the matching --features.",
                bundle.params.hash_alg, build_hash,
            ),
        }));
    }

    // ── 5. Reconstruct params from stored metadata ─────────────────────────
    let pi_hash = public_inputs.to_commitment_bytes();
    let params = DeepFriParams {
        schedule: bundle.params.schedule.clone(),
        r: bundle.params.r,
        seed_z: bundle.params.seed_z,
        coeff_commit_final: bundle.params.coeff_commit_final,
        d_final: bundle.params.d_final,
        stir: bundle.params.stir,
        s0: bundle.params.s0,
        public_inputs_hash: Some(pi_hash),
    };

    // ── 6. Deserialize and run FRI verification (dispatch on ext_degree) ───
    let valid = match bundle.params.ext_degree {
        6 => verify_with::<SexticExt>(&bundle, &params),
        8 => verify_with::<OcticExt>(&bundle, &params),
        d => {
            return Ok(Json(VerifyResponse {
                valid: false,
                proof_id,
                verify_time_ms: t0.elapsed().as_millis() as u64,
                message: format!("unsupported extension-field degree: {d} (expected 6 or 8)"),
            }));
        }
    };

    let verify_time_ms = t0.elapsed().as_millis() as u64;

    let (valid_bool, message) = match valid {
        Ok(true)  => (true,  "proof is valid".to_string()),
        Ok(false) => (false, "proof verification failed".to_string()),
        Err(e)    => (false, format!("proof deserialization failed: {e}")),
    };

    Ok(Json(VerifyResponse {
        valid: valid_bool,
        proof_id,
        verify_time_ms,
        message,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Bundle loading: 4 sources, exactly one required
// ─────────────────────────────────────────────────────────────────────────────

fn load_bundle(
    state: &AppState,
    req: &VerifyRequest,
) -> Result<JsonProofBundle, (StatusCode, Json<ErrorResponse>)> {
    let sources = [
        req.proof_id.is_some(),
        req.bundle.is_some(),
        req.bundle_path.is_some(),
        req.split_paths.is_some(),
    ];
    let count = sources.iter().filter(|&&x| x).count();
    if count == 0 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "provide one of: proof_id, bundle, bundle_path, split_paths",
        ));
    }
    if count > 1 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "provide exactly one of: proof_id, bundle, bundle_path, split_paths",
        ));
    }

    if let Some(id) = &req.proof_id {
        return state.store
            .get(id)
            .map_err(|e| api_err(StatusCode::NOT_FOUND, format!("proof not found: {e}")));
    }
    if let Some(val) = &req.bundle {
        return serde_json::from_value(val.clone())
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, format!("invalid bundle JSON: {e}")));
    }
    if let Some(path) = &req.bundle_path {
        return ProofStore::load_from_file(path)
            .map_err(|e| api_err(StatusCode::NOT_FOUND, format!("cannot read {path}: {e}")));
    }
    if let Some(sp) = &req.split_paths {
        return ProofStore::load_from_split(&sp.params, &sp.public_input, &sp.proof)
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, format!("split-file load failed: {e}")));
    }
    unreachable!("count == 1 enforced above");
}

/// Use inline `public_inputs` if provided; otherwise fall back to the bundle's
/// embedded `public_inputs`.  When both are present, they must agree.
fn resolve_public_inputs(
    req: &VerifyRequest,
    bundle: &JsonProofBundle,
) -> Result<CairoPublicInputs, (StatusCode, Json<ErrorResponse>)> {
    let from_bundle: Result<CairoPublicInputs, _> =
        serde_json::from_value(bundle.public_inputs.clone());

    match (&req.public_inputs, from_bundle) {
        (Some(inline), Ok(embedded)) => {
            // Both present: enforce agreement via SHA3-256 commitment.
            if inline.to_commitment_bytes() != embedded.to_commitment_bytes() {
                Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "inline public_inputs do not match the public_inputs embedded in the bundle",
                ))
            } else {
                Ok(inline.clone())
            }
        }
        (Some(inline), Err(_)) => Ok(inline.clone()),
        (None, Ok(embedded)) => Ok(embedded),
        (None, Err(e)) => Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("no public_inputs provided and bundle has none: {e}"),
        )),
    }
}

/// Generic verify helper: deserialize the proof in the requested extension
/// field and run `deep_fri_verify`.
fn verify_with<E: deep_ali::tower_field::TowerField>(
    bundle: &JsonProofBundle,
    params: &DeepFriParams,
) -> Result<bool, String> {
    let proof = deserialize_proof::<E>(&bundle.proof)?;
    Ok(deep_fri_verify::<E>(params, &proof))
}

fn api_err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (code, Json(ErrorResponse::new(msg.into())))
}
