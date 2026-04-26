//! POST /v1/prove — Run the prover and store the resulting proof.

use std::time::Instant;

use ark_ff::{PrimeField, Zero};
use ark_goldilocks::Goldilocks as F;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};
use axum::{extract::State, http::StatusCode, Json};

use deep_ali::{
    air_workloads::{AirType, build_execution_trace},
    deep_ali_merge_general,
    fri::{deep_fri_prove, DeepFriParams, DeepFriProof, FriDomain},
    octic_ext::OcticExt,
    sextic_ext::SexticExt,
    tower_field::TowerField,
};
use proof_store::{JsonProofBundle, ProofMetadata, SerializedParams, SerializedProof};
use transcript::Transcript;

use crate::{
    AppState,
    convert::serialize_proof,
    security::{ExtensionField, NistLevel, ProfileError, QuantumBudget, SecurityProfile},
    types::{ErrorResponse, ProveOutputPaths, ProveRequest, ProveResponse},
};

// ─────────────────────────────────────────────────────────────────────────────
//  Handler
// ─────────────────────────────────────────────────────────────────────────────

pub async fn handle_prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, Json<ErrorResponse>)> {
    let t0 = Instant::now();

    // ── 1. Parse & validate configuration ──────────────────────────────────
    // Default blowup = 32 (paper Table III).  Smaller blowups are allowed but
    // require a *larger* r to maintain the same κ_IT — the SecurityProfile
    // recalculates r per blowup via the Johnson-regime formula
    //     bits/query = ½·log₂(blowup),
    //     r = ⌈ κ_IT / bits/query ⌉.
    // Larger blowups need fewer queries.  Either way the chosen profile's
    // claimed κ_IT is preserved.
    let blowup = req.config.blowup.unwrap_or(32);
    if !blowup.is_power_of_two() || blowup < 2 {
        return Err(api_err(StatusCode::BAD_REQUEST, "blowup must be a power-of-2 >= 2"));
    }

    // STIR is the default for new proofs (paper Table III recommendation:
    // k=8 fold, conjecture-free Johnson regime).  Set fri_mode="fri"
    // explicitly to opt back into binary-fold FRI.
    let use_stir = match req.config.fri_mode.as_deref() {
        Some("fri")  => false,
        Some("stir") => true,
        Some(other)  => return Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("unknown fri_mode '{other}' (expected 'fri' or 'stir')"),
        )),
        None         => true, // default → STIR
    };

    // ── 1a. Resolve security profile ───────────────────────────────────────
    let profile = resolve_profile(&req.config)?;

    // ── 2. Build raw trace columns ─────────────────────────────────────────
    let trace = &req.trace;
    let trace_len = trace.length;

    if !trace_len.is_power_of_two() || trace_len < 4 {
        return Err(api_err(StatusCode::BAD_REQUEST, "trace length must be a power-of-2 >= 4"));
    }

    let air_type = if let Some(label) = req.config.air_type.as_deref() {
        air_type_from_label(label)
            .ok_or_else(|| api_err(
                StatusCode::BAD_REQUEST,
                format!("unknown air_type '{label}' \
                    (expected fibonacci|cairo_simple|poseidon_chain|register_machine|hash_rollup)"),
            ))?
    } else {
        air_type_for_width(trace.width)
    };

    let raw_cols: Vec<Vec<u64>> = if trace.columns.is_empty() {
        let raw = build_execution_trace(air_type, trace_len);
        raw.iter()
            .map(|col| col.iter().map(|f| f.into_bigint().0[0]).collect())
            .collect()
    } else {
        let mut sorted_names: Vec<&String> = trace.columns.keys().collect();
        sorted_names.sort();
        sorted_names.iter()
            .map(|name| {
                let col = trace.columns.get(*name).unwrap();
                if col.len() != trace_len {
                    return Err(format!("column '{}' length {} != trace_len {}", name, col.len(), trace_len));
                }
                Ok(col.clone())
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?
    };

    // ── 3. Validate boundary constraints against public inputs ──────────────
    req.public_inputs
        .validate_trace_boundaries(&raw_cols)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, format!("boundary constraint violation: {e}")))?;

    // ── 4. Convert to Goldilocks field elements ────────────────────────────
    let f_cols: Vec<Vec<F>> = raw_cols.iter()
        .map(|col| col.iter().map(|&v| F::from(v)).collect())
        .collect();

    // ── 5. LDE: interpolate + evaluate on extended domain ─────────────────
    let n0 = trace_len * blowup;
    let trace_dom = Domain::<F>::new(trace_len).unwrap();
    let lde_dom = Domain::<F>::new(n0).unwrap();

    let lde_cols: Vec<Vec<F>> = f_cols.iter()
        .map(|col| {
            let coeffs = trace_dom.ifft(col);
            let mut padded = coeffs;
            padded.resize(n0, F::zero());
            lde_dom.fft(&padded)
        })
        .collect();

    // ── 6. Derive combination coefficients from public inputs hash ─────────
    let pi_hash = req.public_inputs.to_commitment_bytes();
    let combination_coeffs = derive_combination_coeffs(&pi_hash, air_type.num_constraints());

    // ── 7. DEEP-ALI merge ─────────────────────────────────────────────────
    let domain0 = FriDomain::new_radix2(n0);
    let (composition, _info) = deep_ali_merge_general(
        &lde_cols,
        &combination_coeffs,
        air_type,
        domain0.omega,
        trace_len,
        blowup,
    );

    // ── 8. FRI prove (dispatch on extension field) ─────────────────────────
    let schedule = default_schedule(n0, use_stir);
    let r = profile.r_for_blowup(blowup)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let params = DeepFriParams {
        schedule: schedule.clone(),
        r,
        seed_z: 42,
        coeff_commit_final: true,
        d_final: 1,
        stir: use_stir,
        s0: r,
        public_inputs_hash: Some(pi_hash),
    };

    let serialized = match profile.ext_field {
        ExtensionField::Fp6 => {
            let proof: DeepFriProof<SexticExt> =
                deep_fri_prove(composition, domain0, &params);
            serialize_proof(&proof)
        }
        ExtensionField::Fp8 => {
            let proof: DeepFriProof<OcticExt> =
                deep_fri_prove(composition, domain0, &params);
            serialize_proof(&proof)
        }
    };

    let prove_time_ms = t0.elapsed().as_millis() as u64;

    // ── 9. Bundle ──────────────────────────────────────────────────────────
    let proof_json_bytes = serde_json::to_vec(&serialized).unwrap();
    let proof_size_bytes = proof_json_bytes.len();

    let pi_json = serde_json::to_value(&req.public_inputs).unwrap();

    let security_level_bits = req.config.security_level.unwrap_or(profile.lambda_bits);

    let sp = SerializedParams {
        schedule,
        r,
        seed_z: 42,
        coeff_commit_final: true,
        d_final: 1,
        stir: use_stir,
        s0: r,
        n0,
        blowup,
        air_type: air_type.label().into(),
        security_level: security_level_bits,
        public_inputs_hash: hex::encode(pi_hash),
        nist_level: Some(profile.level.as_u8()),
        quantum_budget_log2: Some(profile.quantum_budget.log2()),
        ext_degree: ext_degree(profile.ext_field),
        hash_alg: profile.hash_alg.label().into(),
    };

    let meta = ProofMetadata {
        prove_time_ms,
        proof_size_bytes,
        trace_width: air_type.width(),
        trace_length: trace_len,
    };

    let bundle = JsonProofBundle::new(pi_json, serialized, sp, meta);

    // ── 10. Store proof ───────────────────────────────────────────────────
    let format = req.config.output_format.as_deref().unwrap_or("bundle");
    let output_path = req.config.output_path.as_deref();

    let (proof_id, output_paths) = match format {
        "ethstark-split" => {
            let stem = output_path.ok_or_else(|| api_err(
                StatusCode::BAD_REQUEST,
                "ethstark-split format requires output_path (used as the file stem)",
            ))?;
            let id = bundle.proof_id.clone();
            let paths = state.store
                .save_split(bundle.clone(), stem)
                .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("store error: {e}")))?;
            (id, ProveOutputPaths {
                params: Some(paths.params.to_string_lossy().into()),
                public_input: Some(paths.public_input.to_string_lossy().into()),
                proof: Some(paths.proof.to_string_lossy().into()),
                ..Default::default()
            })
        }
        "bundle" | "" => {
            if let Some(path) = output_path {
                let id = bundle.proof_id.clone();
                let written = state.store
                    .save_to_path(bundle.clone(), path)
                    .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("store error: {e}")))?;
                (id, ProveOutputPaths {
                    bundle: Some(written.to_string_lossy().into()),
                    ..Default::default()
                })
            } else {
                let id = state.store
                    .save(bundle.clone())
                    .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, format!("store error: {e}")))?;
                let p = state.store_path_for(&id);
                (id, ProveOutputPaths {
                    bundle: Some(p.to_string_lossy().into()),
                    ..Default::default()
                })
            }
        }
        other => return Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("unknown output_format '{other}' (expected 'bundle' or 'ethstark-split')"),
        )),
    };

    let bundle_json = serde_json::to_value(&bundle).unwrap();

    Ok(Json(ProveResponse {
        proof_id,
        prove_time_ms,
        proof_size_bytes,
        bundle: bundle_json,
        output_paths,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert SerializedProof's stored copy back to bytes is unused at prove time;
/// the helper exists in convert.rs.  We avoid producing one here.
#[allow(dead_code)]
fn _use_serialized_proof(_p: &SerializedProof) {}

/// Resolve a SecurityProfile from the request.  Falls back to a Level-1 q=2^40
/// profile if no NIST inputs are provided (preserves backward compatibility).
fn resolve_profile(
    cfg: &crate::types::ProverConfigInput,
) -> Result<SecurityProfile, (StatusCode, Json<ErrorResponse>)> {
    // If neither nist_level nor quantum_budget_log2 is set, use a default
    // matching the binary's compiled hash.
    if cfg.nist_level.is_none() && cfg.quantum_budget_log2.is_none() {
        return Ok(default_profile_for_build());
    }

    let level_u8 = cfg.nist_level.ok_or_else(|| api_err(
        StatusCode::BAD_REQUEST,
        "nist_level required when quantum_budget_log2 is set",
    ))?;
    let q_log2 = cfg.quantum_budget_log2.ok_or_else(|| api_err(
        StatusCode::BAD_REQUEST,
        "quantum_budget_log2 required when nist_level is set",
    ))?;

    let level = NistLevel::from_u8(level_u8).ok_or_else(|| api_err(
        StatusCode::BAD_REQUEST,
        format!("nist_level must be 1, 3, or 5 (got {level_u8})"),
    ))?;
    let q = QuantumBudget::from_log2(q_log2).ok_or_else(|| api_err(
        StatusCode::BAD_REQUEST,
        format!("quantum_budget_log2 must be 40, 65, or 90 (got {q_log2})"),
    ))?;

    let profile = SecurityProfile::lookup(level, q, cfg.allow_binding_wall_violation)
        .map_err(|e| match e {
            ProfileError::BindingWallViolated => api_err(StatusCode::FORBIDDEN, e.to_string()),
            _ => api_err(StatusCode::BAD_REQUEST, e.to_string()),
        })?;

    profile.check_hash_compatibility()
        .map_err(|e| api_err(StatusCode::PRECONDITION_FAILED, e.to_string()))?;

    Ok(profile)
}

/// When the request omits nist_level/q, pick a default profile matching the build.
fn default_profile_for_build() -> SecurityProfile {
    use crate::security::HashAlg::*;
    match SecurityProfile::build_hash() {
        Sha3_256 => SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q40, false).unwrap(),
        Sha3_384 => SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q65, false).unwrap(),
        Sha3_512 => SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q90, false).unwrap(),
    }
}

fn ext_degree(e: ExtensionField) -> usize {
    match e {
        ExtensionField::Fp6 => SexticExt::DEGREE,
        ExtensionField::Fp8 => OcticExt::DEGREE,
    }
}

fn air_type_for_width(width: usize) -> AirType {
    match width {
        2  => AirType::Fibonacci,
        4  => AirType::HashRollup,
        8  => AirType::CairoSimple,
        16 => AirType::PoseidonChain,
        _  => AirType::RegisterMachine,
    }
}

fn air_type_from_label(label: &str) -> Option<AirType> {
    match label {
        "fibonacci"        => Some(AirType::Fibonacci),
        "cairo_simple"     => Some(AirType::CairoSimple),
        "poseidon_chain"   => Some(AirType::PoseidonChain),
        "register_machine" => Some(AirType::RegisterMachine),
        "hash_rollup"      => Some(AirType::HashRollup),
        _                  => None,
    }
}

/// Derive random linear combination coefficients from the public inputs hash.
/// Uses the build-time hash via Transcript and the Fiat-Shamir transcript to produce field elements.
fn derive_combination_coeffs(pi_hash: &[u8; 32], num_constraints: usize) -> Vec<F> {
    let mut tr = Transcript::new_matching_hash(b"DEEP-ALI-COMBINATION");
    tr.absorb_bytes(pi_hash);
    (0..num_constraints)
        .map(|i| tr.challenge(format!("coeff_{i}").as_bytes()))
        .collect()
}

/// Default folding schedule, conditional on STIR mode.
///
/// * **STIR enabled (`use_stir = true`)** → arity-8 fold per the paper's
///   Table III recommendation (`k = 8`, conjecture-free in the Johnson
///   regime).  log₂(n0) need not be a multiple of 3; any residual bits
///   are absorbed in a single smaller terminal fold (e.g. `n0 = 1024`
///   → `[8, 8, 8, 2]`).
///
/// * **Plain FRI (`use_stir = false`)** → arity-2 (binary) fold.  This
///   is the *only* arity with a proven proximity-gap soundness theorem
///   for FRI; higher arities require the conjectural Ben-Sasson/Carmon
///   higher-arity correlated-agreement extension which we explicitly
///   avoid for FIPS-140-3 compliance.
///
/// Both schedules fold all the way to a final domain of size 1, which
/// is required by `d_final = 1` + `coeff_commit_final = true`.
fn default_schedule(n0: usize, use_stir: bool) -> Vec<usize> {
    assert!(n0.is_power_of_two(), "n0 must be a power of 2");
    let log_n0 = n0.trailing_zeros() as usize;

    if !use_stir {
        // FRI mode: arity-2 binary fold (the only proven-secure FRI arity).
        return vec![2usize; log_n0];
    }

    // STIR mode: arity-8 fold + residual to land at size 1.
    let log_arity = 3usize;             // log2(8)
    let full_folds = log_n0 / log_arity;
    let remainder_log = log_n0 % log_arity;

    let mut schedule = vec![8usize; full_folds];
    if remainder_log > 0 {
        schedule.push(1usize << remainder_log);
    }
    schedule
}

fn api_err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (code, Json(ErrorResponse::new(msg.into())))
}
