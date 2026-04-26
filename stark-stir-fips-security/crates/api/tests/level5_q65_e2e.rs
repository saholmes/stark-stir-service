//! End-to-end integration test exercising the prove/verify pipeline at
//! NIST PQ Level 5 with quantum budget q = 2^65.
//!
//! Profile from Table III of the STIR-FIPS paper:
//!   Level 5 (λ=256), q=2^65 → Fp^8 extension, SHA3-512 hash, r = 105
//!
//! Required build features: this test only runs under the `sha3-512` feature
//! because Level 5 needs SHA3-512 for the FIPS-202 binding wall.
//!
//! Run with:
//!   cargo test -p api --no-default-features --features sha3-512 --test level5_q65_e2e -- --nocapture
//!
//! The test:
//!   1. Builds CairoSimple AIR public inputs (n_trace=256, initial_pc=0, initial_ap=100).
//!   2. Submits a prove request with output_format="ethstark-split", output_path="sampleoutput".
//!   3. Verifies all three split files were written.
//!   4. Reads the params file and confirms NIST profile metadata matches Level 5 / q=2^65.
//!   5. Submits a verify request using the split_paths and asserts validity.
//!   6. Confirms tampering with the public_input file flips validation to false.

#![cfg(feature = "sha3-512")]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::{extract::State, Json};

use api::{
    routes::{prove::handle_prove, verify::handle_verify},
    types::{
        ProveRequest, ProverConfigInput, StarkWareTraceInput,
        VerifyRequest, VerifySplitPaths,
    },
    AppState,
};
use deep_ali::air_workloads::{CAIRO_SIMPLE_INITIAL_AP, CAIRO_SIMPLE_INITIAL_PC};
use proof_store::{ProofStore, SplitParamsFile, SplitPublicInputFile};
use public_inputs::CairoPublicInputs;

const N_TRACE: usize = 256;
const TRACE_WIDTH: usize = 8; // CairoSimple

fn temp_dir(label: &str) -> PathBuf {
    // If STARK_KEEP_OUTPUT is set, use a stable predictable path so artifacts
    // can be inspected after the test.  Otherwise use a random subdir.
    let dir = if std::env::var("STARK_KEEP_OUTPUT").ok().as_deref() == Some("1") {
        std::env::temp_dir().join(format!("stark-stir-fips-demo-{label}"))
    } else {
        std::env::temp_dir().join(format!("stark-stir-fips-{label}-{}", uuid::Uuid::new_v4()))
    };
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn level5_q65_prove_and_verify_split_format() {
    // ── Setup: store + app state ───────────────────────────────────────────
    let store_dir = temp_dir("store");
    let out_dir = temp_dir("out");
    let store = ProofStore::new(&store_dir).unwrap();
    let state = AppState::with_in_memory_auth(store);

    // ── Public inputs for CairoSimple AIR ──────────────────────────────────
    let pi = CairoPublicInputs::for_cairo_simple_air(
        CAIRO_SIMPLE_INITIAL_PC,
        CAIRO_SIMPLE_INITIAL_AP,
        N_TRACE,
    );

    // ── Prove request: synthetic trace (empty columns), Level 5 / q=2^65,
    //     ethstark-split output to "<out_dir>/sampleoutput" ────────────────
    let stem = out_dir.join("sampleoutput");
    let stem_str = stem.to_string_lossy().to_string();

    let req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width: TRACE_WIDTH,
            length: N_TRACE,
            columns: HashMap::new(), // empty → server builds synthetic CairoSimple trace
        },
        public_inputs: pi.clone(),
        config: ProverConfigInput {
            nist_level: Some(5),
            quantum_budget_log2: Some(65),
            allow_binding_wall_violation: false,
            output_format: Some("ethstark-split".into()),
            output_path: Some(stem_str.clone()),
            ..Default::default()
        },
    };

    let prove_resp = handle_prove(State(state.clone()), Json(req))
        .await
        .expect("prove failed");
    let pr = prove_resp.0;

    println!(
        "[Level 5 / q=2^65] prove_time_ms = {}, proof_size_bytes = {}, proof_id = {}",
        pr.prove_time_ms, pr.proof_size_bytes, pr.proof_id
    );

    // ── Check the three split files were written ──────────────────────────
    let params_path = pr.output_paths.params.expect("params path missing");
    let public_path = pr.output_paths.public_input.expect("public_input path missing");
    let proof_path  = pr.output_paths.proof.expect("proof path missing");

    assert!(PathBuf::from(&params_path).exists(),  "params file missing: {params_path}");
    assert!(PathBuf::from(&public_path).exists(),  "public_input file missing: {public_path}");
    assert!(PathBuf::from(&proof_path).exists(),   "proof file missing: {proof_path}");

    assert!(params_path.ends_with("sampleoutput.params.json"));
    assert!(public_path.ends_with("sampleoutput.public_input.json"));
    assert!(proof_path.ends_with("sampleoutput.proof.json"));

    // ── Verify the params file encodes the right NIST profile ─────────────
    let params_json = std::fs::read_to_string(&params_path).unwrap();
    let params_file: SplitParamsFile = serde_json::from_str(&params_json).unwrap();

    assert_eq!(params_file.params.nist_level,         Some(5));
    assert_eq!(params_file.params.quantum_budget_log2, Some(65));
    assert_eq!(params_file.params.ext_degree,          8);
    assert_eq!(params_file.params.hash_alg,            "SHA3-512");
    assert_eq!(params_file.params.r,                   105);
    assert_eq!(params_file.params.security_level,      256);
    assert_eq!(params_file.params.air_type,            "cairo_simple_w8_d2");

    // ── Verify the public_input file echoes the embedded inputs ───────────
    let pi_json = std::fs::read_to_string(&public_path).unwrap();
    let pi_file: SplitPublicInputFile = serde_json::from_str(&pi_json).unwrap();
    assert_eq!(pi_file.public_inputs_hash, hex::encode(pi.to_commitment_bytes()));

    // ── Verify request: load from split_paths, check valid = true ─────────
    let verify_req = VerifyRequest {
        proof_id:     None,
        bundle:       None,
        bundle_path:  None,
        split_paths:  Some(VerifySplitPaths {
            params:       params_path.clone(),
            public_input: public_path.clone(),
            proof:        proof_path.clone(),
        }),
        public_inputs: Some(pi.clone()),
    };

    let verify_resp = handle_verify(State(state.clone()), Json(verify_req))
        .await
        .expect("verify failed");
    let vr = verify_resp.0;

    println!(
        "[Level 5 / q=2^65] verify_time_ms = {}, valid = {}, message = {}",
        vr.verify_time_ms, vr.valid, vr.message
    );
    assert!(vr.valid, "verification failed: {}", vr.message);

    // ── Tamper test: modify the public_input file, re-verify, expect false ─
    let tamper_path = out_dir.join("tampered.public_input.json");
    let pi_tampered = pi_file.clone();
    let mut pi_tampered_json: serde_json::Value =
        serde_json::to_value(&pi_tampered).unwrap();
    // Bump initial_ap so the SHA3-256 commitment changes
    pi_tampered_json["public_inputs"]["initial_ap"] = serde_json::json!(999u64);
    std::fs::write(&tamper_path, serde_json::to_string_pretty(&pi_tampered_json).unwrap()).unwrap();

    let tamper_req = VerifyRequest {
        proof_id:    None,
        bundle:      None,
        bundle_path: None,
        split_paths: Some(VerifySplitPaths {
            params:       params_path.clone(),
            public_input: tamper_path.to_string_lossy().into(),
            proof:        proof_path.clone(),
        }),
        public_inputs: None,
    };
    // The split-file integrity check rejects mismatched public_inputs_hash
    // before any FRI work; this should return an error response, not a panic.
    let tamper_resp = handle_verify(State(state.clone()), Json(tamper_req)).await;
    match tamper_resp {
        Ok(Json(vr)) => assert!(!vr.valid, "tampered proof unexpectedly verified"),
        Err((_status, Json(_err))) => { /* error response is acceptable */ }
    }

    // ── Cleanup ────────────────────────────────────────────────────────────
    // Honour STARK_KEEP_OUTPUT=1 so a developer can inspect artifacts.
    if std::env::var("STARK_KEEP_OUTPUT").ok().as_deref() != Some("1") {
        std::fs::remove_dir_all(&out_dir).ok();
        std::fs::remove_dir_all(&store_dir).ok();
    } else {
        eprintln!("\n[STARK_KEEP_OUTPUT=1] artifacts retained at: {}\n", out_dir.display());
    }
}
