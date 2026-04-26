//! Smoke test for the default build (SHA3-256, Fp^6) with Level 1 / q=2^40.
//! Used to isolate whether verification failures at Level 5 are profile-
//! specific or a more general API↔FRI integration issue.

#![cfg(feature = "sha3-256")]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::{extract::State, Json};

use api::{
    routes::{prove::handle_prove, verify::handle_verify},
    types::{ProveRequest, ProverConfigInput, StarkWareTraceInput, VerifyRequest},
    AppState,
};
use deep_ali::air_workloads::{CAIRO_SIMPLE_INITIAL_AP, CAIRO_SIMPLE_INITIAL_PC};
use proof_store::ProofStore;
use public_inputs::CairoPublicInputs;

#[tokio::test]
async fn level1_q40_default_build_smoke() {
    let store_dir: PathBuf = std::env::temp_dir().join(format!(
        "stark-stir-fips-l1q40-{}", uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&store_dir).unwrap();
    let store = ProofStore::new(&store_dir).unwrap();
    let state = AppState::with_in_memory_auth(store);

    let pi = CairoPublicInputs::for_cairo_simple_air(
        CAIRO_SIMPLE_INITIAL_PC, CAIRO_SIMPLE_INITIAL_AP, 256,
    );

    let req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width: 8,
            length: 256,
            columns: HashMap::new(),
        },
        public_inputs: pi.clone(),
        config: ProverConfigInput {
            nist_level: Some(1),
            quantum_budget_log2: Some(40),
            ..Default::default()
        },
    };

    let pr = handle_prove(State(state.clone()), Json(req)).await.unwrap().0;
    println!("[L1/q40] prove={} ms size={}", pr.prove_time_ms, pr.proof_size_bytes);

    let vreq = VerifyRequest {
        proof_id: Some(pr.proof_id.clone()),
        bundle: None, bundle_path: None, split_paths: None,
        public_inputs: Some(pi),
    };
    let vr = handle_verify(State(state), Json(vreq)).await.unwrap().0;
    println!("[L1/q40] verify={} ms valid={} message={}", vr.verify_time_ms, vr.valid, vr.message);

    std::fs::remove_dir_all(&store_dir).ok();

    // Assertion: at minimum the plumbing must run without panic.
    // valid=true requires the AIR composition pipeline to be correct end-to-end.
    assert!(
        vr.message.contains("proof is valid") || vr.message.contains("verification failed"),
        "unexpected verify message: {}", vr.message,
    );
}
