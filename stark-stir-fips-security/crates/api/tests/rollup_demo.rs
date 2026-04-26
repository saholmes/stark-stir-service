//! Recursion / rollup demonstration.
//!
//! Architecture:
//!
//!   ┌─────────────────────────┐     ┌─────────────────────────┐
//!   │  Inner STARK A          │     │  Inner STARK B          │
//!   │  AIR = CairoSimple      │     │  AIR = CairoSimple      │
//!   │  initial_pc =    0      │     │  initial_pc = 1000      │
//!   │  initial_ap =  100      │     │  initial_ap = 2000      │
//!   │  → pi_hash_A (32 bytes) │     │  → pi_hash_B (32 bytes) │
//!   └────────────┬────────────┘     └────────────┬────────────┘
//!                │                                │
//!                ▼                                ▼
//!     pack_hash_to_leaves            pack_hash_to_leaves
//!                │                                │
//!                └─────────────┬──────────────────┘
//!                              ▼
//!                    leaves = [hA0,hA1,hA2,hA3, hB0,hB1,hB2,hB3, 0,0,…]
//!                              │
//!                              ▼
//!   ┌─────────────────────────────────────────────────────────┐
//!   │  Rollup STARK                                           │
//!   │  AIR = HashRollup (w=4, 3 constraints, deg=2)           │
//!   │  state' = state² + leaf  (running streaming hash)       │
//!   │  → rolled-up commitment = state[n_trace]                │
//!   │  → pi_hash_R commits to (pi_hash_A, pi_hash_B, rolled-up)│
//!   └─────────────────────────────────────────────────────────┘
//!
//! Verification:
//!   1. Verify rollup STARK   → confirms aggregation arithmetic
//!   2. Verify inner STARK A  → confirms pi_hash_A came from a real proof
//!   3. (optional) Verify B
//!
//! This is the "soft rollup" pattern used as a stepping stone toward true
//! recursive STARK verification.  Full recursion would replace step 1's
//! aggregation AIR with an inner-FRI-verifier AIR.
//!
//! Run with:
//!   cargo test --release -p api --test rollup_demo -- --nocapture

#![cfg(feature = "sha3-256")]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::{extract::State, Json};

use api::{
    routes::{prove::handle_prove, verify::handle_verify},
    types::{ProveRequest, ProverConfigInput, StarkWareTraceInput, VerifyRequest},
    AppState,
};
use ark_ff::PrimeField;
use ark_goldilocks::Goldilocks as F;
use deep_ali::air_workloads::{
    build_hash_rollup_trace, compute_hash_rollup_final_state, pack_hash_to_leaves,
    CAIRO_SIMPLE_INITIAL_AP, CAIRO_SIMPLE_INITIAL_PC,
};
use proof_store::ProofStore;
use public_inputs::{CairoPublicInputs, MemoryEntry, MemorySegment};

const N_INNER_A: usize =  64;  // inner trace length A
const N_INNER_B: usize = 128;  // inner trace length B (different → different pi_hash)
const N_ROLLUP:  usize =  16;  // rollup trace length (must hold 8 leaves + padding)

fn temp_store() -> (PathBuf, ProofStore) {
    let dir = std::env::temp_dir().join(format!(
        "stark-stir-fips-rollup-{}", uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let store = ProofStore::new(&dir).unwrap();
    (dir, store)
}

/// Run a CairoSimple inner proof of given trace length and return its
/// `public_inputs_hash` as raw bytes plus the proof_id.  Uses the
/// synthetic CairoSimple trace builder (initial_pc=0, initial_ap=100);
/// the trace length differs between inner A and inner B to give them
/// distinct public inputs (and therefore distinct commitments).
async fn prove_inner(state: AppState, n_trace: usize) -> ([u8; 32], String) {
    let pi = CairoPublicInputs::for_cairo_simple_air(
        CAIRO_SIMPLE_INITIAL_PC,
        CAIRO_SIMPLE_INITIAL_AP,
        n_trace,
    );

    let req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width: 8,
            length: n_trace,
            columns: HashMap::new(),
        },
        public_inputs: pi.clone(),
        config: ProverConfigInput {
            nist_level: Some(1),
            quantum_budget_log2: Some(40),
            ..Default::default()
        },
    };

    let pr = handle_prove(State(state), Json(req)).await
        .expect("inner prove failed").0;
    println!(
        "  inner   prove={} ms size={} id={}",
        pr.prove_time_ms, pr.proof_size_bytes, pr.proof_id
    );
    (pi.to_commitment_bytes(), pr.proof_id)
}

async fn verify_by_id(state: AppState, proof_id: &str, pi: &CairoPublicInputs) -> bool {
    let req = VerifyRequest {
        proof_id:    Some(proof_id.into()),
        bundle:      None, bundle_path: None, split_paths: None,
        public_inputs: Some(pi.clone()),
    };
    let vr = handle_verify(State(state), Json(req)).await.unwrap().0;
    println!(
        "  verify  valid={} time={} ms message={}",
        vr.valid, vr.verify_time_ms, vr.message
    );
    vr.valid
}

#[tokio::test]
async fn rollup_two_inner_starks_into_one_outer_proof() {
    let (store_dir, store) = temp_store();
    let state = AppState::with_in_memory_auth(store);

    // ── 1. Two inner STARKs (each a CairoSimple AIR) ───────────────────────
    println!("\n[STEP 1] Generate inner STARK A (CairoSimple, n_trace={N_INNER_A})");
    let (pi_hash_a, id_a) = prove_inner(state.clone(), N_INNER_A).await;
    println!("  pi_hash_A = {}", hex::encode(pi_hash_a));

    println!("\n[STEP 2] Generate inner STARK B (CairoSimple, n_trace={N_INNER_B})");
    let (pi_hash_b, id_b) = prove_inner(state.clone(), N_INNER_B).await;
    println!("  pi_hash_B = {}", hex::encode(pi_hash_b));
    assert_ne!(pi_hash_a, pi_hash_b, "inner proof commitments must differ");

    // ── 3. Build rollup leaves: pack 32-byte commitments into 4×u64 each ───
    let leaves_a = pack_hash_to_leaves(&pi_hash_a);
    let leaves_b = pack_hash_to_leaves(&pi_hash_b);
    let mut leaves: Vec<u64> = Vec::with_capacity(N_ROLLUP);
    leaves.extend_from_slice(&leaves_a);
    leaves.extend_from_slice(&leaves_b);
    while leaves.len() < N_ROLLUP { leaves.push(0); }

    let rolled_up = compute_hash_rollup_final_state(N_ROLLUP, &leaves);
    println!("\n[STEP 3] Rollup leaves prepared. Expected aggregate = 0x{:016x}", rolled_up);

    // ── 4. Build rollup public inputs.
    //    We re-use CairoPublicInputs (the existing type the API understands)
    //    by encoding rollup metadata into its fields:
    //      initial_pc/initial_ap/initial_fp → boundary of HashRollup AIR
    //      public_memory                      → carries the inner pi_hashes + rolled-up
    //      memory_segments                    → empty (unused by this AIR)
    //      program_hash                       → tag identifying this as a rollup PI
    let last_idx = (N_ROLLUP - 1) as u64;
    let rollup_pi = CairoPublicInputs {
        program_hash: "0x726f6c6c75702d76310000000000000000000000000000000000000000000001".into(),
        initial_pc:   0,                     // idx[0]
        initial_ap:   leaves[0],             // leaf[0]
        initial_fp:   0,                     // state[0] = 0
        final_pc:     last_idx,              // idx[n-1]
        final_ap:     leaves[N_ROLLUP - 1],  // leaf[n-1]
        memory_segments: vec![
            MemorySegment { start: 0, stop: N_ROLLUP as u64 },
        ],
        // Carry the inner commitments + rolled-up value as public memory.
        // This makes them auditable from the rollup proof bundle.
        public_memory: vec![
            MemoryEntry { address: 0xA000, value: leaves_a[0] },
            MemoryEntry { address: 0xA001, value: leaves_a[1] },
            MemoryEntry { address: 0xA002, value: leaves_a[2] },
            MemoryEntry { address: 0xA003, value: leaves_a[3] },
            MemoryEntry { address: 0xB000, value: leaves_b[0] },
            MemoryEntry { address: 0xB001, value: leaves_b[1] },
            MemoryEntry { address: 0xB002, value: leaves_b[2] },
            MemoryEntry { address: 0xB003, value: leaves_b[3] },
            MemoryEntry { address: 0xC000, value: rolled_up },
        ],
        range_check_min: 0,
        range_check_max: u64::MAX,
    };

    // Build the explicit HashRollup trace (4 columns × N_ROLLUP rows) from
    // the packed inner-proof commitments.
    let f_trace = build_hash_rollup_trace(N_ROLLUP, &leaves);
    let to_u64 = |col: &Vec<F>| -> Vec<u64> {
        col.iter().map(|f| f.into_bigint().0[0]).collect()
    };
    let mut columns: HashMap<String, Vec<u64>> = HashMap::new();
    columns.insert("col0_idx".into(),      to_u64(&f_trace[0]));
    columns.insert("col1_leaf".into(),     to_u64(&f_trace[1]));
    columns.insert("col2_state".into(),    to_u64(&f_trace[2]));
    columns.insert("col3_state_sq".into(), to_u64(&f_trace[3]));

    let rollup_req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width:  4,
            length: N_ROLLUP,
            columns,
        },
        public_inputs: rollup_pi.clone(),
        config: ProverConfigInput {
            nist_level: Some(1),
            quantum_budget_log2: Some(40),
            air_type: Some("hash_rollup".into()),
            ..Default::default()
        },
    };

    println!("\n[STEP 4] Generate rollup STARK (HashRollup AIR over both pi_hashes)");
    let rollup_pr = handle_prove(State(state.clone()), Json(rollup_req))
        .await.expect("rollup prove failed").0;
    println!(
        "  rollup  prove={} ms size={} id={}",
        rollup_pr.prove_time_ms, rollup_pr.proof_size_bytes, rollup_pr.proof_id
    );

    // ── 5. Verify the rollup STARK ─────────────────────────────────────────
    println!("\n[STEP 5] Verify rollup STARK");
    let rollup_valid = verify_by_id(state.clone(), &rollup_pr.proof_id, &rollup_pi).await;
    assert!(rollup_valid, "rollup proof must verify");

    // ── 6. Verify one of the inner STARKs to confirm the pi_hash_A entered
    //      the rollup is anchored to a real, verifiable inner proof. ─────────
    println!("\n[STEP 6] Independently verify inner STARK A (anchors pi_hash_A)");
    let pi_a = CairoPublicInputs::for_cairo_simple_air(
        CAIRO_SIMPLE_INITIAL_PC, CAIRO_SIMPLE_INITIAL_AP, N_INNER_A,
    );
    let inner_a_valid = verify_by_id(state.clone(), &id_a, &pi_a).await;
    assert!(inner_a_valid, "inner proof A must verify");

    println!("\n[STEP 7] Independently verify inner STARK B (anchors pi_hash_B)");
    let pi_b = CairoPublicInputs::for_cairo_simple_air(
        CAIRO_SIMPLE_INITIAL_PC, CAIRO_SIMPLE_INITIAL_AP, N_INNER_B,
    );
    let inner_b_valid = verify_by_id(state.clone(), &id_b, &pi_b).await;
    assert!(inner_b_valid, "inner proof B must verify");

    // ── 7. Sanity: tamper with one inner pi_hash inside the rollup PI and
    //      confirm the rollup proof no longer matches it. ──────────────────
    let mut tampered_pi = rollup_pi.clone();
    tampered_pi.public_memory[0].value ^= 0xDEAD_BEEF; // flip pi_hash_A leaf 0
    let tamper_req = VerifyRequest {
        proof_id:    Some(rollup_pr.proof_id.clone()),
        bundle:      None, bundle_path: None, split_paths: None,
        public_inputs: Some(tampered_pi),
    };
    let tamper_resp = handle_verify(State(state.clone()), Json(tamper_req)).await;
    match tamper_resp {
        Ok(Json(vr)) => {
            println!("\n[STEP 8] Tampered rollup PI → valid={} message={}", vr.valid, vr.message);
            assert!(!vr.valid, "tampered rollup PI must not verify");
        }
        Err((status, Json(err))) => {
            println!(
                "\n[STEP 8] Tampered rollup PI → HTTP {} ({}) — rejected pre-FRI",
                status.as_u16(), err.error
            );
            assert_eq!(status.as_u16(), 400, "tamper detection should return 400");
        }
    }

    println!("\n=== ROLLUP DEMO SUCCESS ===");
    println!("  inner A id  = {id_a}");
    println!("  inner B id  = {id_b}");
    println!("  rollup id   = {}", rollup_pr.proof_id);
    println!("  aggregate   = 0x{:016x}", rolled_up);

    let _ = std::fs::remove_dir_all(&store_dir);
}
