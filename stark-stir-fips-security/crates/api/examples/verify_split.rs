//! Standalone verifier for ethSTARK-split proof files.
//!
//! Usage:
//!   cargo run --release -p api --no-default-features --features sha3-512 \
//!     --example verify_split -- \
//!     <params.json> <public_input.json> <proof.json>
//!
//! Exit code 0 on valid, 1 on invalid or error.

use axum::{extract::State, Json};

use api::{
    routes::verify::handle_verify,
    types::{VerifyRequest, VerifySplitPaths},
    AppState,
};
use proof_store::ProofStore;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "usage: {} <params.json> <public_input.json> <proof.json>",
            args[0]
        );
        std::process::exit(2);
    }

    // Build a throwaway ProofStore (verify-by-path doesn't use it for storage).
    let tmp = std::env::temp_dir().join(format!(
        "verify-split-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).expect("cannot create temp store dir");
    let store = ProofStore::new(&tmp).expect("ProofStore::new failed");
    let state = AppState::with_in_memory_auth(store);

    let req = VerifyRequest {
        proof_id:     None,
        bundle:       None,
        bundle_path:  None,
        split_paths:  Some(VerifySplitPaths {
            params:       args[1].clone(),
            public_input: args[2].clone(),
            proof:        args[3].clone(),
        }),
        public_inputs: None, // read from the public_input file
    };

    println!("verifying:");
    println!("  params       = {}", args[1]);
    println!("  public_input = {}", args[2]);
    println!("  proof        = {}", args[3]);

    let resp = handle_verify(State(state), Json(req)).await;
    let _ = std::fs::remove_dir_all(&tmp);

    match resp {
        Ok(Json(vr)) => {
            println!();
            println!("proof_id        = {}", vr.proof_id.unwrap_or_default());
            println!("verify_time_ms  = {}", vr.verify_time_ms);
            println!("valid           = {}", vr.valid);
            println!("message         = {}", vr.message);
            std::process::exit(if vr.valid { 0 } else { 1 });
        }
        Err((status, Json(err))) => {
            eprintln!();
            eprintln!("verify error (HTTP {}): {}", status.as_u16(), err.error);
            if let Some(d) = err.details {
                eprintln!("details: {d}");
            }
            std::process::exit(1);
        }
    }
}
