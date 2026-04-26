//! Request / response types for the STARK API.

use serde::{Deserialize, Serialize};
use public_inputs::CairoPublicInputs;

// ─────────────────────────────────────────────────────────────────────────────
//  Prove endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// StarkWare-style column-major trace (matches ethSTARK trace export format).
#[derive(Debug, Deserialize)]
pub struct StarkWareTraceInput {
    /// Trace format identifier (e.g. "starkware-v1").
    pub format: Option<String>,
    /// Number of trace columns.
    pub width: usize,
    /// Number of trace rows (must be a power of 2).
    pub length: usize,
    /// Column data: map from column name to a vector of u64 field elements.
    pub columns: std::collections::HashMap<String, Vec<u64>>,
}

/// Optional prover configuration.
///
/// Two ways to specify security:
///   1. NIST profile: set `nist_level` (1, 3, 5) and `quantum_budget_log2` (40, 65, 90).
///      The profile determines the hash variant, extension field (Fp^6/Fp^8), and `r`.
///   2. Legacy mode: set `security_level` (bits) directly; uses Fp^6 + build-time hash.
#[derive(Debug, Deserialize, Default)]
pub struct ProverConfigInput {
    /// NIST PQ level: 1, 3, or 5.  When set, takes precedence over `security_level`.
    pub nist_level: Option<u8>,
    /// Quantum query budget log₂(q): 40, 65, or 90.  Required when `nist_level` is set.
    pub quantum_budget_log2: Option<u32>,
    /// Allow Level 5 q=2^90 (binding-wall violator, NOT FIPS-compliant).
    #[serde(default)]
    pub allow_binding_wall_violation: bool,
    /// Legacy: target security level in bits (default: 100).  Ignored if `nist_level` is set.
    pub security_level: Option<u32>,
    /// FRI mode: "fri" (default) or "stir".
    pub fri_mode: Option<String>,
    /// LDE blowup factor (default: 4).
    pub blowup: Option<usize>,
    /// Output format.  "bundle" (default) writes a single combined JSON file.
    /// "ethstark-split" writes three files matching ethSTARK convention:
    ///   `<stem>.params.json`, `<stem>.public_input.json`, `<stem>.proof.json`
    pub output_format: Option<String>,
    /// Where to write the proof on disk.  For "bundle" format this is the full
    /// path of a single JSON file.  For "ethstark-split" this is the stem path
    /// (suffixes appended).  When omitted, the proof is stored under the
    /// server's `store_dir/{proof_id}.json` (legacy behavior).
    pub output_path: Option<String>,
    /// Optional explicit AIR type label: one of
    /// "fibonacci" | "cairo_simple" | "poseidon_chain" | "register_machine" | "hash_rollup".
    /// When omitted, the AIR is inferred from `trace.width` (2/8/16 → standard mapping;
    /// 4 → HashRollup, anything else → RegisterMachine).
    pub air_type: Option<String>,
}

/// Request body for POST /v1/prove.
#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    /// Execution trace in StarkWare column-major format.
    pub trace: StarkWareTraceInput,
    /// Cairo-style public inputs.
    pub public_inputs: CairoPublicInputs,
    /// Optional prover configuration.
    #[serde(default)]
    pub config: ProverConfigInput,
}

/// Response from POST /v1/prove.
#[derive(Debug, Serialize)]
pub struct ProveResponse {
    /// Unique proof identifier for later retrieval or verification.
    pub proof_id: String,
    /// Time taken to generate the proof in milliseconds.
    pub prove_time_ms: u64,
    /// Proof size in bytes (JSON-encoded).
    pub proof_size_bytes: usize,
    /// The full proof bundle (same as what is stored on disk).
    pub bundle: serde_json::Value,
    /// Output paths actually written.
    /// For "bundle" format: one path. For "ethstark-split" format: three paths.
    pub output_paths: ProveOutputPaths,
}

/// Either a single path (bundle) or three paths (ethSTARK-split).
#[derive(Debug, Serialize, Default)]
pub struct ProveOutputPaths {
    /// Path of the bundled JSON file (bundle format only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    /// Path of `<stem>.params.json` (ethstark-split format only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<String>,
    /// Path of `<stem>.public_input.json` (ethstark-split format only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_input: Option<String>,
    /// Path of `<stem>.proof.json` (ethstark-split format only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Verify endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Request body for POST /v1/verify.
///
/// Exactly one of these proof sources must be provided:
///   * `proof_id`     — load a bundled proof from the server store
///   * `bundle`       — inline proof bundle (single-file format)
///   * `bundle_path`  — load a bundled proof from a file path on the server
///   * `split_paths`  — load an ethSTARK-split proof from three file paths
///
/// `public_inputs` may be supplied inline; for split-format loads, the file's
/// `public_inputs` is used and the inline value (if any) is checked for
/// consistency.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// ID of a previously stored proof (load from server's file store).
    pub proof_id: Option<String>,
    /// Inline proof bundle (single-file format).
    pub bundle: Option<serde_json::Value>,
    /// Path to a bundled JSON proof file on the server.
    pub bundle_path: Option<String>,
    /// Paths to the three ethSTARK-split files.
    pub split_paths: Option<VerifySplitPaths>,
    /// Public inputs to verify against (optional when `split_paths` is used).
    /// Must match those used during proving.
    pub public_inputs: Option<CairoPublicInputs>,
}

/// Paths to the three ethSTARK-split files for verification.
#[derive(Debug, Deserialize)]
pub struct VerifySplitPaths {
    pub params: String,
    pub public_input: String,
    pub proof: String,
}

/// Response from POST /v1/verify.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Proof ID (echoed back if one was provided).
    pub proof_id: Option<String>,
    /// Time taken to verify in milliseconds.
    pub verify_time_ms: u64,
    /// Human-readable verdict.
    pub message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Error response
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        ErrorResponse { error: error.into(), details: None }
    }

    pub fn with_details(error: impl Into<String>, details: impl Into<String>) -> Self {
        ErrorResponse { error: error.into(), details: Some(details.into()) }
    }
}
