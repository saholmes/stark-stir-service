//! Dual in-memory + file-backed STARK proof store.
//!
//! Proofs are stored as JSON files under `{store_dir}/{proof_id}.json`.
//! An in-memory HashMap provides fast lookup; the file backend persists
//! proofs across restarts and enables load-from-disk for standalone
//! verification.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
//  Serializable proof types
// ─────────────────────────────────────────────────────────────────────────────

/// Serialized Merkle opening (hash bytes as hex strings).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedMerkleOpening {
    /// Leaf hash (hex).
    pub leaf: String,
    /// Merkle path: each level is a sibling list (hex strings).
    pub path: Vec<Vec<String>>,
    /// Leaf index in the tree.
    pub index: usize,
}

/// Serialized FRI layer query reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedLayerQueryRef {
    pub i: usize,
    pub child_pos: usize,
    pub parent_index: usize,
    pub parent_pos: usize,
}

/// Serialized layer opening payload.
/// Extension field elements represented as Vec of hex u64 strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedLayerOpenPayload {
    pub f_val: Vec<String>,
    pub s_val: Vec<String>,
    pub q_val: Vec<String>,
}

/// Serialized FRI query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFriQuery {
    pub per_layer_refs: Vec<SerializedLayerQueryRef>,
    pub per_layer_payloads: Vec<SerializedLayerOpenPayload>,
    pub f0_opening: SerializedMerkleOpening,
    pub final_index: usize,
}

/// Serialized STIR proximity query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedStirProximityQuery {
    pub base_index: usize,
    pub raw_query_index: usize,
    pub fiber_indices: Vec<usize>,
    pub fiber_f_vals: Vec<String>,
    pub f0_packed_opening: SerializedMerkleOpening,
    pub f_next_val: Vec<String>,
    pub layer1_opening: Option<SerializedMerkleOpening>,
}

/// The full serialized DEEP-FRI proof.
/// Extension field elements are Vec<String> of hex-encoded u64 values.
/// Hash bytes are hex strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedProof {
    /// Root of f₀ Merkle tree (hex).
    pub root_f0: String,
    /// Roots of FRI layer Merkle trees (hex).
    pub roots: Vec<String>,
    /// Layer Merkle openings: outer index = layer, inner = per-query openings.
    pub layer_proofs: Vec<Vec<SerializedMerkleOpening>>,
    /// f₀ Merkle openings for DEEP queries.
    pub f0_openings: Vec<SerializedMerkleOpening>,
    /// FRI query payloads (one per query index r).
    pub queries: Vec<SerializedFriQuery>,
    /// f(z) evaluations at each FRI layer (extension field elements).
    pub fz_per_layer: Vec<Vec<String>>,
    /// Final low-degree polynomial coefficients (extension field elements).
    pub final_poly_coeffs: Vec<Vec<String>>,
    /// FRI domain size.
    pub n0: usize,
    /// FRI domain generator (hex u64).
    pub omega0: String,
    /// Coefficient commitment tuples (present when coeff_commit_final=true).
    pub coeff_tuples: Option<Vec<Vec<Vec<String>>>>,
    /// Root of the coefficient commitment tree (hex).
    pub coeff_root: Option<String>,
    /// STIR coset evaluations per layer (present when stir=true).
    pub stir_coset_evals: Option<Vec<Vec<Vec<String>>>>,
    /// STIR proximity queries (present when stir=true).
    pub stir_proximity_queries: Option<Vec<SerializedStirProximityQuery>>,
    /// Extension field degree (e.g. 6 for SexticExt).
    pub ext_degree: usize,
}

/// Protocol parameters stored alongside the proof for verification.
///
/// The `nist_level`, `quantum_budget_log2`, `ext_degree`, and `hash_alg`
/// fields are optional for backward compatibility with proofs created before
/// the NIST profile machinery was introduced.  Older proofs default to
/// Fp^6 / SHA3-256 with no NIST profile metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedParams {
    pub schedule: Vec<usize>,
    pub r: usize,
    pub seed_z: u64,
    pub coeff_commit_final: bool,
    pub d_final: usize,
    pub stir: bool,
    pub s0: usize,
    pub n0: usize,
    pub blowup: usize,
    pub air_type: String,
    pub security_level: u32,
    /// SHA3-{256,384,512} hash of the public inputs (hex), bound into the FRI transcript.
    pub public_inputs_hash: String,
    /// NIST PQ level (1, 3, or 5).  None for legacy proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nist_level: Option<u8>,
    /// Quantum query budget log₂(q): 40, 65, or 90.  None for legacy proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantum_budget_log2: Option<u32>,
    /// Extension-field degree: 6 (SexticExt) or 8 (OcticExt).  Defaults to 6 for legacy proofs.
    #[serde(default = "default_ext_degree")]
    pub ext_degree: usize,
    /// Hash variant used for Merkle commitments and Fiat-Shamir.
    /// One of "SHA3-256", "SHA3-384", "SHA3-512".  Defaults to SHA3-256 for legacy proofs.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

fn default_ext_degree() -> usize { 6 }
fn default_hash_alg() -> String { "SHA3-256".to_string() }

/// Metadata about a single proving run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub prove_time_ms: u64,
    pub proof_size_bytes: usize,
    pub trace_width: usize,
    pub trace_length: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
//  ethSTARK-compatible split file types
// ─────────────────────────────────────────────────────────────────────────────
//
// ethSTARK (StarkWare stone-prover) writes 3 separate files:
//   * `<base>.params.json`        — protocol parameters (security, FRI layers, hash)
//   * `<base>.public_input.json`  — application-level public inputs
//   * `<base>.proof.json`         — the FRI proof tree itself
//
// The proof commits cryptographically to the public inputs via Fiat-Shamir,
// so the three files are tamper-evident as a set.

/// Split-format params file (`<base>.params.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitParamsFile {
    pub format: String,           // "stark-stir-fips/params-v1"
    pub created_at: DateTime<Utc>,
    pub proof_id: String,
    pub params: SerializedParams,
    pub metadata: ProofMetadata,
}

/// Split-format public input file (`<base>.public_input.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitPublicInputFile {
    pub format: String,           // "stark-stir-fips/public-input-v1"
    pub created_at: DateTime<Utc>,
    pub proof_id: String,
    pub public_inputs: serde_json::Value,
    /// SHA3-256 hex of public_inputs (binds this file to the proof).
    pub public_inputs_hash: String,
}

/// Split-format proof file (`<base>.proof.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitProofFile {
    pub format: String,           // "stark-stir-fips/proof-v1"
    pub created_at: DateTime<Utc>,
    pub proof_id: String,
    pub proof: SerializedProof,
    /// Echoed for cross-file integrity check on verify.
    pub public_inputs_hash: String,
}

/// The complete JSON proof bundle stored as `{store_dir}/{proof_id}.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonProofBundle {
    /// Bundle format version.
    pub version: String,
    /// Unique proof identifier.
    pub proof_id: String,
    /// UTC creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Cairo-style public inputs (as raw JSON).
    pub public_inputs: serde_json::Value,
    /// The serialized FRI proof.
    pub proof: SerializedProof,
    /// Protocol parameters used during proving.
    pub params: SerializedParams,
    /// Performance and size metadata.
    pub metadata: ProofMetadata,
}

impl JsonProofBundle {
    pub const VERSION: &'static str = "stark-stir-fips-v1";

    pub fn new(
        public_inputs: serde_json::Value,
        proof: SerializedProof,
        params: SerializedParams,
        metadata: ProofMetadata,
    ) -> Self {
        JsonProofBundle {
            version: Self::VERSION.into(),
            proof_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            public_inputs,
            proof,
            params,
            metadata,
        }
    }

    /// Split this bundle into ethSTARK-compatible files.
    pub fn split(&self) -> (SplitParamsFile, SplitPublicInputFile, SplitProofFile) {
        let pi_hash = self.params.public_inputs_hash.clone();
        let now = self.created_at;
        let id = self.proof_id.clone();

        let params_file = SplitParamsFile {
            format: "stark-stir-fips/params-v1".into(),
            created_at: now,
            proof_id: id.clone(),
            params: self.params.clone(),
            metadata: self.metadata.clone(),
        };
        let public_file = SplitPublicInputFile {
            format: "stark-stir-fips/public-input-v1".into(),
            created_at: now,
            proof_id: id.clone(),
            public_inputs: self.public_inputs.clone(),
            public_inputs_hash: pi_hash.clone(),
        };
        let proof_file = SplitProofFile {
            format: "stark-stir-fips/proof-v1".into(),
            created_at: now,
            proof_id: id,
            proof: self.proof.clone(),
            public_inputs_hash: pi_hash,
        };
        (params_file, public_file, proof_file)
    }

    /// Reassemble a bundle from ethSTARK-style split files.  Verifies that
    /// all three files agree on `proof_id` and `public_inputs_hash`.
    pub fn from_split(
        params: SplitParamsFile,
        public_input: SplitPublicInputFile,
        proof: SplitProofFile,
    ) -> Result<Self, StoreError> {
        if params.proof_id != public_input.proof_id || params.proof_id != proof.proof_id {
            return Err(StoreError::InvalidId(format!(
                "proof_id mismatch across split files: params={}, public_input={}, proof={}",
                params.proof_id, public_input.proof_id, proof.proof_id,
            )));
        }
        let pih = &params.params.public_inputs_hash;
        if pih != &public_input.public_inputs_hash || pih != &proof.public_inputs_hash {
            return Err(StoreError::InvalidId(
                "public_inputs_hash mismatch across split files".into(),
            ));
        }
        Ok(JsonProofBundle {
            version: Self::VERSION.into(),
            proof_id: params.proof_id,
            created_at: params.created_at,
            public_inputs: public_input.public_inputs,
            proof: proof.proof,
            params: params.params,
            metadata: params.metadata,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Store errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("proof not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid proof id: {0}")]
    InvalidId(String),
}

// ─────────────────────────────────────────────────────────────────────────────
//  ProofStore
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory + file-backed proof store.
///
/// On `save`, the bundle is written to `{store_dir}/{proof_id}.json` AND
/// cached in the in-memory map.  On `load`, the in-memory map is checked
/// first; if missing (e.g. after a restart), the file is read from disk.
pub struct ProofStore {
    store_dir: PathBuf,
    cache: Arc<RwLock<HashMap<String, JsonProofBundle>>>,
}

impl ProofStore {
    /// Create a new store rooted at `store_dir`.
    /// Creates the directory if it does not exist.
    pub fn new<P: AsRef<Path>>(store_dir: P) -> Result<Self, StoreError> {
        let store_dir = store_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&store_dir)?;
        Ok(ProofStore {
            store_dir,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Save a proof bundle.  Returns the proof_id.
    pub fn save(&self, bundle: JsonProofBundle) -> Result<String, StoreError> {
        let proof_id = bundle.proof_id.clone();
        let path = self.path_for(&proof_id);
        let json = serde_json::to_string_pretty(&bundle)?;
        std::fs::write(&path, json)?;
        self.cache.write().unwrap().insert(proof_id.clone(), bundle);
        Ok(proof_id)
    }

    /// Save a bundle to a caller-specified path (no UUID rename).
    /// Also caches under `bundle.proof_id`.
    pub fn save_to_path<P: AsRef<Path>>(
        &self,
        bundle: JsonProofBundle,
        path: P,
    ) -> Result<PathBuf, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(&bundle)?;
        std::fs::write(&path, json)?;
        self.cache.write().unwrap().insert(bundle.proof_id.clone(), bundle);
        Ok(path)
    }

    /// Save a bundle in ethSTARK-split format: writes 3 files under the same
    /// stem.  `<stem>.params.json`, `<stem>.public_input.json`, `<stem>.proof.json`.
    /// `stem_path` may be a full path or a stem; the suffixes are appended.
    pub fn save_split<P: AsRef<Path>>(
        &self,
        bundle: JsonProofBundle,
        stem_path: P,
    ) -> Result<SplitPaths, StoreError> {
        let stem = stem_path.as_ref().to_path_buf();
        if let Some(parent) = stem.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let stem_str = stem.to_string_lossy().trim_end_matches(".json").to_string();
        let params_path = PathBuf::from(format!("{stem_str}.params.json"));
        let public_path = PathBuf::from(format!("{stem_str}.public_input.json"));
        let proof_path  = PathBuf::from(format!("{stem_str}.proof.json"));

        let (params_file, public_file, proof_file) = bundle.split();

        std::fs::write(&params_path, serde_json::to_string_pretty(&params_file)?)?;
        std::fs::write(&public_path, serde_json::to_string_pretty(&public_file)?)?;
        std::fs::write(&proof_path,  serde_json::to_string_pretty(&proof_file)?)?;

        self.cache.write().unwrap().insert(bundle.proof_id.clone(), bundle);

        Ok(SplitPaths { params: params_path, public_input: public_path, proof: proof_path })
    }

    /// Retrieve a proof bundle by ID.
    /// Checks in-memory cache first; falls back to reading from disk.
    pub fn get(&self, proof_id: &str) -> Result<JsonProofBundle, StoreError> {
        {
            let cache = self.cache.read().unwrap();
            if let Some(b) = cache.get(proof_id) {
                return Ok(b.clone());
            }
        }

        let path = self.path_for(proof_id);
        let json = std::fs::read_to_string(&path)
            .map_err(|_| StoreError::NotFound(proof_id.into()))?;
        let bundle: JsonProofBundle = serde_json::from_str(&json)?;

        self.cache.write().unwrap().insert(proof_id.into(), bundle.clone());
        Ok(bundle)
    }

    /// Load a proof bundle directly from a file path (for standalone verification).
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<JsonProofBundle, StoreError> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Load a bundle from ethSTARK-split files.  All three paths must be
    /// provided.  Performs cross-file integrity checks.
    pub fn load_from_split<P: AsRef<Path>>(
        params_path: P,
        public_input_path: P,
        proof_path: P,
    ) -> Result<JsonProofBundle, StoreError> {
        let params: SplitParamsFile =
            serde_json::from_str(&std::fs::read_to_string(params_path)?)?;
        let public_input: SplitPublicInputFile =
            serde_json::from_str(&std::fs::read_to_string(public_input_path)?)?;
        let proof: SplitProofFile =
            serde_json::from_str(&std::fs::read_to_string(proof_path)?)?;
        JsonProofBundle::from_split(params, public_input, proof)
    }

    /// List all stored proof IDs (from the filesystem).
    pub fn list_ids(&self) -> Result<Vec<String>, StoreError> {
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.store_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.ends_with(".json") {
                ids.push(s.trim_end_matches(".json").to_string());
            }
        }
        Ok(ids)
    }

    /// Number of proofs currently in the in-memory cache.
    pub fn cache_size(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Public accessor for the on-disk path of a stored proof_id.
    pub fn path_for_id(&self, proof_id: &str) -> PathBuf {
        self.path_for(proof_id)
    }

    fn path_for(&self, proof_id: &str) -> PathBuf {
        self.store_dir.join(format!("{proof_id}.json"))
    }
}

/// Three paths produced by `save_split`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplitPaths {
    pub params: PathBuf,
    pub public_input: PathBuf,
    pub proof: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Binary-native proof representation
// ─────────────────────────────────────────────────────────────────────────────
//
// `SerializedProof` (above) carries all hash bytes as `0x...` hex strings and
// all field elements as 16-char hex u64 strings.  That keeps the JSON form
// human-readable but inflates wire size by ~2.25× vs the raw bytes.
//
// `SerializedProofBytes` is the binary-native equivalent: hashes become
// `Vec<u8>`, field-element u64s become `u64`, extension elements become
// `Vec<u64>`.  Combined with `bincode` serialization, this matches the wire
// representation a paper-style benchmark would report.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedMerkleOpeningBytes {
    pub leaf:  Vec<u8>,
    pub path:  Vec<Vec<Vec<u8>>>,
    pub index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedLayerOpenPayloadBytes {
    pub f_val: Vec<u64>,
    pub s_val: Vec<u64>,
    pub q_val: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFriQueryBytes {
    pub per_layer_refs:     Vec<SerializedLayerQueryRef>,
    pub per_layer_payloads: Vec<SerializedLayerOpenPayloadBytes>,
    pub f0_opening:         SerializedMerkleOpeningBytes,
    pub final_index:        usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedStirProximityQueryBytes {
    pub base_index:        usize,
    pub raw_query_index:   usize,
    pub fiber_indices:     Vec<usize>,
    pub fiber_f_vals:      Vec<u64>,
    pub f0_packed_opening: SerializedMerkleOpeningBytes,
    pub f_next_val:        Vec<u64>,
    pub layer1_opening:    Option<SerializedMerkleOpeningBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedProofBytes {
    pub root_f0:                Vec<u8>,
    pub roots:                  Vec<Vec<u8>>,
    pub layer_proofs:           Vec<Vec<SerializedMerkleOpeningBytes>>,
    pub f0_openings:            Vec<SerializedMerkleOpeningBytes>,
    pub queries:                Vec<SerializedFriQueryBytes>,
    pub fz_per_layer:           Vec<Vec<u64>>,
    pub final_poly_coeffs:      Vec<Vec<u64>>,
    pub n0:                     usize,
    pub omega0:                 u64,
    pub coeff_tuples:           Option<Vec<Vec<Vec<u64>>>>,
    pub coeff_root:             Option<Vec<u8>>,
    pub stir_coset_evals:       Option<Vec<Vec<Vec<u64>>>>,
    pub stir_proximity_queries: Option<Vec<SerializedStirProximityQueryBytes>>,
    pub ext_degree:             usize,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hex ↔ binary conversions
// ─────────────────────────────────────────────────────────────────────────────

fn hex_to_u64(s: &str) -> u64 {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap_or_default()
}

fn opening_to_bytes(o: &SerializedMerkleOpening) -> SerializedMerkleOpeningBytes {
    SerializedMerkleOpeningBytes {
        leaf:  hex_to_bytes(&o.leaf),
        path:  o.path.iter().map(|lvl| lvl.iter().map(|h| hex_to_bytes(h)).collect()).collect(),
        index: o.index,
    }
}

impl From<&SerializedProof> for SerializedProofBytes {
    fn from(p: &SerializedProof) -> Self {
        SerializedProofBytes {
            root_f0: hex_to_bytes(&p.root_f0),
            roots:   p.roots.iter().map(|r| hex_to_bytes(r)).collect(),
            layer_proofs: p.layer_proofs.iter()
                .map(|lp| lp.iter().map(opening_to_bytes).collect())
                .collect(),
            f0_openings: p.f0_openings.iter().map(opening_to_bytes).collect(),
            queries: p.queries.iter().map(|q| SerializedFriQueryBytes {
                per_layer_refs: q.per_layer_refs.clone(),
                per_layer_payloads: q.per_layer_payloads.iter()
                    .map(|pp| SerializedLayerOpenPayloadBytes {
                        f_val: pp.f_val.iter().map(|s| hex_to_u64(s)).collect(),
                        s_val: pp.s_val.iter().map(|s| hex_to_u64(s)).collect(),
                        q_val: pp.q_val.iter().map(|s| hex_to_u64(s)).collect(),
                    }).collect(),
                f0_opening: opening_to_bytes(&q.f0_opening),
                final_index: q.final_index,
            }).collect(),
            fz_per_layer: p.fz_per_layer.iter()
                .map(|v| v.iter().map(|s| hex_to_u64(s)).collect())
                .collect(),
            final_poly_coeffs: p.final_poly_coeffs.iter()
                .map(|v| v.iter().map(|s| hex_to_u64(s)).collect())
                .collect(),
            n0:     p.n0,
            omega0: hex_to_u64(&p.omega0),
            coeff_tuples: p.coeff_tuples.as_ref().map(|ct|
                ct.iter().map(|row|
                    row.iter().map(|v| v.iter().map(|s| hex_to_u64(s)).collect()).collect()
                ).collect()),
            coeff_root: p.coeff_root.as_ref().map(|r| hex_to_bytes(r)),
            stir_coset_evals: p.stir_coset_evals.as_ref().map(|ls|
                ls.iter().map(|layer|
                    layer.iter().map(|v| v.iter().map(|s| hex_to_u64(s)).collect()).collect()
                ).collect()),
            stir_proximity_queries: p.stir_proximity_queries.as_ref().map(|qs|
                qs.iter().map(|q| SerializedStirProximityQueryBytes {
                    base_index: q.base_index,
                    raw_query_index: q.raw_query_index,
                    fiber_indices: q.fiber_indices.clone(),
                    fiber_f_vals: q.fiber_f_vals.iter().map(|s| hex_to_u64(s)).collect(),
                    f0_packed_opening: opening_to_bytes(&q.f0_packed_opening),
                    f_next_val: q.f_next_val.iter().map(|s| hex_to_u64(s)).collect(),
                    layer1_opening: q.layer1_opening.as_ref().map(opening_to_bytes),
                }).collect()),
            ext_degree: p.ext_degree,
        }
    }
}

impl SerializedProof {
    /// Bincode-serialize the proof in **binary-native** form (hex strings
    /// converted back to raw bytes / u64 first).  Returns the wire-size
    /// number that paper-style benchmarks report.
    pub fn to_bincode_compact(&self) -> Vec<u8> {
        let bin: SerializedProofBytes = self.into();
        bincode::serialize(&bin).expect("bincode serialize")
    }

    /// JSON-encoded size of the proof (current default storage format).
    pub fn to_json_size(&self) -> usize {
        serde_json::to_vec(self).expect("json serialize").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_bundle() -> JsonProofBundle {
        let proof = SerializedProof {
            root_f0: "0xdead".into(),
            roots: vec!["0xbeef".into()],
            layer_proofs: vec![],
            f0_openings: vec![],
            queries: vec![],
            fz_per_layer: vec![],
            final_poly_coeffs: vec![],
            n0: 256,
            omega0: "0x1".into(),
            coeff_tuples: None,
            coeff_root: None,
            stir_coset_evals: None,
            stir_proximity_queries: None,
            ext_degree: 6,
        };
        let params = SerializedParams {
            schedule: vec![2, 2, 2],
            r: 54,
            seed_z: 42,
            coeff_commit_final: false,
            d_final: 1,
            stir: false,
            s0: 54,
            n0: 256,
            blowup: 4,
            air_type: "fib_w2_d2".into(),
            security_level: 128,
            public_inputs_hash: "abc123".into(),
            nist_level: Some(1),
            quantum_budget_log2: Some(40),
            ext_degree: 6,
            hash_alg: "SHA3-256".into(),
        };
        let meta = ProofMetadata {
            prove_time_ms: 0,
            proof_size_bytes: 0,
            trace_width: 2,
            trace_length: 64,
        };
        JsonProofBundle::new(serde_json::json!({}), proof, params, meta)
    }

    #[test]
    fn split_roundtrip_preserves_bundle() {
        let bundle = dummy_bundle();
        let (params_f, public_f, proof_f) = bundle.split();
        assert_eq!(params_f.params.public_inputs_hash, public_f.public_inputs_hash);
        assert_eq!(public_f.public_inputs_hash, proof_f.public_inputs_hash);

        let restored = JsonProofBundle::from_split(params_f, public_f, proof_f).unwrap();
        assert_eq!(restored.proof_id, bundle.proof_id);
        assert_eq!(restored.params.r, 54);
        assert_eq!(restored.params.public_inputs_hash, bundle.params.public_inputs_hash);
    }

    #[test]
    fn split_detects_proof_id_mismatch() {
        let bundle = dummy_bundle();
        let (mut params_f, public_f, proof_f) = bundle.split();
        params_f.proof_id = "different-id".into();
        assert!(JsonProofBundle::from_split(params_f, public_f, proof_f).is_err());
    }

    #[test]
    fn split_detects_pi_hash_mismatch() {
        let bundle = dummy_bundle();
        let (params_f, mut public_f, proof_f) = bundle.split();
        public_f.public_inputs_hash = "tampered".into();
        assert!(JsonProofBundle::from_split(params_f, public_f, proof_f).is_err());
    }

    #[test]
    fn save_load_split_files_round_trip() {
        let tmp = tempdir_path();
        let bundle = dummy_bundle();
        let store = ProofStore::new(&tmp).unwrap();
        let stem = tmp.join("test_proof");
        let paths = store.save_split(bundle.clone(), &stem).unwrap();

        assert!(paths.params.exists());
        assert!(paths.public_input.exists());
        assert!(paths.proof.exists());

        let restored = ProofStore::load_from_split(
            &paths.params, &paths.public_input, &paths.proof,
        ).unwrap();
        assert_eq!(restored.proof_id, bundle.proof_id);

        std::fs::remove_dir_all(&tmp).ok();
    }

    fn tempdir_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "proof-store-test-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
