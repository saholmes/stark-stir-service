//! Conversion between `DeepFriProof<E>` and the JSON-serializable
//! `SerializedProof` type from the proof-store crate.
//!
//! Generic over the extension field `E: TowerField` so the same code path
//! handles both Fp^6 (`SexticExt`) and Fp^8 (`OcticExt`) at runtime.
//!
//! Goldilocks field elements are stored as hex-encoded u64 strings to avoid
//! JavaScript/JSON 53-bit precision loss (Goldilocks prime ≈ 2^64).
//! Extension field elements are stored as Vec<String> of DEGREE hex u64s.

use ark_ff::PrimeField;
use ark_goldilocks::Goldilocks as F;

use deep_ali::{
    fri::{
        DeepFriProof, FriQueryPayload, LayerQueryRef, LayerOpenPayload,
        FriLayerProofs, LayerProof, StirProximityPayload,
    },
    tower_field::TowerField,
};

use merkle::MerkleOpening;

use proof_store::{
    SerializedFriQuery, SerializedLayerOpenPayload, SerializedLayerQueryRef,
    SerializedMerkleOpening, SerializedProof, SerializedStirProximityQuery,
};

// ─────────────────────────────────────────────────────────────────────────────
//  Primitive helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Goldilocks field element → hex string ("0x" + 16 hex chars).
pub fn f_to_hex(f: F) -> String {
    format!("0x{:016x}", f.into_bigint().0[0])
}

/// Hex string → Goldilocks field element.
pub fn hex_to_f(s: &str) -> Result<F, String> {
    let s = s.trim_start_matches("0x");
    let v = u64::from_str_radix(s, 16).map_err(|e| format!("bad hex u64 '{s}': {e}"))?;
    Ok(F::from(v))
}

/// Extension field element → Vec<String> (one hex u64 per base component).
pub fn ext_to_hex_vec<E: TowerField>(e: E) -> Vec<String> {
    e.to_fp_components().into_iter().map(f_to_hex).collect()
}

/// Vec<String> → extension field element.
pub fn hex_vec_to_ext<E: TowerField>(v: &[String]) -> Result<E, String> {
    if v.len() != E::DEGREE {
        return Err(format!("expected {} components, got {}", E::DEGREE, v.len()));
    }
    let comps: Result<Vec<F>, _> = v.iter().map(|s| hex_to_f(s)).collect();
    E::from_fp_components(&comps?).ok_or_else(|| "invalid ext field element".into())
}

/// Raw bytes → hex string.
pub fn bytes_to_hex(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Hex string → bytes.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(|e| format!("bad hex bytes: {e}"))
}

/// Fixed-size byte array → hex.
pub fn hash_to_hex<const N: usize>(h: &[u8; N]) -> String {
    bytes_to_hex(h)
}

/// Hex → fixed-size byte array.
pub fn hex_to_hash<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = hex_to_bytes(s)?;
    if v.len() != N {
        return Err(format!("expected {N} bytes, got {}", v.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
//  MerkleOpening serialization
// ─────────────────────────────────────────────────────────────────────────────

pub fn serialize_merkle_opening(o: &MerkleOpening) -> SerializedMerkleOpening {
    SerializedMerkleOpening {
        leaf: hash_to_hex(&o.leaf),
        path: o.path.iter()
            .map(|level| level.iter().map(|h| hash_to_hex(h)).collect())
            .collect(),
        index: o.index,
    }
}

pub fn deserialize_merkle_opening(s: &SerializedMerkleOpening) -> Result<MerkleOpening, String> {
    Ok(MerkleOpening {
        leaf: hex_to_hash(&s.leaf)?,
        path: s.path.iter()
            .map(|level| level.iter().map(|h| hex_to_hash(h)).collect::<Result<Vec<_>, _>>())
            .collect::<Result<Vec<_>, _>>()?,
        index: s.index,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  FRI query payloads
// ─────────────────────────────────────────────────────────────────────────────

pub fn serialize_layer_query_ref(r: &LayerQueryRef) -> SerializedLayerQueryRef {
    SerializedLayerQueryRef {
        i: r.i,
        child_pos: r.child_pos,
        parent_index: r.parent_index,
        parent_pos: r.parent_pos,
    }
}

pub fn serialize_layer_open_payload<E: TowerField>(p: &LayerOpenPayload<E>) -> SerializedLayerOpenPayload {
    SerializedLayerOpenPayload {
        f_val: ext_to_hex_vec(p.f_val),
        s_val: ext_to_hex_vec(p.s_val),
        q_val: ext_to_hex_vec(p.q_val),
    }
}

pub fn serialize_fri_query<E: TowerField>(q: &FriQueryPayload<E>) -> SerializedFriQuery {
    SerializedFriQuery {
        per_layer_refs: q.per_layer_refs.iter().map(serialize_layer_query_ref).collect(),
        per_layer_payloads: q.per_layer_payloads.iter().map(serialize_layer_open_payload).collect(),
        f0_opening: serialize_merkle_opening(&q.f0_opening),
        final_index: q.final_index,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  STIR proximity queries
// ─────────────────────────────────────────────────────────────────────────────

pub fn serialize_stir_query<E: TowerField>(q: &StirProximityPayload<E>) -> SerializedStirProximityQuery {
    SerializedStirProximityQuery {
        base_index: q.base_index,
        raw_query_index: q.raw_query_index,
        fiber_indices: q.fiber_indices.clone(),
        fiber_f_vals: q.fiber_f_vals.iter().map(|&f| f_to_hex(f)).collect(),
        f0_packed_opening: serialize_merkle_opening(&q.f0_packed_opening),
        f_next_val: ext_to_hex_vec(q.f_next_val),
        layer1_opening: q.layer1_opening.as_ref().map(serialize_merkle_opening),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  DeepFriProof → SerializedProof
// ─────────────────────────────────────────────────────────────────────────────

pub fn serialize_proof<E: TowerField>(proof: &DeepFriProof<E>) -> SerializedProof {
    let layer_proofs: Vec<Vec<SerializedMerkleOpening>> = proof
        .layer_proofs
        .layers
        .iter()
        .map(|lp| lp.openings.iter().map(serialize_merkle_opening).collect())
        .collect();

    SerializedProof {
        root_f0: hash_to_hex(&proof.root_f0),
        roots: proof.roots.iter().map(|r| hash_to_hex(r)).collect(),
        layer_proofs,
        f0_openings: proof.f0_openings.iter().map(serialize_merkle_opening).collect(),
        queries: proof.queries.iter().map(serialize_fri_query).collect(),
        fz_per_layer: proof.fz_per_layer.iter().map(|&e| ext_to_hex_vec(e)).collect(),
        final_poly_coeffs: proof.final_poly_coeffs.iter().map(|&e| ext_to_hex_vec(e)).collect(),
        n0: proof.n0,
        omega0: f_to_hex(proof.omega0),
        coeff_tuples: proof.coeff_tuples.as_ref().map(|ct| {
            ct.iter().map(|row| row.iter().map(|&e| ext_to_hex_vec(e)).collect()).collect()
        }),
        coeff_root: proof.coeff_root.as_ref().map(|r| hash_to_hex(r)),
        stir_coset_evals: proof.stir_coset_evals.as_ref().map(|layers| {
            layers.iter().map(|layer| layer.iter().map(|&e| ext_to_hex_vec(e)).collect()).collect()
        }),
        stir_proximity_queries: proof.stir_proximity_queries.as_ref().map(|qs| {
            qs.iter().map(serialize_stir_query).collect()
        }),
        ext_degree: E::DEGREE,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SerializedProof → DeepFriProof
// ─────────────────────────────────────────────────────────────────────────────

pub fn deserialize_proof<E: TowerField>(s: &SerializedProof) -> Result<DeepFriProof<E>, String> {
    if s.ext_degree != E::DEGREE {
        return Err(format!(
            "extension-field degree mismatch: stored proof uses Fp^{} but verifier uses Fp^{}",
            s.ext_degree, E::DEGREE
        ));
    }

    let layer_proofs = FriLayerProofs {
        layers: s.layer_proofs.iter()
            .map(|lp| Ok(LayerProof {
                openings: lp.iter().map(deserialize_merkle_opening).collect::<Result<Vec<_>, _>>()?,
            }))
            .collect::<Result<Vec<_>, String>>()?,
    };

    Ok(DeepFriProof {
        root_f0: hex_to_hash(&s.root_f0)?,
        roots: s.roots.iter().map(|r| hex_to_hash(r)).collect::<Result<Vec<_>, _>>()?,
        layer_proofs,
        f0_openings: s.f0_openings.iter()
            .map(deserialize_merkle_opening)
            .collect::<Result<Vec<_>, _>>()?,
        queries: s.queries.iter()
            .map(deserialize_fri_query::<E>)
            .collect::<Result<Vec<_>, _>>()?,
        fz_per_layer: s.fz_per_layer.iter()
            .map(|v| hex_vec_to_ext::<E>(v))
            .collect::<Result<Vec<_>, _>>()?,
        final_poly_coeffs: s.final_poly_coeffs.iter()
            .map(|v| hex_vec_to_ext::<E>(v))
            .collect::<Result<Vec<_>, _>>()?,
        n0: s.n0,
        omega0: hex_to_f(&s.omega0)?,
        coeff_tuples: s.coeff_tuples.as_ref().map(|ct| {
            ct.iter()
                .map(|row| row.iter().map(|v| hex_vec_to_ext::<E>(v)).collect::<Result<Vec<_>, _>>())
                .collect::<Result<Vec<_>, _>>()
        }).transpose()?,
        coeff_root: s.coeff_root.as_ref().map(|r| hex_to_hash(r)).transpose()?,
        stir_coset_evals: s.stir_coset_evals.as_ref().map(|layers| {
            layers.iter()
                .map(|layer| layer.iter().map(|v| hex_vec_to_ext::<E>(v)).collect::<Result<Vec<_>, _>>())
                .collect::<Result<Vec<_>, _>>()
        }).transpose()?,
        stir_proximity_queries: s.stir_proximity_queries.as_ref().map(|qs| {
            qs.iter().map(deserialize_stir_query::<E>).collect::<Result<Vec<_>, _>>()
        }).transpose()?,
    })
}

fn deserialize_layer_open_payload<E: TowerField>(
    s: &SerializedLayerOpenPayload,
) -> Result<LayerOpenPayload<E>, String> {
    Ok(LayerOpenPayload {
        f_val: hex_vec_to_ext::<E>(&s.f_val)?,
        s_val: hex_vec_to_ext::<E>(&s.s_val)?,
        q_val: hex_vec_to_ext::<E>(&s.q_val)?,
    })
}

fn deserialize_fri_query<E: TowerField>(s: &SerializedFriQuery) -> Result<FriQueryPayload<E>, String> {
    Ok(FriQueryPayload {
        per_layer_refs: s.per_layer_refs.iter().map(|r| LayerQueryRef {
            i: r.i,
            child_pos: r.child_pos,
            parent_index: r.parent_index,
            parent_pos: r.parent_pos,
        }).collect(),
        per_layer_payloads: s.per_layer_payloads.iter()
            .map(deserialize_layer_open_payload::<E>)
            .collect::<Result<Vec<_>, _>>()?,
        f0_opening: deserialize_merkle_opening(&s.f0_opening)?,
        final_index: s.final_index,
    })
}

fn deserialize_stir_query<E: TowerField>(
    s: &SerializedStirProximityQuery,
) -> Result<StirProximityPayload<E>, String> {
    Ok(StirProximityPayload {
        base_index: s.base_index,
        raw_query_index: s.raw_query_index,
        fiber_indices: s.fiber_indices.clone(),
        fiber_f_vals: s.fiber_f_vals.iter().map(|h| hex_to_f(h)).collect::<Result<Vec<_>, _>>()?,
        f0_packed_opening: deserialize_merkle_opening(&s.f0_packed_opening)?,
        f_next_val: hex_vec_to_ext::<E>(&s.f_next_val)?,
        layer1_opening: s.layer1_opening.as_ref().map(deserialize_merkle_opening).transpose()?,
    })
}
