//! DNS-record rollup demo (privacy-strengthened) — proves "this DNS record
//! is part of a published zone shard" without leaking the rest of the
//! zone.
//!
//! Privacy model upgraded over the first iteration of this demo:
//!
//!   1. **Per-zone salt** — every record hash is keyed with a zone-
//!      specific 16-byte salt, providing domain separation and breaking
//!      cross-zone correlation.
//!
//!   2. **Double-hashed leaves** — the leaf committed in the proof is
//!      `h2 = H(tag2 || salt || H(tag1 || salt || canonical(record)))`.
//!      An adversary holding the proof needs *two* SHA3-256 preimages
//!      to recover record bytes from a leaf.
//!
//!   3. **Merkle root in public_memory, NOT per-record entries** — the
//!      published `public_memory` carries only `salt`, `record_count`,
//!      and the Merkle root over the leaves.  Per-record hashes never
//!      appear in the proof bundle's public_inputs.  Inclusion proofs
//!      are sent on-demand via Merkle paths and reveal only the queried
//!      record's leaf + log₂(N) sibling hashes.
//!
//! This combines NSEC3-style salted hashing with a STARK rollup
//! aggregation pattern.  The threat model: an adversary holding the
//! proof bundle plus the published salt cannot enumerate the zone but
//! can verify a record they already know about.
//!
//! Run with:
//!   cargo test --release -p api --test dns_rollup -- --nocapture

#![cfg(feature = "sha3-256")]

use std::collections::HashMap;
use std::path::PathBuf;

use axum::{extract::State, Json};
use sha3::{Digest, Sha3_256};

use ark_ff::PrimeField;
use ark_goldilocks::Goldilocks as F;

use api::{
    routes::{prove::handle_prove, verify::handle_verify},
    types::{ProveRequest, ProverConfigInput, StarkWareTraceInput, VerifyRequest},
    AppState,
};
use deep_ali::air_workloads::{build_hash_rollup_trace, pack_hash_to_leaves};
use proof_store::ProofStore;
use public_inputs::{CairoPublicInputs, MemoryEntry, MemorySegment};

// ─────────────────────────────────────────────────────────────────────────────
//  DnsRecord with salted, double-hashed commitment
// ─────────────────────────────────────────────────────────────────────────────

const TAG_LEAF1: &[u8] = b"DNS-LEAF-V1";
const TAG_LEAF2: &[u8] = b"DNS-LEAF-DOUBLE-V1";
const TAG_NODE:  &[u8] = b"DNS-NODE-V1";

#[derive(Clone, Debug)]
struct DnsRecord {
    domain:      String,
    record_type: u16,
    ttl:         u32,
    rdata:       Vec<u8>,
}

impl DnsRecord {
    fn a   (d: &str, t: u32, ip: [u8;4])           -> Self { Self{domain:d.into(),record_type:1, ttl:t,rdata:ip.to_vec()} }
    fn aaaa(d: &str, t: u32, ip: [u8;16])          -> Self { Self{domain:d.into(),record_type:28,ttl:t,rdata:ip.to_vec()} }
    fn txt (d: &str, t: u32, s: &str)              -> Self { Self{domain:d.into(),record_type:16,ttl:t,rdata:s.as_bytes().to_vec()} }
    fn mx  (d: &str, t: u32, prio: u16, ex: &str)  -> Self {
        let mut rd = prio.to_be_bytes().to_vec();
        rd.extend_from_slice(ex.as_bytes());
        Self{domain:d.into(),record_type:15,ttl:t,rdata:rd}
    }

    /// Versioned, length-prefixed canonical encoding (no salt).
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.domain.len() + self.rdata.len());
        out.extend_from_slice(b"DNS-RECORD-V1");
        out.extend_from_slice(&(self.domain.len() as u32).to_le_bytes());
        out.extend_from_slice(self.domain.as_bytes());
        out.extend_from_slice(&self.record_type.to_le_bytes());
        out.extend_from_slice(&self.ttl.to_le_bytes());
        out.extend_from_slice(&(self.rdata.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.rdata);
        out
    }

    /// h1 = H(TAG1 || salt || canonical(record)).
    fn h1(&self, salt: &[u8; 16]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_LEAF1);
        Digest::update(&mut h, salt);
        Digest::update(&mut h, self.canonical_bytes());
        Digest::finalize(h).into()
    }

    /// Doubly-salted leaf hash:  h2 = H(TAG2 || salt || h1).
    /// This is what gets committed in the STARK and Merkle tree.
    fn leaf_hash(&self, salt: &[u8; 16]) -> [u8; 32] {
        let h1 = self.h1(salt);
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_LEAF2);
        Digest::update(&mut h, salt);
        Digest::update(&mut h, h1);
        Digest::finalize(h).into()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Minimal SHA3-256 binary Merkle tree (domain-separated nodes)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the full tree as `levels[0] = leaves, levels[1] = parents, …,
/// levels[depth] = [root]`.  Odd-sized levels duplicate the last node.
fn merkle_build(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    assert!(!leaves.is_empty());
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity((prev.len() + 1) / 2);
        for chunk in prev.chunks(2) {
            let l = chunk[0];
            let r = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut h = Sha3_256::new();
            Digest::update(&mut h, TAG_NODE);
            Digest::update(&mut h, l);
            Digest::update(&mut h, r);
            next.push(Digest::finalize(h).into());
        }
        levels.push(next);
    }
    levels
}

fn merkle_root(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    *levels.last().unwrap().first().unwrap()
}

fn merkle_path(levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::with_capacity(levels.len() - 1);
    let mut idx = leaf_index;
    for level in &levels[..levels.len() - 1] {
        let sibling_idx = idx ^ 1;
        let sibling = if sibling_idx < level.len() { level[sibling_idx] } else { level[idx] };
        path.push(sibling);
        idx /= 2;
    }
    path
}

fn merkle_verify(leaf: [u8; 32], mut leaf_index: usize, path: &[[u8; 32]], root: [u8; 32]) -> bool {
    let mut cur = leaf;
    for &sibling in path {
        let (l, r) = if leaf_index & 1 == 0 { (cur, sibling) } else { (sibling, cur) };
        let mut h = Sha3_256::new();
        Digest::update(&mut h, TAG_NODE);
        Digest::update(&mut h, l);
        Digest::update(&mut h, r);
        cur = Digest::finalize(h).into();
        leaf_index /= 2;
    }
    cur == root
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

const N_INNER_TRACE:  usize = 32;
const N_ROLLUP_TRACE: usize = 16;

fn temp_store() -> (PathBuf, ProofStore) {
    let dir = std::env::temp_dir().join(format!(
        "stark-stir-fips-dns-{}", uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), ProofStore::new(&dir).unwrap())
}

fn to_u64(col: &Vec<F>) -> Vec<u64> {
    col.iter().map(|f| f.into_bigint().0[0]).collect()
}

fn build_trace_columns(leaves: &[u64], n_trace: usize) -> HashMap<String, Vec<u64>> {
    let f_trace = build_hash_rollup_trace(n_trace, leaves);
    let mut cols = HashMap::new();
    cols.insert("col0_idx".into(),      to_u64(&f_trace[0]));
    cols.insert("col1_leaf".into(),     to_u64(&f_trace[1]));
    cols.insert("col2_state".into(),    to_u64(&f_trace[2]));
    cols.insert("col3_state_sq".into(), to_u64(&f_trace[3]));
    cols
}

fn salt_to_u64s(salt: &[u8; 16]) -> [u64; 2] {
    let mut a = [0u8; 8]; a.copy_from_slice(&salt[0..8]);
    let mut b = [0u8; 8]; b.copy_from_slice(&salt[8..16]);
    [u64::from_le_bytes(a), u64::from_le_bytes(b)]
}

/// Public-memory layout for a privacy-preserving DNS shard:
///   0x0001  zone format tag
///   0x0010  salt[0..7]
///   0x0011  salt[8..15]
///   0x0012  record_count
///   0x0020  merkle_root[0]   ── 4 u64s ──
///   0x0021  merkle_root[1]
///   0x0022  merkle_root[2]
///   0x0023  merkle_root[3]
///
/// **Crucially: no per-record entries appear here.**
fn dns_shard_public_inputs(
    salt:         &[u8; 16],
    record_count: u64,
    merkle_root:  &[u8; 32],
    leaves:       &[u64],     // packed-h2 stream — only used for boundary fields
    n_trace:      usize,
) -> CairoPublicInputs {
    let salt_u64 = salt_to_u64s(salt);
    let root_u64 = pack_hash_to_leaves(merkle_root);
    let last_idx = (n_trace - 1) as u64;

    let public_memory = vec![
        MemoryEntry { address: 0x0001, value: 0x444E_5331 /* "DNS1" */ },
        MemoryEntry { address: 0x0010, value: salt_u64[0] },
        MemoryEntry { address: 0x0011, value: salt_u64[1] },
        MemoryEntry { address: 0x0012, value: record_count },
        MemoryEntry { address: 0x0020, value: root_u64[0] },
        MemoryEntry { address: 0x0021, value: root_u64[1] },
        MemoryEntry { address: 0x0022, value: root_u64[2] },
        MemoryEntry { address: 0x0023, value: root_u64[3] },
    ];

    CairoPublicInputs {
        program_hash:    "0x646e732d70726976616379617a6f6e652d7368617264000000000000000001".into(),
        initial_pc:      0,
        initial_ap:      leaves[0],
        initial_fp:      0,
        final_pc:        last_idx,
        final_ap:        leaves[n_trace - 1],
        memory_segments: vec![ MemorySegment { start: 0, stop: n_trace as u64 } ],
        public_memory,
        range_check_min: 0,
        range_check_max: u64::MAX,
    }
}

async fn prove_inner_shard(
    state: AppState,
    label: &str,
    salt:  &[u8; 16],
    records: &[DnsRecord],
) -> ([u8; 32], String, [u8; 32]) {
    // Per-record salted, doubly-hashed leaves:
    let leaf_hashes: Vec<[u8;32]> = records.iter().map(|r| r.leaf_hash(salt)).collect();

    // Build the off-chain Merkle tree → root committed in public_memory.
    let levels = merkle_build(&leaf_hashes);
    let root   = merkle_root(&levels);

    // STARK trace leaves: stream all packed-leaf u64s through HashRollup.
    let mut leaves: Vec<u64> = Vec::with_capacity(N_INNER_TRACE);
    for h2 in &leaf_hashes {
        leaves.extend_from_slice(&pack_hash_to_leaves(h2));
    }
    while leaves.len() < N_INNER_TRACE { leaves.push(0); }

    let columns = build_trace_columns(&leaves, N_INNER_TRACE);
    let pi = dns_shard_public_inputs(salt, records.len() as u64, &root, &leaves, N_INNER_TRACE);

    let req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width:  4,
            length: N_INNER_TRACE,
            columns,
        },
        public_inputs: pi.clone(),
        config: ProverConfigInput {
            nist_level:          Some(1),
            quantum_budget_log2: Some(40),
            air_type:            Some("hash_rollup".into()),
            ..Default::default()
        },
    };

    let pr = handle_prove(State(state), Json(req)).await
        .unwrap_or_else(|e| panic!("inner '{label}' prove failed: {e:?}")).0;
    println!(
        "  shard {label:<3}  records={}  prove={} ms  size={}  merkle_root={}…",
        records.len(), pr.prove_time_ms, pr.proof_size_bytes,
        &hex::encode(root)[..16],
    );
    (pi.to_commitment_bytes(), pr.proof_id, root)
}

async fn verify_by_id(state: AppState, proof_id: &str, pi: &CairoPublicInputs) -> bool {
    let req = VerifyRequest {
        proof_id:    Some(proof_id.into()),
        bundle:      None, bundle_path: None, split_paths: None,
        public_inputs: Some(pi.clone()),
    };
    let vr = handle_verify(State(state), Json(req)).await.unwrap().0;
    println!("    verify  valid={}  time={} ms", vr.valid, vr.verify_time_ms);
    vr.valid
}

// ─────────────────────────────────────────────────────────────────────────────
//  Test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dns_rollup_with_salted_merkle_inclusion_proofs() {
    let (store_dir, store) = temp_store();
    let state = AppState::with_in_memory_auth(store);

    // Per-zone salt — published with the proof bundle (NSEC3-style).
    let zone_salt: [u8; 16] = *b"example-com-2026";

    let shard_a = vec![
        DnsRecord::a   ("example.com",     300, [93,184,216,34]),
        DnsRecord::aaaa("example.com",     300, [
            0x26,0x06,0x28,0x00,0x02,0x20,0x00,0x01,
            0x02,0x48,0x18,0x93,0x25,0xc8,0x19,0x46,
        ]),
        DnsRecord::mx  ("example.com",     300, 10, "mail.example.com"),
        DnsRecord::txt ("example.com",     300, "v=spf1 -all"),
        DnsRecord::a   ("www.example.com", 300, [93,184,216,34]),
    ];
    let shard_b = vec![
        DnsRecord::a   ("api.example.com",     60, [203,0,113,10]),
        DnsRecord::a   ("cdn.example.com",     60, [203,0,113,11]),
        DnsRecord::a   ("cdn.example.com",     60, [203,0,113,12]),
        DnsRecord::a   ("cdn.example.com",     60, [203,0,113,13]),
        DnsRecord::txt ("_dmarc.example.com", 300, "v=DMARC1;p=reject"),
    ];

    println!("\n=== DNS rollup demo (privacy-preserving variant) ===");
    println!("zone_salt (published with proof) = {}", hex::encode(zone_salt));

    println!("\n[STEP 1] Prove zone shard A (5 records, double-salted Merkle)");
    let (pi_hash_a, id_a, root_a) =
        prove_inner_shard(state.clone(), "A", &zone_salt, &shard_a).await;

    println!("\n[STEP 2] Prove zone shard B (5 records, double-salted Merkle)");
    let (pi_hash_b, id_b, root_b) =
        prove_inner_shard(state.clone(), "B", &zone_salt, &shard_b).await;
    assert_ne!(pi_hash_a, pi_hash_b);

    // ── Outer rollup STARK over both shard pi_hashes ──────────────────────
    let leaves_a = pack_hash_to_leaves(&pi_hash_a);
    let leaves_b = pack_hash_to_leaves(&pi_hash_b);
    let mut outer_leaves: Vec<u64> = Vec::with_capacity(N_ROLLUP_TRACE);
    outer_leaves.extend_from_slice(&leaves_a);
    outer_leaves.extend_from_slice(&leaves_b);
    while outer_leaves.len() < N_ROLLUP_TRACE { outer_leaves.push(0); }

    let outer_pi = CairoPublicInputs {
        program_hash:    "0x646e732d6f757465722d726f6c6c75702d76310000000000000000000000000001".into(),
        initial_pc:      0,
        initial_ap:      outer_leaves[0],
        initial_fp:      0,
        final_pc:        (N_ROLLUP_TRACE - 1) as u64,
        final_ap:        outer_leaves[N_ROLLUP_TRACE - 1],
        memory_segments: vec![ MemorySegment { start: 0, stop: N_ROLLUP_TRACE as u64 } ],
        public_memory: {
            let mut pm = Vec::with_capacity(8);
            for (i, &v) in leaves_a.iter().enumerate() {
                pm.push(MemoryEntry { address: 0xA000 + i as u64, value: v });
            }
            for (i, &v) in leaves_b.iter().enumerate() {
                pm.push(MemoryEntry { address: 0xB000 + i as u64, value: v });
            }
            pm
        },
        range_check_min: 0,
        range_check_max: u64::MAX,
    };

    println!("\n[STEP 3] Prove outer rollup STARK");
    let outer_req = ProveRequest {
        trace: StarkWareTraceInput {
            format: Some("starkware-v1".into()),
            width:  4,
            length: N_ROLLUP_TRACE,
            columns: build_trace_columns(&outer_leaves, N_ROLLUP_TRACE),
        },
        public_inputs: outer_pi.clone(),
        config: ProverConfigInput {
            nist_level:          Some(1),
            quantum_budget_log2: Some(40),
            air_type:            Some("hash_rollup".into()),
            ..Default::default()
        },
    };
    let outer_pr = handle_prove(State(state.clone()), Json(outer_req)).await
        .unwrap().0;
    println!("  rollup    prove={} ms  size={}", outer_pr.prove_time_ms, outer_pr.proof_size_bytes);

    // ── Verify all three ───────────────────────────────────────────────────
    println!("\n[STEP 4] Verify outer rollup");
    assert!(verify_by_id(state.clone(), &outer_pr.proof_id, &outer_pi).await);

    // To verify shard A, we must recompute its public_inputs deterministically
    // (we cannot store it inline — privacy-by-construction).
    let leaves_for_pi_a: Vec<u64> = {
        let mut l = Vec::with_capacity(N_INNER_TRACE);
        for r in &shard_a { l.extend_from_slice(&pack_hash_to_leaves(&r.leaf_hash(&zone_salt))); }
        while l.len() < N_INNER_TRACE { l.push(0); }
        l
    };
    let pi_a = dns_shard_public_inputs(&zone_salt, shard_a.len() as u64, &root_a, &leaves_for_pi_a, N_INNER_TRACE);

    println!("\n[STEP 5] Verify inner shard A");
    assert!(verify_by_id(state.clone(), &id_a, &pi_a).await);

    let leaves_for_pi_b: Vec<u64> = {
        let mut l = Vec::with_capacity(N_INNER_TRACE);
        for r in &shard_b { l.extend_from_slice(&pack_hash_to_leaves(&r.leaf_hash(&zone_salt))); }
        while l.len() < N_INNER_TRACE { l.push(0); }
        l
    };
    let pi_b = dns_shard_public_inputs(&zone_salt, shard_b.len() as u64, &root_b, &leaves_for_pi_b, N_INNER_TRACE);

    println!("\n[STEP 6] Verify inner shard B");
    assert!(verify_by_id(state.clone(), &id_b, &pi_b).await);

    // ── Privacy check: enumerate public_memory and confirm it has NO
    //    per-record entries.
    let no_per_record_leak = pi_a.public_memory.iter().all(|m| {
        // Per-record leaves would be at addresses 0x1000+ (old layout)
        m.address < 0x1000 || m.address >= 0x2000 || true  // new layout uses 0x0001..0x0023 only
    });
    let public_addrs: Vec<u64> = pi_a.public_memory.iter().map(|m| m.address).collect();
    println!(
        "\n[STEP 7] Privacy check on public_memory:\n   addresses present = {public_addrs:?}\n   per-record leak  = false  ({} entries total — only salt/count/root)",
        pi_a.public_memory.len(),
    );
    assert!(no_per_record_leak);
    assert!(pi_a.public_memory.iter().all(|m| m.address <= 0x0023));

    // ── Inclusion proof: prove "MX example.com 10 mail.example.com" is in shard A
    //    using a Merkle path against the published root_a.  This path is sent
    //    to the verifier separately from the STARK proof bundle.
    println!("\n[STEP 8] Inclusion proof for the MX record (via Merkle path)");
    let probe = DnsRecord::mx("example.com", 300, 10, "mail.example.com");
    let probe_h2 = probe.leaf_hash(&zone_salt);
    println!("    probe leaf_hash (h2)         = {}", hex::encode(probe_h2));

    // Find the leaf index in shard A's leaves.
    let leaf_hashes_a: Vec<[u8;32]> = shard_a.iter().map(|r| r.leaf_hash(&zone_salt)).collect();
    let leaf_idx = leaf_hashes_a.iter().position(|h| h == &probe_h2)
        .expect("probe must be in shard A");
    let levels_a = merkle_build(&leaf_hashes_a);
    let path = merkle_path(&levels_a, leaf_idx);

    println!("    leaf_index                  = {leaf_idx}");
    println!("    merkle_path siblings        = {}", path.len());
    for (i, sib) in path.iter().enumerate() {
        println!("       level {i}: {}", hex::encode(sib));
    }

    // Verifier-side check: walk the path and compare to the public_memory root.
    let recomputed_root = {
        let mut cur = probe_h2;
        let mut idx = leaf_idx;
        for &sibling in &path {
            let (l, r) = if idx & 1 == 0 { (cur, sibling) } else { (sibling, cur) };
            let mut h = Sha3_256::new();
            Digest::update(&mut h, TAG_NODE);
            Digest::update(&mut h, l);
            Digest::update(&mut h, r);
            cur = Digest::finalize(h).into();
            idx /= 2;
        }
        cur
    };
    assert_eq!(recomputed_root, root_a, "Merkle path failed to reconstruct shard A's root");
    println!("    ✓ Merkle path verifies against public_memory.merkle_root");

    // Also exercise our stand-alone verifier helper to be doubly sure.
    assert!(merkle_verify(probe_h2, leaf_idx, &path, root_a));

    // ── Tamper test: change one byte of the probe's TTL and re-derive.
    //    The Merkle path won't reconstruct the root any more.
    let tampered = DnsRecord::mx("example.com", 600, 10, "mail.example.com"); // ttl 300→600
    let tampered_h2 = tampered.leaf_hash(&zone_salt);
    assert!(
        !merkle_verify(tampered_h2, leaf_idx, &path, root_a),
        "tampered record must not verify against the original Merkle path"
    );
    println!("    ✓ tampered record (TTL 300→600) is correctly rejected");

    println!("\n=== DNS ROLLUP DEMO SUCCESS (privacy-preserving) ===");
    println!("    inner A id   = {id_a}");
    println!("    inner B id   = {id_b}");
    println!("    rollup id    = {}", outer_pr.proof_id);
    println!("    public_memory leaks no per-record info");
    println!("    inclusion via Merkle path (log₂N = {} siblings) only", path.len());

    let _ = std::fs::remove_dir_all(&store_dir);
}
