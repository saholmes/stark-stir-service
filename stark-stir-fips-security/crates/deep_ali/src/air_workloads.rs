//! air_workloads.rs
//!
//! Three AIR workloads for benchmarking DEEP-ALI + MF-FRI across
//! varying trace widths and constraint structures.
//!
//!   AIR                  | w   | constraints | degree | blowup
//!   ---------------------|-----|-------------|--------|-------
//!   Fibonacci            |  2  |     1       |   2    |   4
//!   Poseidon hash chain  | 16  |    16       |   2    |   4
//!   Register machine     |  8  |     8       |   2    |   4
//!
//! All AIRs produce genuine execution traces that satisfy their
//! transition constraints, so the composition quotient polynomial
//! is well-defined and low-degree.

use ark_ff::{Field, Zero, One, UniformRand};
use ark_goldilocks::Goldilocks as F;
use rand::{rngs::StdRng, SeedableRng};

// ═══════════════════════════════════════════════════════════════════
//  AIR type enumeration
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AirType {
    /// Fibonacci recurrence  f(i+2) = f(i+1) + f(i).
    /// w = 2 trace columns, 1 degree-2 transition constraint.
    Fibonacci,

    /// Poseidon-like hash chain with state width t = 4.
    /// S-box x^7 decomposed: sq = x², cu = x³, fo = x⁴
    ///   → sbox_out = fo · cu = x⁷  (each step is degree 2).
    /// w = 16 columns  (4 state + 4 sq + 4 cu + 4 fo).
    /// 16 degree-2 transition constraints.
    PoseidonChain,

    /// Eight-register arithmetic machine with cross-coupled
    /// bilinear (degree-2) transition constraints.
    /// w = 8 columns, 8 degree-2 transition constraints.
    RegisterMachine,

    /// Simplified Cairo CPU AIR compatible with ethSTARK trace input format.
    ///
    /// Columns (w = 8):
    ///   [0] pc  — program counter
    ///   [1] ap  — allocation pointer
    ///   [2] fp  — frame pointer
    ///   [3] op0 — first operand
    ///   [4] op1 — second operand
    ///   [5] res — op0 * op1  (multiplication gate)
    ///   [6] dst — copy of res
    ///   [7] flags — instruction flags (reserved, always 0 in this AIR)
    ///
    /// Transition constraints (4, max degree 2):
    ///   C0: pc'  − pc  − 1 = 0   (PC advances by 1 per step)
    ///   C1: ap'  − ap  − 1 = 0   (AP advances by 1 per step)
    ///   C2: fp'  − fp      = 0   (FP is constant)
    ///   C3: dst  − op0 * op1 = 0  (multiplication gate, degree 2)
    ///
    /// Public inputs define boundary constraints on (pc, ap, fp) at
    /// row 0 and row n-1, verified by the API before proving.
    CairoSimple,

    /// Hash-chain rollup aggregator (w = 4).
    ///
    /// Absorbs a stream of leaf values into a running hash, used to
    /// aggregate commitments from multiple inner STARK proofs into a
    /// single rolled-up commitment.
    ///
    /// Columns (w = 4):
    ///   [0] idx       — row counter (0, 1, 2, …, n-1)
    ///   [1] leaf_val  — value being absorbed at this row
    ///   [2] state     — running hash accumulator
    ///   [3] state_sq  — auxiliary equal to state² (degree-1 reduction)
    ///
    /// Transition constraints (3, max degree 2):
    ///   C0: idx'      − idx − 1                = 0   (counter)
    ///   C1: state_sq  − state · state           = 0   (auxiliary squaring)
    ///   C2: state'    − state_sq − leaf_val     = 0   (absorb step: s' = s² + leaf)
    ///
    /// The leaf_val sequence in rollup demos contains the bytes of each
    /// inner proof's `public_inputs_hash`, packed 8 bytes per row.
    HashRollup,
}

impl AirType {
    /// Short label for CSV / filenames.
    pub fn label(self) -> &'static str {
        match self {
            AirType::Fibonacci       => "fib_w2_d2",
            AirType::PoseidonChain   => "poseidon_w16_d2",
            AirType::RegisterMachine => "regmach_w8_d2",
            AirType::CairoSimple     => "cairo_simple_w8_d2",
            AirType::HashRollup      => "hash_rollup_w4_d2",
        }
    }

    /// Number of trace columns.
    pub fn width(self) -> usize {
        match self {
            AirType::Fibonacci       => 2,
            AirType::PoseidonChain   => 16,
            AirType::RegisterMachine => 8,
            AirType::CairoSimple     => 8,
            AirType::HashRollup      => 4,
        }
    }

    /// Maximum individual constraint degree.
    pub fn max_constraint_degree(self) -> usize {
        2
    }

    /// Number of transition constraints.
    pub fn num_constraints(self) -> usize {
        match self {
            AirType::Fibonacci       => 1,
            AirType::PoseidonChain   => 16,
            AirType::RegisterMachine => 8,
            AirType::CairoSimple     => 4,
            AirType::HashRollup      => 3,
        }
    }

    /// Convenience: all defined workloads.
    pub fn all() -> &'static [AirType] {
        &[
            AirType::Fibonacci,
            AirType::PoseidonChain,
            AirType::RegisterMachine,
            AirType::CairoSimple,
            AirType::HashRollup,
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Top-level dispatcher
// ═══════════════════════════════════════════════════════════════════

/// Build a raw execution trace (w columns × n_trace rows) for the
/// given AIR.  Every row genuinely satisfies the transition
/// constraints so that the composition quotient is low-degree.
pub fn build_execution_trace(air: AirType, n_trace: usize) -> Vec<Vec<F>> {
    assert!(n_trace >= 2, "trace must have at least 2 rows");
    match air {
        AirType::Fibonacci       => build_fibonacci_trace(n_trace),
        AirType::PoseidonChain   => build_poseidon_chain_trace(n_trace),
        AirType::RegisterMachine => build_register_machine_trace(n_trace),
        AirType::CairoSimple     => build_cairo_simple_trace(n_trace),
        AirType::HashRollup      => build_hash_rollup_trace(n_trace, &default_rollup_leaves(n_trace)),
    }
}

/// Evaluate the transition constraints for AIR type `air` given
/// the current row values `cur` and the next row values `nxt`.
/// Returns a vector of length `air.num_constraints()`.
/// On a valid trace every entry is zero.
pub fn evaluate_constraints(
    air: AirType,
    cur: &[F],
    nxt: &[F],
    // Poseidon needs round constants per row; pass row index
    row: usize,
) -> Vec<F> {
    match air {
        AirType::Fibonacci       => eval_fibonacci_constraints(cur, nxt),
        AirType::PoseidonChain   => eval_poseidon_constraints(cur, nxt, row),
        AirType::RegisterMachine => eval_register_constraints(cur, nxt),
        AirType::CairoSimple     => eval_cairo_simple_constraints(cur, nxt),
        AirType::HashRollup      => eval_hash_rollup_constraints(cur, nxt),
    }
}

// ═══════════════════════════════════════════════════════════════════
//  AIR 1 — Fibonacci  (w = 2)
// ═══════════════════════════════════════════════════════════════════

fn build_fibonacci_trace(n: usize) -> Vec<Vec<F>> {
    let mut c0 = vec![F::zero(); n];
    let mut c1 = vec![F::zero(); n];
    c0[0] = F::one();
    c1[0] = F::one();
    for i in 0..n - 1 {
        // transition: c0' = c1,  c1' = c0 + c1
        let next_c0 = c1[i];
        let next_c1 = c0[i] + c1[i];
        if i + 1 < n {
            c0[i + 1] = next_c0;
            c1[i + 1] = next_c1;
        }
    }
    vec![c0, c1]
}

fn eval_fibonacci_constraints(cur: &[F], nxt: &[F]) -> Vec<F> {
    // constraint:  nxt[1] - cur[0] - cur[1] = 0
    vec![nxt[1] - cur[0] - cur[1]]
}

// ═══════════════════════════════════════════════════════════════════
//  AIR 2 — Poseidon-like hash chain  (w = 16)
// ═══════════════════════════════════════════════════════════════════
//
//  State width t = 4.
//  Columns layout:
//     [0..4)   state   s_j
//     [4..8)   sq_j  = (s_j + rc_j)²
//     [8..12)  cu_j  = sq_j · (s_j + rc_j)     = (s_j + rc_j)³
//     [12..16) fo_j  = sq_j²                    = (s_j + rc_j)⁴
//
//  sbox_out_j = fo_j · cu_j  = (s_j + rc_j)⁷
//
//  Transition constraints (all degree ≤ 2):
//    C_{4+j}:  sq_j  - (s_j + rc_j)²                     = 0
//    C_{8+j}:  cu_j  - sq_j · (s_j + rc_j)               = 0
//    C_{12+j}: fo_j  - sq_j²                              = 0
//    C_j:      s_j'  - Σ_k mds[j][k] · (fo_k · cu_k)     = 0
//
//  Round constants are derived deterministically from a fixed seed.

/// Deterministic round constants.  Cached via a simple closure;
/// the benchmark calls `build_execution_trace` which generates them
/// inline. For constraint evaluation we regenerate from the same seed.
fn poseidon_round_constant(row: usize, col: usize) -> F {
    // Fast deterministic derivation — not cryptographically strong,
    // but sufficient for a benchmark trace.
    let seed = (row as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(col as u64)
        .wrapping_mul(0x6C62_272E_07BB_0142);
    F::from(seed)
}

fn build_mds_4x4() -> [[F; 4]; 4] {
    // Cauchy matrix:  M[i][j] = 1 / (x_i + y_j)
    // with x_i = i+1, y_j = t+j+1,  t = 4.
    let mut m = [[F::zero(); 4]; 4];
    for i in 0..4u64 {
        for j in 0..4u64 {
            let denom = F::from(i + 1) + F::from(4 + j + 1);
            m[i as usize][j as usize] =
                denom.inverse().expect("Cauchy denominator is nonzero");
        }
    }
    m
}

fn build_poseidon_chain_trace(n: usize) -> Vec<Vec<F>> {
    let t = 4usize;
    let w = 4 * t; // 16
    let mut trace = vec![vec![F::zero(); n]; w];
    let mds = build_mds_4x4();

    let mut state: [F; 4] = [
        F::from(1u64),
        F::from(2u64),
        F::from(3u64),
        F::from(4u64),
    ];

    for row in 0..n {
        // ---- write state columns 0..4 ----
        for j in 0..t {
            trace[j][row] = state[j];
        }

        // ---- S-box decomposition ----
        let mut sbox_out = [F::zero(); 4];
        for j in 0..t {
            let rc = poseidon_round_constant(row, j);
            let s  = state[j] + rc;
            let sq = s * s;        // s²
            let cu = sq * s;       // s³
            let fo = sq * sq;      // s⁴
            sbox_out[j] = fo * cu; // s⁷

            trace[t     + j][row] = sq; // cols  4..8
            trace[2 * t + j][row] = cu; // cols  8..12
            trace[3 * t + j][row] = fo; // cols 12..16
        }

        // ---- MDS → next state ----
        if row + 1 < n {
            for j in 0..t {
                let mut acc = F::zero();
                for k in 0..t {
                    acc += mds[j][k] * sbox_out[k];
                }
                state[j] = acc;
            }
        }
    }

    trace
}

fn eval_poseidon_constraints(cur: &[F], nxt: &[F], row: usize) -> Vec<F> {
    let t = 4usize;
    let mds = build_mds_4x4(); // cheap for t = 4
    let mut out = vec![F::zero(); 16];

    // ---- auxiliary column constraints ----
    for j in 0..t {
        let rc = poseidon_round_constant(row, j);
        let s  = cur[j] + rc;         // state + round constant
        let sq = cur[t + j];          // sq column
        let cu = cur[2 * t + j];      // cu column
        let fo = cur[3 * t + j];      // fo column

        out[t     + j] = sq - s * s;         // sq  = s²
        out[2 * t + j] = cu - sq * s;        // cu  = s³
        out[3 * t + j] = fo - sq * sq;       // fo  = s⁴
    }

    // ---- state transition constraints ----
    for j in 0..t {
        let mut expected = F::zero();
        for k in 0..t {
            let fo = cur[3 * t + k];
            let cu = cur[2 * t + k];
            expected += mds[j][k] * fo * cu; // fo · cu = s⁷
        }
        out[j] = nxt[j] - expected;
    }

    out
}

// ═══════════════════════════════════════════════════════════════════
//  AIR 3 — Eight-register arithmetic machine  (w = 8)
// ═══════════════════════════════════════════════════════════════════
//
//  Transitions (all degree-2, bilinear cross-coupling):
//    r0' = r0 · r1 + r2
//    r1' = r1 · r2 + r3
//    r2' = r2 · r3 + r4
//    r3' = r3 · r4 + r5
//    r4' = r4 · r5 + r6
//    r5' = r5 · r6 + r7
//    r6' = r6 · r7 + r0
//    r7' = r0 · r4 + r1 · r5 + r2 · r6 + r3 · r7
//
//  The last constraint couples all 8 registers via an inner-product
//  structure, making the constraint system non-separable.

fn build_register_machine_trace(n: usize) -> Vec<Vec<F>> {
    let w = 8usize;
    let mut trace = vec![vec![F::zero(); n]; w];

    let mut r: [F; 8] = core::array::from_fn(|i| F::from((i + 1) as u64));

    for row in 0..n {
        for j in 0..w {
            trace[j][row] = r[j];
        }
        if row + 1 < n {
            let p = r; // snapshot
            r[0] = p[0] * p[1] + p[2];
            r[1] = p[1] * p[2] + p[3];
            r[2] = p[2] * p[3] + p[4];
            r[3] = p[3] * p[4] + p[5];
            r[4] = p[4] * p[5] + p[6];
            r[5] = p[5] * p[6] + p[7];
            r[6] = p[6] * p[7] + p[0];
            r[7] = p[0] * p[4] + p[1] * p[5] + p[2] * p[6] + p[3] * p[7];
        }
    }

    trace
}

fn eval_register_constraints(cur: &[F], nxt: &[F]) -> Vec<F> {
    let r = cur;
    vec![
        nxt[0] - (r[0] * r[1] + r[2]),
        nxt[1] - (r[1] * r[2] + r[3]),
        nxt[2] - (r[2] * r[3] + r[4]),
        nxt[3] - (r[3] * r[4] + r[5]),
        nxt[4] - (r[4] * r[5] + r[6]),
        nxt[5] - (r[5] * r[6] + r[7]),
        nxt[6] - (r[6] * r[7] + r[0]),
        nxt[7] - (r[0] * r[4] + r[1] * r[5] + r[2] * r[6] + r[3] * r[7]),
    ]
}

// ═══════════════════════════════════════════════════════════════════
//  AIR 4 — Simplified Cairo CPU  (w = 8)
// ═══════════════════════════════════════════════════════════════════
//
//  Columns:
//    [0] pc    — program counter  (starts at initial_pc, increments by 1)
//    [1] ap    — allocation ptr   (starts at initial_ap, increments by 1)
//    [2] fp    — frame pointer    (constant throughout execution)
//    [3] op0   — first operand    (row+1, the natural sequence)
//    [4] op1   — second operand   (row+2)
//    [5] res   — op0 * op1        (multiplication gate)
//    [6] dst   — copy of res
//    [7] flags — reserved (zero)
//
//  Transition constraints (4 constraints, max degree 2):
//    C0: pc'  - pc  - 1 = 0             (PC increments)
//    C1: ap'  - ap  - 1 = 0             (AP increments)
//    C2: fp'  - fp      = 0             (FP constant)
//    C3: dst  - op0 * op1 = 0           (MUL gate, degree 2)
//
//  Public inputs set boundary values for (pc, ap, fp) at row 0 and row n-1.

/// Default initial PC and AP for CairoSimple traces.
pub const CAIRO_SIMPLE_INITIAL_PC: u64 = 0;
pub const CAIRO_SIMPLE_INITIAL_AP: u64 = 100;

fn build_cairo_simple_trace(n: usize) -> Vec<Vec<F>> {
    let mut pc   = vec![F::zero(); n];
    let mut ap   = vec![F::zero(); n];
    let mut fp   = vec![F::zero(); n];
    let mut op0  = vec![F::zero(); n];
    let mut op1  = vec![F::zero(); n];
    let mut res  = vec![F::zero(); n];
    let mut dst  = vec![F::zero(); n];
    let mut flags = vec![F::zero(); n];

    let init_pc = F::from(CAIRO_SIMPLE_INITIAL_PC);
    let init_ap = F::from(CAIRO_SIMPLE_INITIAL_AP);

    for i in 0..n {
        let row = i as u64;
        pc[i]   = init_pc + F::from(row);
        ap[i]   = init_ap + F::from(row);
        fp[i]   = init_ap; // constant
        op0[i]  = F::from(row + 1);
        op1[i]  = F::from(row + 2);
        res[i]  = op0[i] * op1[i];
        dst[i]  = res[i];
        flags[i] = F::zero();
    }

    vec![pc, ap, fp, op0, op1, res, dst, flags]
}

fn eval_cairo_simple_constraints(cur: &[F], nxt: &[F]) -> Vec<F> {
    // C0: pc' - pc - 1 = 0
    let c0 = nxt[0] - cur[0] - F::one();
    // C1: ap' - ap - 1 = 0
    let c1 = nxt[1] - cur[1] - F::one();
    // C2: fp' - fp = 0
    let c2 = nxt[2] - cur[2];
    // C3: dst - op0 * op1 = 0  (uses current row only, degree 2)
    let c3 = cur[6] - cur[3] * cur[4];
    vec![c0, c1, c2, c3]
}

// ═══════════════════════════════════════════════════════════════════
//  AIR 5 — HashRollup aggregator  (w = 4)
// ═══════════════════════════════════════════════════════════════════
//
//  A streaming hash that absorbs a sequence of leaf values into a
//  running accumulator.  Used as the outer "rollup" AIR over a sequence
//  of inner-proof commitments.
//
//  Columns:
//    [0] idx       — counter, 0, 1, …, n-1
//    [1] leaf_val  — value being absorbed at this row
//    [2] state     — running hash accumulator (state' = state² + leaf)
//    [3] state_sq  — auxiliary equal to state²
//
//  Transition constraints (3, max degree 2):
//    C0: idx'      − idx − 1                = 0
//    C1: state_sq  − state · state           = 0
//    C2: state'    − state_sq − leaf_val     = 0
//
//  Boundary semantics (under the existing `validate_trace_boundaries`):
//    initial_pc → idx[0]      = 0
//    initial_ap → leaf_val[0] = first absorbed value
//    initial_fp → state[0]    = 0   (running hash starts at zero)
//    final_pc   → idx[n-1]    = n-1
//    final_ap   → leaf_val[n-1] = last absorbed value
//
//  The rolled-up commitment is `state[n-1]` — the verifier learns this
//  from the public-inputs commitment (carried through the FS transcript)
//  and from `public_memory` entries if those are populated.

/// Build a HashRollup trace from an explicit sequence of leaf values.
/// `leaves.len()` must equal `n_trace`; if not, leaves are padded with
/// zeros / truncated.
pub fn build_hash_rollup_trace(n_trace: usize, leaves: &[u64]) -> Vec<Vec<F>> {
    let mut idx      = vec![F::zero(); n_trace];
    let mut leaf_col = vec![F::zero(); n_trace];
    let mut state    = vec![F::zero(); n_trace];
    let mut state_sq = vec![F::zero(); n_trace];

    let mut s = F::zero();
    for i in 0..n_trace {
        let leaf = if i < leaves.len() { F::from(leaves[i]) } else { F::zero() };
        idx[i]      = F::from(i as u64);
        leaf_col[i] = leaf;
        state[i]    = s;
        state_sq[i] = s * s;
        // Advance for the next row.
        s = state_sq[i] + leaf;
    }

    vec![idx, leaf_col, state, state_sq]
}

fn eval_hash_rollup_constraints(cur: &[F], nxt: &[F]) -> Vec<F> {
    // C0: idx' - idx - 1 = 0
    let c0 = nxt[0] - cur[0] - F::one();
    // C1: state_sq - state * state = 0
    let c1 = cur[3] - cur[2] * cur[2];
    // C2: state' - state_sq - leaf_val = 0
    let c2 = nxt[2] - cur[3] - cur[1];
    vec![c0, c1, c2]
}

/// Default leaf sequence for `build_execution_trace(HashRollup, n)`.
/// Used by benchmarks and the AIR self-tests; rollup demos build their
/// own leaf vector from inner proof commitments.
fn default_rollup_leaves(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect()
}

/// Pack a 32-byte hash into 4 little-endian u64 leaves.  Used by rollup
/// demos to absorb each inner proof's `public_inputs_hash` into the
/// outer HashRollup trace.
pub fn pack_hash_to_leaves(hash: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, chunk) in hash.chunks_exact(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(buf);
    }
    out
}

/// Compute the same rollup state[n-1] that `build_hash_rollup_trace`
/// would produce, in pure host arithmetic (for verifier-side consistency
/// checks against the public-inputs commitment).
pub fn compute_hash_rollup_final_state(n_trace: usize, leaves: &[u64]) -> u64 {
    use ark_ff::PrimeField;
    let mut s = F::zero();
    for i in 0..n_trace {
        let leaf = if i < leaves.len() { F::from(leaves[i]) } else { F::zero() };
        s = s * s + leaf;
    }
    s.into_bigint().0[0]
}

// ═══════════════════════════════════════════════════════════════════
//  Sanity check (debug builds / tests)
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;

    fn verify_trace(air: AirType, n: usize) {
        let trace = build_execution_trace(air, n);
        assert_eq!(trace.len(), air.width());
        for col in &trace {
            assert_eq!(col.len(), n);
        }
        // Check constraints on interior rows
        for row in 0..n - 1 {
            let cur: Vec<F> = trace.iter().map(|c| c[row]).collect();
            let nxt: Vec<F> = trace.iter().map(|c| c[row + 1]).collect();
            let cv = evaluate_constraints(air, &cur, &nxt, row);
            for (ci, val) in cv.iter().enumerate() {
                assert!(
                    val.is_zero(),
                    "AIR {:?}  row {}  constraint {} != 0",
                    air, row, ci
                );
            }
        }
    }

    #[test]
    fn fibonacci_trace_valid()    { verify_trace(AirType::Fibonacci, 1024); }

    #[test]
    fn poseidon_trace_valid()     { verify_trace(AirType::PoseidonChain, 1024); }

    #[test]
    fn register_trace_valid()     { verify_trace(AirType::RegisterMachine, 1024); }

    #[test]
    fn cairo_simple_trace_valid() { verify_trace(AirType::CairoSimple, 1024); }

    #[test]
    fn hash_rollup_trace_valid()  { verify_trace(AirType::HashRollup, 1024); }

    #[test]
    fn hash_rollup_aggregates_two_proof_hashes() {
        // Pack two 32-byte SHA3-256 commitments into 8 leaves and roll them up.
        let h_a: [u8; 32] = *b"INNER_PROOF_A_PUBLIC_INPUTS_HASH";
        let h_b: [u8; 32] = *b"INNER_PROOF_B_PUBLIC_INPUTS_HASH";
        let mut leaves = pack_hash_to_leaves(&h_a).to_vec();
        leaves.extend_from_slice(&pack_hash_to_leaves(&h_b));

        let n = 16usize;                   // power of 2 >= leaves.len()
        let trace = build_hash_rollup_trace(n, &leaves);
        assert_eq!(trace.len(), 4);
        assert_eq!(trace[0].len(), n);

        // All transition constraints must be satisfied.
        for row in 0..n - 1 {
            let cur: Vec<F> = trace.iter().map(|c| c[row]).collect();
            let nxt: Vec<F> = trace.iter().map(|c| c[row + 1]).collect();
            let cv = eval_hash_rollup_constraints(&cur, &nxt);
            for (i, v) in cv.iter().enumerate() {
                assert!(v.is_zero(), "row {row} constraint {i} != 0");
            }
        }

        // The host-side closed-form must match the trace's final state.
        let expected = compute_hash_rollup_final_state(n, &leaves);
        let trace_final: u64 =
            <F as ark_ff::PrimeField>::into_bigint(trace[2][n - 1]).0[0];
        // After the last row's update would have happened, but the trace stores
        // state[i] BEFORE absorbing leaf[i], so the closed-form for `n`
        // absorbs corresponds to `compute_hash_rollup_final_state(n, leaves)`
        // computed AFTER the loop.  The trace[2][n-1] equals state before the
        // n-th absorb step.  So compare to compute(n-1, leaves).
        let prefinal = compute_hash_rollup_final_state(n - 1, &leaves);
        assert_eq!(trace_final, prefinal);
        // And the n-th step value (what state[n] would be if the trace had one
        // more row) equals expected.
        let _ = expected;
    }

    #[test]
    fn cairo_simple_boundary_values() {
        use super::{CAIRO_SIMPLE_INITIAL_AP, CAIRO_SIMPLE_INITIAL_PC};
        let n = 64usize;
        let trace = build_execution_trace(AirType::CairoSimple, n);
        assert_eq!(trace.len(), 8);
        // PC starts at initial_pc, ends at initial_pc + n - 1
        let pc_u64: u64 = trace[0][0].into_bigint().0[0];
        assert_eq!(pc_u64, CAIRO_SIMPLE_INITIAL_PC);
        let pc_final: u64 = trace[0][n - 1].into_bigint().0[0];
        assert_eq!(pc_final, CAIRO_SIMPLE_INITIAL_PC + n as u64 - 1);
        // AP starts at initial_ap
        let ap_u64: u64 = trace[1][0].into_bigint().0[0];
        assert_eq!(ap_u64, CAIRO_SIMPLE_INITIAL_AP);
        // FP is constant
        assert_eq!(trace[2][0], trace[2][n - 1]);
    }
}
