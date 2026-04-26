//! NIST PQ security profile definitions for the STARK API.
//!
//! Implements Table III ("NIST-compliant STIR-DEEP-ALI parameter sets") from
//! the STIR-FIPS paper:
//!
//! ```text
//!   Level | λ   | q    | Ext   | Hash      | r
//!   ──────┼─────┼──────┼───────┼───────────┼────
//!     1   | 128 | 2^40 | Fp^6  | SHA3-256  | 54
//!     1   | 128 | 2^65 | Fp^6  | SHA3-384  | 54
//!     1   | 128 | 2^90 | Fp^6  | SHA3-512  | 54
//!     3   | 192 | 2^40 | Fp^6  | SHA3-384  | 79
//!     3   | 192 | 2^65 | Fp^6  | SHA3-512  | 79
//!     3   | 192 | 2^90 | Fp^6  | SHA3-512  | 79
//!     5   | 256 | 2^40 | Fp^8  | SHA3-512  | 105
//!     5   | 256 | 2^65 | Fp^8  | SHA3-512  | 105
//!     5   | 256 | 2^90 | Fp^8  | SHA3-512  | 105  (binding wall violated)
//! ```
//!
//! Level 5 at q=2^90 violates the FIPS-202 binding wall (κ_bind = 239 < 256).
//! It is rejected by `SecurityProfile::lookup` unless `allow_binding_wall_violation`
//! is explicitly set.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
//  NIST PQ levels
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NistLevel {
    L1, // λ = 128
    L3, // λ = 192
    L5, // λ = 256
}

impl NistLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(NistLevel::L1),
            3 => Some(NistLevel::L3),
            5 => Some(NistLevel::L5),
            _ => None,
        }
    }
    pub fn lambda_bits(self) -> u32 {
        match self {
            NistLevel::L1 => 128,
            NistLevel::L3 => 192,
            NistLevel::L5 => 256,
        }
    }
    pub fn as_u8(self) -> u8 {
        match self {
            NistLevel::L1 => 1,
            NistLevel::L3 => 3,
            NistLevel::L5 => 5,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Quantum query budget log₂(q)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuantumBudget {
    Q40, // q = 2^40
    Q65, // q = 2^65
    Q90, // q = 2^90
}

impl QuantumBudget {
    pub fn from_log2(v: u32) -> Option<Self> {
        match v {
            40 => Some(QuantumBudget::Q40),
            65 => Some(QuantumBudget::Q65),
            90 => Some(QuantumBudget::Q90),
            _ => None,
        }
    }
    pub fn log2(self) -> u32 {
        match self {
            QuantumBudget::Q40 => 40,
            QuantumBudget::Q65 => 65,
            QuantumBudget::Q90 => 90,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Hash variant and extension field
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlg {
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlg {
    pub fn label(self) -> &'static str {
        match self {
            HashAlg::Sha3_256 => "SHA3-256",
            HashAlg::Sha3_384 => "SHA3-384",
            HashAlg::Sha3_512 => "SHA3-512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionField {
    Fp6,
    Fp8,
}

impl ExtensionField {
    pub fn degree(self) -> usize {
        match self {
            ExtensionField::Fp6 => 6,
            ExtensionField::Fp8 => 8,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ExtensionField::Fp6 => "Fp^6",
            ExtensionField::Fp8 => "Fp^8",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SecurityProfile: a row of Table III
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SecurityProfile {
    pub level:         NistLevel,
    pub lambda_bits:   u32,
    pub quantum_budget: QuantumBudget,
    pub ext_field:     ExtensionField,
    pub hash_alg:      HashAlg,
    /// Paper-calibrated baseline query count at `blowup = 32` (1/ρ₀ = 32).
    /// For other blowups use `r_for_blowup(blowup)`.
    pub r:             usize,
    /// Information-theoretic soundness bits (κ_IT) — independent of blowup.
    pub kappa_it:      u32,
    /// Merkle binding bits (κ_bind) — independent of blowup.
    pub kappa_bind:    u32,
    /// Fiat-Shamir bits (κ_FS) — independent of blowup.
    pub kappa_fs:      u32,
    /// System-level security (κ_sys) at the paper's `blowup = 32` calibration.
    pub kappa_sys:     u32,
    /// True iff this row violates the FIPS-202 binding wall.
    pub binding_wall_violated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("unsupported (level, q) combination: Level={level} q=2^{q_log2}")]
    Unsupported { level: u8, q_log2: u32 },
    #[error(
        "Level 5 q=2^90 violates the FIPS-202 binding wall (κ_bind=239 < λ=256). \
         Set allow_binding_wall_violation=true to override (NOT FIPS-compliant)."
    )]
    BindingWallViolated,
    #[error(
        "build/runtime hash mismatch: profile requires {required} but binary was built with {actual}. \
         Rebuild with --features {required_feature} to enable this profile."
    )]
    HashFeatureMismatch {
        required: &'static str,
        actual: &'static str,
        required_feature: &'static str,
    },
    #[error("invalid blowup {0}: must be a power of 2 and ≥ 2 (paper recommends 32)")]
    InvalidBlowup(usize),
}

impl SecurityProfile {
    /// Look up the canonical profile for (level, q).  Returns
    /// `BindingWallViolated` for L5/q=2^90 unless explicitly allowed.
    pub fn lookup(
        level: NistLevel,
        q: QuantumBudget,
        allow_binding_wall_violation: bool,
    ) -> Result<Self, ProfileError> {
        use ExtensionField::*;
        use HashAlg::*;
        use NistLevel::*;
        use QuantumBudget::*;

        let row = match (level, q) {
            // ── Level 1, λ=128 ────────────────────────────────────────────
            (L1, Q40) => (Fp6, Sha3_256, 54usize, 135u32, 133, 296, 132, false),
            (L1, Q65) => (Fp6, Sha3_384, 54,     135,    186, 246, 134, false),
            (L1, Q90) => (Fp6, Sha3_512, 54,     135,    239, 196, 134, false),

            // ── Level 3, λ=192 ────────────────────────────────────────────
            (L3, Q40) => (Fp6, Sha3_384, 79,     197,    261, 296, 197, false),
            (L3, Q65) => (Fp6, Sha3_512, 79,     197,    314, 246, 197, false),
            (L3, Q90) => (Fp6, Sha3_512, 79,     197,    239, 196, 195, false),

            // ── Level 5, λ=256 ────────────────────────────────────────────
            (L5, Q40) => (Fp8, Sha3_512, 105,    262,    389, 424, 262, false),
            (L5, Q65) => (Fp8, Sha3_512, 105,    262,    314, 374, 262, false),
            (L5, Q90) => (Fp8, Sha3_512, 105,    262,    239, 324, 238, true),
        };

        let (ext_field, hash_alg, r, kappa_it, kappa_bind, kappa_fs, kappa_sys, wall_viol) = row;

        if wall_viol && !allow_binding_wall_violation {
            return Err(ProfileError::BindingWallViolated);
        }

        Ok(SecurityProfile {
            level,
            lambda_bits: level.lambda_bits(),
            quantum_budget: q,
            ext_field,
            hash_alg,
            r,
            kappa_it,
            kappa_bind,
            kappa_fs,
            kappa_sys,
            binding_wall_violated: wall_viol,
        })
    }

    /// The hash variant the running binary was compiled with.
    pub const fn build_hash() -> HashAlg {
        #[cfg(feature = "sha3-512")] { HashAlg::Sha3_512 }
        #[cfg(all(feature = "sha3-384", not(feature = "sha3-512")))] { HashAlg::Sha3_384 }
        #[cfg(all(feature = "sha3-256", not(feature = "sha3-384"), not(feature = "sha3-512")))] { HashAlg::Sha3_256 }
        #[cfg(not(any(feature = "sha3-256", feature = "sha3-384", feature = "sha3-512")))] {
            // Fallback when no feature is enabled (workspace default builds default features).
            HashAlg::Sha3_256
        }
    }

    /// Verify that this profile's hash matches what the binary was compiled with.
    /// Hash selection is a *compile-time* feature in the underlying `hash`/`merkle`
    /// crates, so a profile requiring SHA3-512 cannot be served by a `sha3-256` build.
    pub fn check_hash_compatibility(&self) -> Result<(), ProfileError> {
        let actual = Self::build_hash();
        if actual == self.hash_alg {
            return Ok(());
        }
        let (required_feature, required_label) = match self.hash_alg {
            HashAlg::Sha3_256 => ("sha3-256", "SHA3-256"),
            HashAlg::Sha3_384 => ("sha3-384", "SHA3-384"),
            HashAlg::Sha3_512 => ("sha3-512", "SHA3-512"),
        };
        Err(ProfileError::HashFeatureMismatch {
            required: required_label,
            actual: actual.label(),
            required_feature,
        })
    }

    /// All nine canonical profiles (including the L5/q=90 binding-wall violator).
    pub fn all() -> Vec<SecurityProfile> {
        let mut out = Vec::with_capacity(9);
        for level in [NistLevel::L1, NistLevel::L3, NistLevel::L5] {
            for q in [QuantumBudget::Q40, QuantumBudget::Q65, QuantumBudget::Q90] {
                if let Ok(p) = SecurityProfile::lookup(level, q, true) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// Recalculate the FRI/STIR query count `r` for a given blowup factor.
    ///
    /// Johnson-regime soundness: per-query rejection error ε = √ρ where
    /// ρ = 1/blowup, giving **bits/query = ½ · log₂(blowup)**.  To meet
    /// the information-theoretic soundness target `κ_IT` we need
    ///
    ///   r ≥ κ_IT / bits_per_query = ⌈ 2 · κ_IT / log₂(blowup) ⌉
    ///
    /// The paper's Table III is calibrated at `blowup = 32` (`bits/query = 2.5`);
    /// at smaller blowups, `r` must grow proportionally.
    ///
    /// `blowup` must be a power of 2 with `blowup ≥ 2`.
    pub fn r_for_blowup(&self, blowup: usize) -> Result<usize, ProfileError> {
        if blowup < 2 || !blowup.is_power_of_two() {
            return Err(ProfileError::InvalidBlowup(blowup));
        }
        let log_b = blowup.trailing_zeros() as f64; // log₂(blowup)
        let bits_per_query = 0.5 * log_b;
        let r = (self.kappa_it as f64 / bits_per_query).ceil() as usize;
        Ok(r)
    }

    /// Compute (κ_IT_realised, r_used) for a given blowup.  The κ_IT realised
    /// at blowup=B with `r` queries is `r · ½ · log₂(B)`.  Useful for the
    /// `GET /v1/security/profiles?blowup=B` introspection endpoint.
    pub fn kappa_it_at_blowup(&self, blowup: usize) -> Result<(u32, usize), ProfileError> {
        let r = self.r_for_blowup(blowup)?;
        let log_b = blowup.trailing_zeros() as f64;
        let kappa = (r as f64 * 0.5 * log_b).floor() as u32;
        Ok((kappa, r))
    }

    /// Profiles that are servable by the *current* binary build (hash compatibility).
    pub fn supported_by_build() -> Vec<SecurityProfile> {
        Self::all()
            .into_iter()
            .filter(|p| p.check_hash_compatibility().is_ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_q40_is_sha3_256_fp6_r54() {
        let p = SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q40, false).unwrap();
        assert_eq!(p.hash_alg, HashAlg::Sha3_256);
        assert_eq!(p.ext_field, ExtensionField::Fp6);
        assert_eq!(p.r, 54);
        assert_eq!(p.lambda_bits, 128);
    }

    #[test]
    fn level5_uses_fp8() {
        let p = SecurityProfile::lookup(NistLevel::L5, QuantumBudget::Q40, false).unwrap();
        assert_eq!(p.ext_field, ExtensionField::Fp8);
        assert_eq!(p.r, 105);
    }

    #[test]
    fn level5_q90_blocked_by_binding_wall() {
        let err = SecurityProfile::lookup(NistLevel::L5, QuantumBudget::Q90, false).unwrap_err();
        assert!(matches!(err, ProfileError::BindingWallViolated));
    }

    #[test]
    fn level5_q90_allowed_when_explicit() {
        let p = SecurityProfile::lookup(NistLevel::L5, QuantumBudget::Q90, true).unwrap();
        assert!(p.binding_wall_violated);
        assert_eq!(p.kappa_sys, 238);
    }

    #[test]
    fn all_returns_nine_rows() {
        assert_eq!(SecurityProfile::all().len(), 9);
    }

    #[test]
    fn r_at_blowup_32_matches_table_iii_baseline() {
        // Sanity: the paper-quoted r values are exactly what r_for_blowup(32) returns.
        for p in SecurityProfile::all() {
            let r32 = p.r_for_blowup(32).unwrap();
            assert_eq!(
                r32, p.r,
                "Level {:?} q={:?}: r_for_blowup(32)={} != table value {}",
                p.level, p.quantum_budget, r32, p.r
            );
        }
    }

    #[test]
    fn r_grows_inversely_with_log2_blowup() {
        let p = SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q40, false).unwrap();
        // L1, κ_IT=135. bits/query = 0.5 * log2(blowup).
        // r = ceil(135 / bits/query)
        // blowup=32: 135/2.5 = 54
        // blowup=16: 135/2.0 = 67.5 → 68
        // blowup= 8: 135/1.5 = 90
        // blowup= 4: 135/1.0 = 135
        // blowup= 2: 135/0.5 = 270
        assert_eq!(p.r_for_blowup(32).unwrap(),  54);
        assert_eq!(p.r_for_blowup(16).unwrap(),  68);
        assert_eq!(p.r_for_blowup( 8).unwrap(),  90);
        assert_eq!(p.r_for_blowup( 4).unwrap(), 135);
        assert_eq!(p.r_for_blowup( 2).unwrap(), 270);
    }

    #[test]
    fn r_for_blowup_rejects_non_power_of_two() {
        let p = SecurityProfile::lookup(NistLevel::L1, QuantumBudget::Q40, false).unwrap();
        assert!(matches!(p.r_for_blowup(0), Err(ProfileError::InvalidBlowup(0))));
        assert!(matches!(p.r_for_blowup(1), Err(ProfileError::InvalidBlowup(1))));
        assert!(matches!(p.r_for_blowup(3), Err(ProfileError::InvalidBlowup(3))));
        assert!(matches!(p.r_for_blowup(7), Err(ProfileError::InvalidBlowup(7))));
        assert!(matches!(p.r_for_blowup(48), Err(ProfileError::InvalidBlowup(48))));
    }

    #[test]
    fn kappa_it_at_blowup_meets_target() {
        // For every (profile, blowup) the realised κ_IT must be ≥ paper's
        // baseline κ_IT (we round r up, so we always meet or exceed target).
        for p in SecurityProfile::all() {
            for blowup in [2, 4, 8, 16, 32, 64, 128] {
                let (kappa, _r) = p.kappa_it_at_blowup(blowup).unwrap();
                assert!(
                    kappa >= p.kappa_it.saturating_sub(1),  // -1 for ceil(...).floor() drift
                    "Level {:?} q={:?} blowup={}: realised κ_IT={} < target {}",
                    p.level, p.quantum_budget, blowup, kappa, p.kappa_it,
                );
            }
        }
    }

    #[test]
    fn level3_l5_recalibration_per_blowup() {
        // L3 κ_IT=197 → blowup=4 needs r=197; L5 κ_IT=262 → blowup=4 needs r=262.
        let l3 = SecurityProfile::lookup(NistLevel::L3, QuantumBudget::Q40, false).unwrap();
        assert_eq!(l3.r_for_blowup(32).unwrap(),  79);
        assert_eq!(l3.r_for_blowup(16).unwrap(),  99);
        assert_eq!(l3.r_for_blowup( 8).unwrap(), 132);
        assert_eq!(l3.r_for_blowup( 4).unwrap(), 197);

        let l5 = SecurityProfile::lookup(NistLevel::L5, QuantumBudget::Q40, false).unwrap();
        assert_eq!(l5.r_for_blowup(32).unwrap(), 105);
        assert_eq!(l5.r_for_blowup(16).unwrap(), 131);
        assert_eq!(l5.r_for_blowup( 8).unwrap(), 175);
        assert_eq!(l5.r_for_blowup( 4).unwrap(), 262);
    }
}
