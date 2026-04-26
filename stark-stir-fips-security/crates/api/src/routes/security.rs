//! GET /v1/security/profiles — list NIST-compliant parameter sets.
//!
//! Returns the nine canonical (Level, q) profiles from the STIR-FIPS paper,
//! flagging which ones the running binary can actually serve (hash compatibility)
//! and which violate the FIPS-202 binding wall.

use axum::Json;
use serde::Serialize;

use crate::security::{HashAlg, SecurityProfile};

#[derive(Debug, Serialize)]
pub struct PerBlowupR {
    pub blowup: usize,
    pub r: usize,
    pub kappa_it_realised: u32,
}

#[derive(Debug, Serialize)]
pub struct ProfileEntry {
    pub level: u8,
    pub lambda_bits: u32,
    pub quantum_budget_log2: u32,
    pub ext_field: &'static str,
    pub hash_alg: &'static str,
    /// Paper-baseline r at blowup = 32.
    pub r: usize,
    pub kappa_it: u32,
    pub kappa_bind: u32,
    pub kappa_fs: u32,
    pub kappa_sys: u32,
    pub binding_wall_violated: bool,
    pub supported_by_build: bool,
    /// Recalibrated r for blowups {2, 4, 8, 16, 32, 64, 128} — Johnson regime.
    pub r_per_blowup: Vec<PerBlowupR>,
}

#[derive(Debug, Serialize)]
pub struct ProfilesResponse {
    pub build_hash: &'static str,
    pub profiles: Vec<ProfileEntry>,
}

pub async fn list_profiles() -> Json<ProfilesResponse> {
    let build_hash = SecurityProfile::build_hash().label();
    let entries = SecurityProfile::all()
        .into_iter()
        .map(|p| {
            let r_per_blowup = [2usize, 4, 8, 16, 32, 64, 128]
                .iter()
                .map(|&b| {
                    let (kappa, r) = p.kappa_it_at_blowup(b).unwrap();
                    PerBlowupR { blowup: b, r, kappa_it_realised: kappa }
                })
                .collect();
            ProfileEntry {
                level: p.level.as_u8(),
                lambda_bits: p.lambda_bits,
                quantum_budget_log2: p.quantum_budget.log2(),
                ext_field: p.ext_field.label(),
                hash_alg: p.hash_alg.label(),
                r: p.r,
                kappa_it: p.kappa_it,
                kappa_bind: p.kappa_bind,
                kappa_fs: p.kappa_fs,
                kappa_sys: p.kappa_sys,
                binding_wall_violated: p.binding_wall_violated,
                supported_by_build: p.check_hash_compatibility().is_ok(),
                r_per_blowup,
            }
        })
        .collect();

    Json(ProfilesResponse {
        build_hash,
        profiles: entries,
    })
}

// Hint to the linker so HashAlg can be referenced for label printing
// even when only one feature is enabled.  The trait is already used through
// `SecurityProfile::build_hash` above, but keeping this `as _` ensures the
// item isn't dead-code-stripped on minimal builds.
#[allow(dead_code)]
const _USES_HASHALG: fn() -> &'static str = || HashAlg::Sha3_256.label();
