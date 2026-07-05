//! Axiom-stack nullifier gadget — Phase 3 of the axiom backend migration
//! (see `docs/axiom-backend-migration.md`).
//!
//! Computes `nullifier = poseidon(Fr(privateKey), Fr(domain))` on the axiom
//! `Context` eDSL, using [`poseidon_axiom`]'s interior (t=3) hasher. V2 uses
//! `"ZKMist_V2_NULLIFIER"` for domain separation, matching the PSE circuit's
//! convention (the domain *bytes* are identical; the Poseidon sponge convention
//! differs — see `poseidon_axiom.rs`).

use halo2_base::{
    gates::RangeInstructions, halo2_proofs::halo2curves::bn256::Fr, AssignedValue, Context,
};

use crate::poseidon_axiom::{hash_interior, native_hash_interior};

/// V2 nullifier domain separator (19 bytes) — identical to the PSE circuit's.
pub const NULLIFIER_DOMAIN_V2: &[u8; 19] = b"ZKMist_V2_NULLIFIER";

/// The V2 domain separator as an axiom `Fr` element: the 19 bytes interpreted
/// as a big-endian integer, reduced mod the scalar field (matching the PSE
/// `from_be_bytes_mod_order` derivation). Computed arithmetically to avoid the
/// strict canonical check of `from_repr`.
pub fn domain_field_element() -> Fr {
    let mut d = Fr::zero();
    for &b in NULLIFIER_DOMAIN_V2 {
        d = d * Fr::from(256u64) + Fr::from(b as u64);
    }
    d
}

/// Compute the nullifier natively (halo2-base Poseidon convention).
pub fn native_compute_nullifier(key: Fr) -> Fr {
    native_hash_interior(key, domain_field_element())
}

/// Compute the nullifier in the axiom circuit:
/// `nullifier = poseidon(private_key, domain)`.
pub fn compute_nullifier(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    private_key: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let domain = ctx.load_constant(domain_field_element());
    hash_interior(ctx, range, private_key, domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::utils::testing::base_test;

    #[test]
    fn test_axiom_nullifier_matches_native() {
        let key = Fr::from(0xBEEFu64);
        let expected = native_compute_nullifier(key);
        let got = base_test().k(12).lookup_bits(8).run(|ctx, range| {
            let k = ctx.load_witness(key);
            *compute_nullifier(ctx, range, k).value()
        });
        assert_eq!(got, expected, "axiom nullifier != native");
    }

    #[test]
    fn test_axiom_nullifier_unique_per_key_and_deterministic() {
        let k = Fr::from(42u64);
        assert_eq!(native_compute_nullifier(k), native_compute_nullifier(k));
        assert_ne!(
            native_compute_nullifier(Fr::from(1u64)),
            native_compute_nullifier(Fr::from(2u64))
        );
    }

    /// V2 domain must differ from V1 (domain-separation sanity, mirroring the
    /// PSE test).
    #[test]
    fn test_axiom_nullifier_v2_differs_from_v1() {
        let key = Fr::from(42u64);
        let v2 = native_compute_nullifier(key);
        // V1 domain, same arithmetic derivation.
        let mut v1_domain = Fr::zero();
        for &b in b"ZKMist_V1_NULLIFIER" {
            v1_domain = v1_domain * Fr::from(256u64) + Fr::from(b as u64);
        }
        let v1 = native_hash_interior(key, v1_domain);
        assert_ne!(v2, v1, "V2 nullifier must differ from V1");
    }
}
