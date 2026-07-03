//! Phase B integration proof-of-concept: halo2wrong secp256k1 scalar mul.
//!
//! Proves that halo2wrong's audited `GeneralEccChip` correctly computes
//! `scalar · G` on secp256k1 INSIDE this crate's halo2 backend — the exact
//! operation the ZKMist circuit needs to derive a claimant's public key from
//! their private key. This is the foundation for the main-circuit rewiring
//! (Phase B remainder): it verifies the dependency, the real API, and the
//! construction pattern BEFORE touching the soundness-critical `ZKMistV2Claim`.
//!
//! Mirrors halo2wrong's own ecdsa test exactly — `NUMBER_OF_LIMBS = 4`,
//! `BIT_LEN_LIMB = 68`, `window_size = 4` (the audited config, consistent
//! across halo2wrong's ecc/integer/ecdsa/transcript tests). See
//! `docs/secp256k1-migration-plan.md`.
//!
//! What this does NOT do (Phase B remainder):
//!   - rewire `ZKMistV2Claim` to use this chip (changes the VK digest),
//!   - re-derive the nullifier↔scalar and leaf↔Keccak-address bindings,
//!   - measure rows / reach for k=22.
//! Those need the careful incremental + MockProver-reverification path.

use ecc::integer::Range;
use ecc::maingate::RegionCtx;
use ecc::{EccConfig, GeneralEccChip};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{bn256::Fr as BnFr, secp256k1::Secp256k1Affine},
    plonk::{Circuit, ConstraintSystem, Error},
};
// secp256k1's SCALAR field (the private-key space).
use halo2_proofs::halo2curves::secp256k1::Fq as Secp256k1Scalar;
use integer::IntegerInstructions;
use maingate::{
    MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions,
};

// Audited halo2wrong config for secp256k1 (see module doc).
const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;
const WINDOW_SIZE: usize = 4;

#[derive(Clone, Debug)]
struct MulConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl MulConfig {
    fn ecc_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}

#[derive(Default, Clone)]
struct Halo2WrongSecp256k1Mul {
    scalar: Value<Secp256k1Scalar>,
    expected_pubkey: Value<Secp256k1Affine>,
    aux_generator: Secp256k1Affine,
}

impl Circuit<BnFr> for Halo2WrongSecp256k1Mul {
    type Config = MulConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<BnFr>) -> Self::Config {
        let (rns_base, rns_scalar) =
            GeneralEccChip::<Secp256k1Affine, BnFr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<BnFr>::configure(meta);
        let mut overflow_bit_lens: Vec<usize> = vec![];
        overflow_bit_lens.extend(rns_base.overflow_lengths());
        overflow_bit_lens.extend(rns_scalar.overflow_lengths());
        let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];
        let range_config = RangeChip::<BnFr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        MulConfig {
            main_gate_config,
            range_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<BnFr>) -> Result<(), Error> {
        let mut ecc_chip =
            GeneralEccChip::<Secp256k1Affine, BnFr, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
                config.ecc_config(),
            );

        // Required mul precomputation (mirrors halo2wrong's canonical mul test:
        // assign_aux with number_of_pairs=1, then materialize via get_mul_aux).
        layouter.assign_region(
            || "assign aux",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);
                ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                ecc_chip.assign_aux(ctx, WINDOW_SIZE, 1)?;
                Ok(())
            },
        )?;;

        // The actual `scalar · G` and an internal soundness check that the
        // result equals the natively-computed expected public key.
        layouter.assign_region(
            || "scalar * G",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let g = ecc_chip.assign_point(ctx, Value::known(Secp256k1Affine::generator()))?;

                let scalar_chip = ecc_chip.scalar_field_chip();
                let scalar_int = ecc_chip.new_unassigned_scalar(self.scalar);
                let scalar_assigned = scalar_chip.assign_integer(ctx, scalar_int, Range::Remainder)?;

                let result = ecc_chip.mul(ctx, &g, &scalar_assigned, WINDOW_SIZE)?;

                let expected = ecc_chip.assign_point(ctx, self.expected_pubkey)?;
                ecc_chip.assert_equal(ctx, &result, &expected)?;
                Ok(())
            },
        )?;

        // Load the range table AFTER the computation regions (matches
        // halo2wrong's ecdsa test: `config.config_range(&mut layouter)`). The
        // integer chip's limb range checks look this up.
        RangeChip::<BnFr>::new(config.range_config.clone()).load_table(&mut layouter)?;

        Ok(())
    }
}

#[test]
fn test_halo2wrong_secp256k1_scalar_mul() {
    use halo2_proofs::halo2curves::{
        group::Curve,
        secp256k1::Secp256k1, // projective curve point
    };

    // Fixed scalar (deterministic; proves the capability without an RNG dep).
    // G · scalar is computed natively via the projective; the circuit must
    // derive the SAME point via the constrained GeneralEccChip mul.
    let scalar = Secp256k1Scalar::from(42u64);
    let g = Secp256k1::generator();
    let expected_pubkey = (g * scalar).to_affine();
    // Any distinct non-identity point for the mul aux generator.
    let aux_generator = (g * (scalar + Secp256k1Scalar::from(7u64))).to_affine();

    let circuit = Halo2WrongSecp256k1Mul {
        scalar: Value::known(scalar),
        expected_pubkey: Value::known(expected_pubkey),
        aux_generator,
    };

    // Run MockProver directly (bypassing halo2wrong's DimensionMeasurement)
    // so any failure surfaces as a real constraint/structural error, not an
    // opaque measure-pass Synthesis. k=20 is generous for an isolated mul.
    use halo2_proofs::dev::MockProver;
    let prover = MockProver::run(20, &circuit, vec![vec![]]).expect("MockProver::run");
    let res = prover.verify();
    assert!(res.is_ok(), "halo2wrong mul verify failed: {:#?}", res);
}
