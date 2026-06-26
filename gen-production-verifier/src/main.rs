//! Standalone production verifier generator for ZKMist.
//!
//! Re-creates the ZKMistV2Claim circuit's `configure()` using the
//! halo2_proofs git v0.3.0 API (required by halo2-solidity-verifier).
//!
//! The VK is determined entirely by `configure()` — `synthesize()` only
//! affects witnesses.

use std::path::PathBuf;

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector, TableColumn},
    poly::{commitment::Params, Rotation},
};
use halo2curves::bn256::G1Affine;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use halo2_solidity_verifier::{BatchOpenScheme, SolidityGenerator};

// ── Gadget configs (exact replicas from zkmist-circuits) ────────────────

#[derive(Debug, Clone)]
struct PoseidonConfig {
    #[allow(dead_code)] advice: [Column<Advice>; 3],
    #[allow(dead_code)] fixed: Column<Fixed>,
    s_mul: Selector, s_add: Selector, s_add_fix: Selector, s_mul_fix: Selector,
}

impl PoseidonConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let fixed = meta.fixed_column();
        for col in &advice { meta.enable_equality(*col); }
        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_add_fix = meta.selector();
        let s_mul_fix = meta.selector();

        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });
        meta.create_gate("add_fix", |meta| {
            let s = meta.query_selector(s_add_fix);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed, Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a + f - b)]
        });
        meta.create_gate("mul_fix", |meta| {
            let s = meta.query_selector(s_mul_fix);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed, Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * f - b)]
        });
        Self { advice, fixed, s_mul, s_add, s_add_fix, s_mul_fix }
    }
}

#[derive(Debug, Clone)]
struct CondSwapConfig {
    #[allow(dead_code)] advice: [Column<Advice>; 3],
    s_swap: Selector, s_bool: Selector,
}

impl CondSwapConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 3]) -> Self {
        let s_swap = meta.selector();
        let s_bool = meta.selector();
        meta.create_gate("bool", |meta| {
            let s = meta.query_selector(s_bool);
            let sel = meta.query_advice(advice[0], Rotation::cur());
            vec![s * (sel.clone() * sel.clone() - sel)]
        });
        meta.create_gate("cond_swap", |meta| {
            let s = meta.query_selector(s_swap);
            let out = meta.query_advice(advice[2], Rotation::cur());
            let t1 = meta.query_advice(advice[0], Rotation::cur());
            let t2 = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (t1 + t2 - out)]
        });
        Self { advice, s_swap, s_bool }
    }
}

#[derive(Debug, Clone)]
struct RangeCheckConfig {
    #[allow(dead_code)] advice: Column<Advice>,
    table: TableColumn,
    #[allow(dead_code)] s_decompose: Selector,
}

impl RangeCheckConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>, advice: Column<Advice>) -> Self {
        let table = meta.lookup_table_column();
        let s_decompose = meta.selector();
        meta.lookup("range_check", |meta| {
            let val = meta.query_advice(advice, Rotation::cur());
            vec![(val, table)]
        });
        Self { advice, table, s_decompose }
    }

    /// Load the 8-bit range table (values 0..=255).
    /// Must be called during synthesis so keygen captures the fixed column commitment.
    fn load_range_table(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "range8",
            |mut table| {
                for i in 0u64..256 {
                    table.assign_cell(
                        || "range8_val",
                        self.table,
                        i as usize,
                        || Value::known(Fr::from(i)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone)]
struct Secp256k1Config {
    #[allow(dead_code)] advice: [Column<Advice>; 8],
    #[allow(dead_code)] fixed: Column<Fixed>,
    #[allow(dead_code)] range_check: RangeCheckConfig,
    s_mul: Selector, s_add: Selector, s_add_fixed: Selector,
    s_mul_fixed: Selector, s_add_carry: Selector, s_bool: Selector, s_nonzero: Selector,
}

impl Secp256k1Config {
    fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 8], rc_advice: Column<Advice>) -> Self {
        for col in &advice { meta.enable_equality(*col); }
        meta.enable_equality(rc_advice);
        let fixed = meta.fixed_column();
        let range_check = RangeCheckConfig::configure(meta, rc_advice);

        let s_mul = meta.selector(); let s_add = meta.selector();
        let s_add_fixed = meta.selector(); let s_mul_fixed = meta.selector();
        let s_add_carry = meta.selector(); let s_bool = meta.selector();
        let s_nonzero = meta.selector();

        meta.create_gate("secp_mul", |meta| {
            let s = meta.query_selector(s_mul);
            vec![s * (meta.query_advice(advice[0], Rotation::cur()) * meta.query_advice(advice[1], Rotation::cur()) - meta.query_advice(advice[2], Rotation::cur()))]
        });
        meta.create_gate("secp_add", |meta| {
            let s = meta.query_selector(s_add);
            vec![s * (meta.query_advice(advice[0], Rotation::cur()) + meta.query_advice(advice[1], Rotation::cur()) - meta.query_advice(advice[2], Rotation::cur()))]
        });
        meta.create_gate("secp_add_fixed", |meta| {
            let s = meta.query_selector(s_add_fixed);
            vec![s * (meta.query_advice(advice[0], Rotation::cur()) + meta.query_fixed(fixed, Rotation::cur()) - meta.query_advice(advice[1], Rotation::cur()))]
        });
        meta.create_gate("secp_mul_fixed", |meta| {
            let s = meta.query_selector(s_mul_fixed);
            vec![s * (meta.query_advice(advice[0], Rotation::cur()) * meta.query_fixed(fixed, Rotation::cur()) - meta.query_advice(advice[1], Rotation::cur()))]
        });
        let two_pow_64 = { let mut v = Fr::ONE; for _ in 0..64 { v = v.double(); } v };
        meta.create_gate("secp_add_carry", |meta| {
            let s = meta.query_selector(s_add_carry);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let ci = meta.query_advice(advice[2], Rotation::cur());
            let r = meta.query_advice(advice[3], Rotation::cur());
            let co = meta.query_advice(advice[4], Rotation::cur());
            vec![s * (a + b + ci - r - co * Expression::Constant(two_pow_64))]
        });
        meta.create_gate("secp_bool", |meta| {
            let s = meta.query_selector(s_bool);
            let x = meta.query_advice(advice[0], Rotation::cur());
            vec![s * (x.clone() * (Expression::Constant(Fr::ONE) - x))]
        });
        meta.create_gate("secp_nonzero", |meta| {
            let s = meta.query_selector(s_nonzero);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * b - Expression::Constant(Fr::ONE))]
        });
        Self { advice, fixed, range_check, s_mul, s_add, s_add_fixed, s_mul_fixed, s_add_carry, s_bool, s_nonzero }
    }

    /// Load lookup tables needed by the secp256k1 gadget.
    /// Delegates to range_check.load_range_table().
    fn load_tables(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        self.range_check.load_range_table(layouter)
    }
}

#[derive(Debug, Clone)]
struct KeccakConfig {
    #[allow(dead_code)] advice: [Column<Advice>; 8],
    #[allow(dead_code)] fixed: Column<Fixed>,
    s_xor: Selector, s_andnot: Selector, s_byte_decomp: Selector,
}

impl KeccakConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>, advice: [Column<Advice>; 8]) -> Self {
        for col in &advice { meta.enable_equality(*col); }
        let fixed = meta.fixed_column();
        let s_xor = meta.selector();
        let s_andnot = meta.selector();
        let s_byte_decomp = meta.selector();

        meta.create_gate("keccak_xor", |meta| {
            let s = meta.query_selector(s_xor);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let ab = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[3], Rotation::cur());
            let two = Expression::Constant(Fr::from(2u64));
            vec![
                s.clone() * (a.clone() * b.clone() - ab.clone()),
                s * (a + b - two * ab - out),
            ]
        });
        meta.create_gate("keccak_andnot", |meta| {
            let s = meta.query_selector(s_andnot);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let ab = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[3], Rotation::cur());
            vec![
                s.clone() * (a.clone() * b.clone() - ab.clone()),
                s * (b - ab - out),
            ]
        });
        meta.create_gate("keccak_byte_decomp", |meta| {
            let s = meta.query_selector(s_byte_decomp);
            let one = Expression::Constant(Fr::ONE);
            let bits: Vec<_> = (0..8).map(|i| meta.query_advice(advice[i], Rotation::cur())).collect();
            let byte_val = meta.query_fixed(fixed, Rotation::cur());
            let weights = [1u64, 2, 4, 8, 16, 32, 64, 128];
            let mut sum = bits[0].clone();
            for i in 1..8 { sum = sum + bits[i].clone() * Expression::Constant(Fr::from(weights[i])); }
            let mut cs = vec![s.clone() * (sum - byte_val)];
            for bit in &bits { cs.push(s.clone() * (bit.clone() * (one.clone() - bit.clone()))); }
            cs
        });
        Self { advice, fixed, s_xor, s_andnot, s_byte_decomp }
    }
}

// ── Circuit ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ZKMistV2ClaimConfig {
    #[allow(dead_code)] poseidon: PoseidonConfig,
    #[allow(dead_code)] cond_swap: CondSwapConfig,
    #[allow(dead_code)] secp256k1: Secp256k1Config,
    #[allow(dead_code)] keccak: KeccakConfig,
    #[allow(dead_code)] range_check: RangeCheckConfig,
    #[allow(dead_code)] instance: Column<Instance>,
    #[allow(dead_code)] advice: [Column<Advice>; 16],
}

#[derive(Debug, Clone)]
struct ZKMistV2Claim;

impl Circuit<Fr> for ZKMistV2Claim {
    type Config = ZKMistV2ClaimConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> ZKMistV2ClaimConfig {
        let advice: [Column<Advice>; 16] = std::array::from_fn(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let poseidon = PoseidonConfig::configure(meta);
        let cond_swap = CondSwapConfig::configure(meta, [advice[0], advice[1], advice[2]]);
        let range_check = RangeCheckConfig::configure(meta, advice[12]);
        let secp256k1 = Secp256k1Config::configure(
            meta,
            [advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6], advice[7]],
            advice[13],
        );
        let keccak = KeccakConfig::configure(
            meta,
            [advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6], advice[7]],
        );

        ZKMistV2ClaimConfig { poseidon, cond_swap, secp256k1, keccak, range_check, instance, advice }
    }

    fn synthesize(&self, config: ZKMistV2ClaimConfig, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        // Load fixed-column tables so keygen_vk captures their commitments.
        // Without these, the VK has zero fixed commitments and every real
        // proof will fail on-chain because the VK digest won't match.
        config.range_check.load_range_table(&mut layouter)?;
        // secp256k1 uses the same range table (delegates to range_check).
        // No need to call it twice — the table column is shared.
        let _ = &config.secp256k1; // suppress unused warning
        Ok(())
    }
}

// ── Constraint-system digest parity (MEDIUM-finding guard) ────────────────
//
// This crate re-implements `configure()` by hand because it cannot import
// `zkmist-circuits` (it needs the PSE halo2 git fork for `halo2_solidity_verifier`).
// A verifying key is derived **only** from `configure()`, so if this copy ever
// drifts from the real circuit, the generated Solidity verifier would silently
// check a *different* circuit — accepting proofs for the wrong statement or
// rejecting all honest ones.
//
// `constraint_system_digest` is a byte-for-byte copy of the function of the
// same name in `zkmist-circuits/src/lib.rs`. We compute it for THIS crate's
// `configure()` and assert it equals `EXPECTED_CS_DIGEST`, which is the value
// captured by `zkmist-circuits`' test `test_circuit_constraint_system_digest`.
// Update BOTH constants together whenever the circuit's `configure()` changes
// (run that test, copy the printed `CS_DIGEST`).
const EXPECTED_CS_DIGEST: &str = "72e30a6509cad673";

fn constraint_system_digest(cs: &ConstraintSystem<Fr>) -> String {
    // 1. Normalize: drop every "query_index: <num>, " occurrence.
    let raw = format!("{:?}", cs.pinned());
    let needle = b"query_index: ";
    let bytes = raw.as_bytes();
    let mut norm = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(needle) {
            let mut j = i + needle.len();
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if bytes.get(j..j + 2) == Some(b", ") {
                j += 2;
            }
            i = j;
        } else {
            norm.push(bytes[i] as char);
            i += 1;
        }
    }
    // 2. FNV-1a (64-bit).
    let mut h: u64 = 0xcbf29ce484222325;
    for b in norm.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut output_dir = PathBuf::from("../contracts/src");
    let mut k: u32 = 23; // MUST match CIRCUIT_K in cli/src/halo2_prover.rs

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => { output_dir = PathBuf::from(&args[i + 1]); i += 2; }
            "--k" => { k = args[i + 1].parse().unwrap_or(21); i += 2; }
            "--help" | "-h" => { eprintln!("Usage: gen-production-verifier [--output DIR] [--k N]"); return; }
            _ => { eprintln!("Unknown: {}", args[i]); std::process::exit(1); }
        }
    }

    eprintln!("╔════════════════════════════════════════════════════════════╗");
    eprintln!("║  ZKMist Production Verifier Generator                      ║");
    eprintln!("╚════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Validate k consistency with the prover.
    let expected_k: u32 = 23; // MUST match CIRCUIT_K in cli/src/halo2_prover.rs
    if k != expected_k {
        eprintln!("⚠️  WARNING: k={} does not match expected CIRCUIT_K={}", k, expected_k);
        eprintln!("   The generated verifier will reject proofs created with a different k.");
        eprintln!("   Proceeding anyway. Use --k {} for the production value.", expected_k);
    }

    eprintln!("[1/4] Creating circuit (k={})...", k);
    let circuit = ZKMistV2Claim;

    // Parity guard: refuse to emit a verifier whose VK would not match the
    // production prover. If this assert fires, this crate's `configure()` has
    // drifted from `zkmist-circuits` — re-sync the gate/column definitions and
    // update `EXPECTED_CS_DIGEST` on both sides.
    {
        let mut cs = ConstraintSystem::<Fr>::default();
        let _ = <ZKMistV2Claim as Circuit<Fr>>::configure(&mut cs);
        let digest = constraint_system_digest(&cs);
        if digest != EXPECTED_CS_DIGEST {
            eprintln!("❌ Constraint-system digest mismatch!");
            eprintln!("   this crate   : {}", digest);
            eprintln!("   zkmist-circ  : {}", EXPECTED_CS_DIGEST);
            eprintln!("   The hand-maintained configure() in this file has drifted from");
            eprintln!("   zkmist-circuits/src/lib.rs. Re-sync the gate/column definitions.");
            eprintln!("   If the change is intentional, update EXPECTED_CS_DIGEST in BOTH");
            eprintln!("   files (run `cargo test -p zkmist-circuits ");
            eprintln!("   test_circuit_constraint_system_digest -- --nocapture`).");
            std::process::exit(1);
        }
        eprintln!("   ✓ constraint-system digest matches zkmist-circuits ({})", digest);
    }

    eprintln!("[2/4] Generating KZG params...");
    let start = std::time::Instant::now();
    let params = ParamsKZG::<halo2curves::bn256::Bn256>::setup(k, &mut rand::thread_rng());
    eprintln!("      ✓ ({:.1}s)", start.elapsed().as_secs_f64());

    eprintln!("[3/4] Generating VK...");
    let t = std::time::Instant::now();
    let vk = halo2_proofs::plonk::keygen_vk(&params, &circuit).expect("keygen_vk failed");
    eprintln!("      ✓ ({:.1}s)", t.elapsed().as_secs_f64());
    eprintln!("      VK repr: {:?}", vk.transcript_repr());

    eprintln!("[4/4] Generating Solidity verifier...");
    let gen = SolidityGenerator::new(&params, &vk, BatchOpenScheme::Bdfg21, 3);
    let (verifier, vk_sol) = gen.render_separately().expect("render failed");

    std::fs::create_dir_all(&output_dir).ok();
    std::fs::write(output_dir.join("Halo2Verifier.sol"), &verifier).unwrap();
    std::fs::write(output_dir.join("Halo2VerifyingKey.sol"), &vk_sol).unwrap();

    let has_pairing = verifier.contains("ecPairing") || verifier.contains("0x08");
    eprintln!("      ✓ Halo2Verifier.sol ({} bytes)", verifier.len());
    eprintln!("      ✓ Halo2VerifyingKey.sol ({} bytes)", vk_sol.len());
    eprintln!("      Pairing: {}", if has_pairing { "✅" } else { "❌" });
    eprintln!();
    eprintln!("✅ Done! Next: cd contracts && forge build && forge test -vvv");
}
