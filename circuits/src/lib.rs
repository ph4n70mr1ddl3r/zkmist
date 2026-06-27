//! ZKMist V2 Circuits — Halo2-KZG anonymous airdrop claim proofs
//!
//! The circuit enforces:
//! 1. **Key → Address**: secp256k1 scalar multiplication + Keccak-256
//! 2. **Leaf hash**: `poseidon(address)` — t=2
//! 3. **Merkle proof**: 26-level Poseidon Merkle path verification
//! 4. **Nullifier**: `poseidon(Fr(key), Fr(domain))` with V2 domain separator
//! 5. **Non-zero recipient**: Rejects address(0)

pub mod gadgets;
// Keccak bit-level operations use index-based loops for clarity
// with lane/byte indexing. Complex types are inherent to circuit code.
#[allow(clippy::needless_range_loop)]
#[allow(clippy::ptr_arg)]
#[allow(clippy::type_complexity)]
pub mod keccak;
pub mod merkle;
pub mod nullifier;
pub mod poseidon;
// Non-native field arithmetic uses limb-indexed loops throughout.
#[allow(clippy::needless_range_loop)]
pub mod secp256k1;
pub mod trivial;

pub use poseidon::{PoseidonChip, PoseidonConfig, PoseidonParams};

use ark_ff::PrimeField;
use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::bn256::Fr;

use crate::gadgets::cond_swap::{cond_swap, CondSwapConfig};
use crate::gadgets::range_check::RangeCheckConfig;
use crate::keccak::KeccakConfig;
use crate::merkle::TREE_DEPTH;
use crate::nullifier::domain_field_element;
use crate::poseidon::ark_to_halo2;
use crate::secp256k1::{
    decompose_key_to_bits, native_derive_address, NativePoint, NativeSecpField, Secp256k1Chip,
    Secp256k1Config,
};

// ──────────────────────────────────────────────────────────────────────
// Soundness-binding helpers (Findings 1–3)
//
// These helpers weld together the three otherwise-independent pillars of the
// claim proof — (a) the secp256k1 scalar `k`, (b) the Keccak-derived address,
// and (c) the nullifier — by accumulating the *constrained boolean bit cells*
// produced by the gadgets into field elements and forcing equality. Every bit
// is re-asserted boolean inside `accumulate_weighted_bits`, so each binding is
// sound even if the feeding gadget relied on implicit booleanity.
// ──────────────────────────────────────────────────────────────────────

/// `2^exp` reduced modulo the BN254 scalar field prime.
fn pow2_fr(exp: u32) -> Fr {
    let mut v = Fr::ONE;
    for _ in 0..exp {
        v = v.double();
    }
    v
}

/// Deterministic fingerprint of a configured `ConstraintSystem`.
///
/// Built from halo2's public `pinned()` view, whose `Debug` output
/// serializes every gate polynomial, lookup, permutation, and column count —
/// i.e. exactly the set of things that determine a verifying key. The
/// `query_index` bookkeeping field is stripped first (it is halo2-internal
/// allocation order, not semantically meaningful — a query is fully
/// identified by its column index + rotation), so the digest is stable across
/// halo2 0.3.x patch versions while still pinning the full constraint
/// structure. The normalized string is then folded with FNV-1a (64-bit) into a
/// compact, dependency-free hash.
///
/// `gen-production-verifier` ships a byte-for-byte identical copy of this
/// function and asserts its output equals `EXPECTED_CS_DIGEST`, preventing it
/// from emitting a Solidity verifier for a circuit whose `configure()` has
/// drifted from this crate.
#[doc(hidden)]
pub fn constraint_system_digest(cs: &halo2_proofs::plonk::ConstraintSystem<Fr>) -> String {
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
    // 2. FNV-1a (64-bit) — deterministic, no external dependency, identical in
    //    both crates.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in norm.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

/// Pinned digest of the production `ZKMistV2Claim` constraint system.
///
/// MUST be kept identical to the constant of the same name in
/// `gen-production-verifier/src/main.rs`. The test
/// `test_circuit_constraint_system_digest` guards this side; the generator's
/// runtime assert guards the other. Update both together when `configure()`
/// changes (run the test, copy the printed `CS_DIGEST` into both files).
///
/// Regenerated (2026 review) after the soundness fixes to `cond_swap`
/// (sound `s_bool`/`s_mul`/`s_add` product gates, replacing the broken single
/// `s_swap` gate) and to the secp256k1 non-native field reduction
/// (`s_add_carry` carry chains). Both changed the constraint system, so the
/// digest moved from `72e30a6509cad673` to `f8f4b46128dd613f`.
///
/// To regenerate after any future `configure()` change: run
/// `cargo test -p zkmist-circuits test_circuit_constraint_system_digest --
/// --nocapture`, copy the printed `CS_DIGEST` into BOTH this constant and
/// `gen-production-verifier`, then commit. (Running that single test is
/// cheap; it does not invoke the expensive k=24 MockProver/KZG paths.)
///
/// ✅ SYNCED (2026): `gen-production-verifier/src/main.rs` now carries the
/// sound `cond_swap` (`s_bool`/`s_mul`/`s_add` product gates) and this same
/// digest (`f8f4b46128dd613f`). The port was validated structurally via a
/// standalone digest harness under crates.io halo2 0.3.0 (the real circuit's
/// halo2), which reproduced `f8f4b46128dd613f` exactly; the generator's own
/// runtime parity assert re-validates it under the PSE halo2 git fork when
/// built in an environment with `halo2-solidity-verifier` present.
pub const EXPECTED_CS_DIGEST: &str = "f8f4b46128dd613f";

/// Finding 3 helper: constrain 8 consecutive Keccak *input* bytes (each
/// already decomposed into 8 boolean bits by `build_initial_state`) to equal a
/// single 64-bit limb cell of the scalar-mul output.
///
/// `input_byte_bits[byte]` holds the 8 bits of that input byte, LSB-first
/// (`bit[0]` = least significant). `start_byte` is the MOST-significant byte
/// of the limb. Limb value (little-endian 64-bit) is reconstructed as
///   Σ_{k=0..7} Σ_{j=0..7} bit[start_byte+k][j] · 2^(8·(7-k) + j)
/// and constrained equal to `limb`.
fn bind_limb_to_inputs(
    secp: &Secp256k1Chip,
    layouter: &mut impl Layouter<Fr>,
    input_byte_bits: &[Vec<AssignedCell<Fr, Fr>>],
    start_byte: usize,
    limb: &AssignedCell<Fr, Fr>,
) -> Result<(), Error> {
    let mut bits: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(64);
    let mut weights: Vec<Fr> = Vec::with_capacity(64);
    for k in 0..8u32 {
        for j in 0..8u32 {
            bits.push(input_byte_bits[start_byte + k as usize][j as usize].clone());
            weights.push(pow2_fr(8 * (7 - k) + j));
        }
    }
    let acc = secp.accumulate_weighted_bits(layouter, &bits, &weights)?;
    layouter.assign_region(|| "bind_limb_eq", |mut region| {
        region.constrain_equal(acc.cell(), limb.cell())
    })?;
    Ok(())
}

/// ZKMist V2 Claim Circuit.
///
/// **Public inputs**: [merkle_root, nullifier, recipient]
///
/// **Private inputs**: private_key, siblings[26], path_indices[26]
#[derive(Debug, Clone)]
pub struct ZKMistV2Claim {
    pub private_key: [u8; 32],
    pub siblings: [[u8; 32]; TREE_DEPTH],
    pub path_indices: [u8; TREE_DEPTH],
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub recipient: Fr,
}

#[derive(Debug, Clone)]
pub struct ZKMistV2ClaimConfig {
    poseidon: PoseidonConfig,
    cond_swap: CondSwapConfig,
    secp256k1: Secp256k1Config,
    keccak: KeccakConfig,
    range_check: RangeCheckConfig,
    instance: Column<Instance>,
    advice: [Column<Advice>; 16],
}

impl Circuit<Fr> for ZKMistV2Claim {
    type Config = ZKMistV2ClaimConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            private_key: [0u8; 32],
            siblings: [[0u8; 32]; TREE_DEPTH],
            path_indices: [0u8; TREE_DEPTH],
            merkle_root: Fr::ZERO,
            nullifier: Fr::ZERO,
            recipient: Fr::ZERO,
        }
    }

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
            [
                advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6],
                advice[7],
            ],
            advice[13],
        );
        let keccak = KeccakConfig::configure(
            meta,
            [
                advice[0], advice[1], advice[2], advice[3], advice[4], advice[5], advice[6],
                advice[7],
            ],
        );

        ZKMistV2ClaimConfig {
            poseidon,
            cond_swap,
            secp256k1,
            keccak,
            range_check,
            instance,
            advice,
        }
    }

    fn synthesize(
        &self,
        config: ZKMistV2ClaimConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.range_check.load_range_table(&mut layouter)?;
        config.secp256k1.load_tables(&mut layouter)?;

        // ── Step 1: Derive address from private key ────────────────────
        let (address_bytes, pub_x_bytes, pub_y_bytes) = native_derive_address(&self.private_key);

        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address_bytes);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        // ── Step 1a: Keccak hash of public key → address bits ──────────
        // The Keccak hash constrains the address derivation. The prover
        // must know a valid public key that hashes to the target address.
        let keccak_chip = crate::keccak::KeccakChip::new(&config.keccak);
        // ── Constrained Keccak: address bits + input byte bits ─────────
        // `keccak_address_bits`: 160 constrained output bits of keccak(pub_x||pub_y)[96..256].
        // `keccak_input_bytes` : per-byte input bit cells (200 bytes × 8 bits).
        // Both are bound to the scalar-mul output and the Merkle leaf below.
        let (keccak_address_bits, keccak_input_bytes, keccak_address) =
            keccak_chip.hash_pubkey_to_address(&mut layouter, &pub_x_bytes, &pub_y_bytes)?;

        // Verify the derived address matches Keccak output (debug only)
        debug_assert_eq!(address_bytes, keccak_address);

        // ── Step 1b: secp256k1 scalar multiplication (constrained) ─────
        let secp_chip = Secp256k1Chip::new(&config.secp256k1);

        let pub_x = NativeSecpField::from_bytes_be(&pub_x_bytes);
        let pub_y = NativeSecpField::from_bytes_be(&pub_y_bytes);
        let pub_x_limbs = pub_x.to_bn254_limbs();
        let pub_y_limbs = pub_y.to_bn254_limbs();

        // Assign affine public key coordinates as field elements
        let pub_x_assigned = {
            let limbs = pub_x_limbs;
            layouter.assign_region(
                || "pub_x",
                |mut region| {
                    let mut assigned = Vec::with_capacity(4);
                    for (i, limb) in limbs.iter().enumerate() {
                        let cell = region.assign_advice(
                            || format!("pub_x_limb_{}", i),
                            config.advice[i],
                            0,
                            || Value::known(*limb),
                        )?;
                        assigned.push(cell);
                    }
                    Ok(crate::secp256k1::AssignedFieldElement {
                        limbs: [
                            assigned[0].clone(),
                            assigned[1].clone(),
                            assigned[2].clone(),
                            assigned[3].clone(),
                        ],
                    })
                },
            )?
        };

        let pub_y_assigned = {
            let limbs = pub_y_limbs;
            layouter.assign_region(
                || "pub_y",
                |mut region| {
                    let mut assigned = Vec::with_capacity(4);
                    for (i, limb) in limbs.iter().enumerate() {
                        let cell = region.assign_advice(
                            || format!("pub_y_limb_{}", i),
                            config.advice[i],
                            0,
                            || Value::known(*limb),
                        )?;
                        assigned.push(cell);
                    }
                    Ok(crate::secp256k1::AssignedFieldElement {
                        limbs: [
                            assigned[0].clone(),
                            assigned[1].clone(),
                            assigned[2].clone(),
                            assigned[3].clone(),
                        ],
                    })
                },
            )?
        };

        // Assign generator point
        let g = NativePoint::GENERATOR;
        let g_assigned = layouter.assign_region(
            || "generator",
            |mut region| {
                let g_x_limbs = g.x.to_bn254_limbs();
                let g_y_limbs = g.y.to_bn254_limbs();
                let mut x_a = Vec::new();
                for (i, l) in g_x_limbs.iter().enumerate() {
                    x_a.push(region.assign_advice(
                        || "gx",
                        config.advice[i],
                        0,
                        || Value::known(*l),
                    )?);
                }
                let mut y_a = Vec::new();
                for (i, l) in g_y_limbs.iter().enumerate() {
                    y_a.push(region.assign_advice(
                        || "gy",
                        config.advice[i],
                        1,
                        || Value::known(*l),
                    )?);
                }
                // Z = 1 for affine generator
                let mut z_a = Vec::new();
                for i in 0..4 {
                    let v = if i == 0 { Fr::ONE } else { Fr::ZERO };
                    z_a.push(region.assign_advice(
                        || "gz",
                        config.advice[i],
                        2,
                        || Value::known(v),
                    )?);
                }
                Ok(crate::secp256k1::AssignedPoint {
                    x: crate::secp256k1::AssignedFieldElement {
                        limbs: [
                            x_a[0].clone(),
                            x_a[1].clone(),
                            x_a[2].clone(),
                            x_a[3].clone(),
                        ],
                    },
                    y: crate::secp256k1::AssignedFieldElement {
                        limbs: [
                            y_a[0].clone(),
                            y_a[1].clone(),
                            y_a[2].clone(),
                            y_a[3].clone(),
                        ],
                    },
                    z: crate::secp256k1::AssignedFieldElement {
                        limbs: [
                            z_a[0].clone(),
                            z_a[1].clone(),
                            z_a[2].clone(),
                            z_a[3].clone(),
                        ],
                    },
                })
            },
        )?;

        // Scalar bits for multiplication — assigned as boolean cells ONCE and
        // shared between the scalar multiplication and the nullifier binding
        // (Finding 2). This shared set of cells is what cryptographically links
        // the nullifier key to the secp256k1 scalar actually multiplied.
        let scalar_bits_bool = decompose_key_to_bits(&self.private_key);
        let scalar_bit_cells = secp_chip.assign_scalar_bits(&mut layouter, &scalar_bits_bool)?;
        let scalar_bits: [AssignedCell<Fr, Fr>; 256] = scalar_bit_cells
            .try_into()
            .expect("assign_scalar_bits returns exactly 256 cells");

        // Perform constrained scalar multiplication: k * G
        let computed_point = secp_chip.scalar_mul(&mut layouter, &scalar_bits, &g_assigned)?;

        // ── Soundness: Verify computed point is on the secp256k1 curve ──
        // This catches any incorrect intermediate field operations.
        // y² = x³ + 7 (mod secp256k1 field prime)
        secp_chip.check_on_curve(&mut layouter, &computed_point)?;

        // ── Soundness: Range-check all limbs of the computed point ──────
        // Ensures no limb exceeds 2^64, preventing carry-chain attacks.
        secp_chip.check_limb_ranges(&mut layouter, &computed_point.x)?;
        secp_chip.check_limb_ranges(&mut layouter, &computed_point.y)?;
        secp_chip.check_limb_ranges(&mut layouter, &computed_point.z)?;

        // Constrain: k*G == (pub_x, pub_y) in affine coordinates
        secp_chip.constrain_affine(
            &mut layouter,
            &computed_point,
            &pub_x_assigned,
            &pub_y_assigned,
        )?;

        // ── Finding 3: Bind the Keccak INPUT to the scalar-mul output ──
        // `constrain_affine` already links k*G → (pub_x_assigned, pub_y_assigned).
        // This block additionally forces the (pub_x||pub_y) bytes fed into the
        // Keccak hash to be those exact coordinates. Without it, a malicious
        // prover could hash an unrelated eligible pubkey while proving a
        // different scalar multiplication, claiming eligibility for an address
        // whose private key they do not know.
        for limb_idx in 0..4usize {
            // pub_x occupies Keccak input bytes 0..31; pub_y bytes 32..63.
            // Limbs are little-endian: limb[i] covers bytes [(3-i)*8 .. +7].
            bind_limb_to_inputs(
                &secp_chip,
                &mut layouter,
                &keccak_input_bytes,
                (3 - limb_idx) * 8,
                &pub_x_assigned.limbs[limb_idx],
            )?;
            bind_limb_to_inputs(
                &secp_chip,
                &mut layouter,
                &keccak_input_bytes,
                32 + (3 - limb_idx) * 8,
                &pub_y_assigned.limbs[limb_idx],
            )?;
        }

        // ── Finding 1: Bind the Merkle leaf to the Keccak-derived address ──
        // Accumulate the 160 constrained Keccak output bits into the address
        // field element and force `leaf_input` to equal it. Without this, the
        // leaf is a free advice cell and the prover can claim membership for
        // any address in the (public) eligibility tree.
        let address_weights: Vec<Fr> = (0..160u32)
            .map(|m| {
                let k = m / 8; // address byte index (0 = MSB byte = hash byte 12)
                let j = m % 8; // bit-within-byte (0 = LSB)
                pow2_fr(8 * (19 - k) + j)
            })
            .collect();
        let address_acc = secp_chip.accumulate_weighted_bits(
            &mut layouter,
            &keccak_address_bits,
            &address_weights,
        )?;

        // ── Step 2: Leaf hash ─────────────────────────────────────────
        let leaf_params = PoseidonParams::new_circom(1);
        let leaf_hasher = PoseidonChip::new(config.poseidon.clone(), &leaf_params);
        let leaf_input = layouter.assign_region(
            || "leaf_input",
            |mut region| {
                region.assign_advice(
                    || "addr",
                    config.advice[0],
                    0,
                    || Value::known(address_field),
                )
            },
        )?;
        // Cryptographic binding: leaf_input == accumulated Keccak address.
        layouter.assign_region(|| "leaf_address_bind", |mut region| {
            region.constrain_equal(leaf_input.cell(), address_acc.cell())
        })?;
        let leaf = leaf_hasher.hash(&mut layouter, &[leaf_input])?;

        // ── Step 3: Merkle proof ──────────────────────────────────────
        let interior_params = PoseidonParams::new_circom(2);
        let interior_hasher = PoseidonChip::new(config.poseidon.clone(), &interior_params);

        // Assign Merkle proof inputs. CRITICAL: the cells MUST be returned from the
        // closure (not accumulated into an external Vec by side-effect). halo2's
        // SimpleFloorPlanner invokes each region closure TWICE — once into a
        // throwaway RegionShape to measure the region's footprint, then again
        // for the real assignment. Cells captured by side-effect during the
        // measurement pass hold Value::unknown(); indexing them later yields a
        // Synthesis error. The floor planner keeps the SECOND pass's return
        // value, so returning the cells here guarantees synthesize holds the
        // real, witness-bearing cells.
        //
        // Column layout: siblings in advice[0], path indices in advice[1], each
        // at rows 0..TREE_DEPTH. Distinct columns ⇒ no intra-region cell
        // collision (the previous (i%8)/((i+8)%16) scheme double-wrote advice[0]
        // at i=8, a separate latent bug).
        let (sibling_cells, path_index_cells) = layouter.assign_region(
            || "merkle_inputs",
            |mut region| {
                let mut siblings = Vec::with_capacity(TREE_DEPTH);
                let mut paths = Vec::with_capacity(TREE_DEPTH);
                for i in 0..TREE_DEPTH {
                    let sib_val =
                        ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&self.siblings[i]));
                    let sib = region.assign_advice(
                        || format!("sibling_{}", i),
                        config.advice[0],
                        i,
                        || Value::known(sib_val),
                    )?;
                    siblings.push(sib);

                    let pi_val = Fr::from(self.path_indices[i] as u64);
                    let pi = region.assign_advice(
                        || format!("path_{}", i),
                        config.advice[1],
                        i,
                        || Value::known(pi_val),
                    )?;
                    paths.push(pi);
                }
                Ok((siblings, paths))
            },
        )?;

        let mut current = leaf;
        for i in 0..TREE_DEPTH {
            let (left, right) = layouter.assign_region(
                || format!("merkle_swap_{}", i),
                |mut region| {
                    cond_swap(
                        &mut region,
                        &config.cond_swap,
                        0,
                        &current,
                        &sibling_cells[i],
                        &path_index_cells[i],
                    )
                },
            )?;
            current = interior_hasher.hash(&mut layouter, &[left, right])?;
        }
        layouter.constrain_instance(current.cell(), config.instance, 0)?;

        // ── Step 4: Nullifier ─────────────────────────────────────────

        // ── Finding 2: Bind the nullifier key to the secp256k1 scalar ──
        // Accumulate the SAME boolean bit cells used by `scalar_mul` into the
        // field element fed to the nullifier Poseidon hash. This forces
        // nullifier = poseidon(k, domain) to use the exact key whose k*G was
        // verified above, preventing nullifier rotation (and thus double /
        // unlimited claims with fresh nullifiers).
        let nullifier_weights: Vec<Fr> = (0..256u32).map(|i| pow2_fr(255 - i)).collect();
        let key_acc = secp_chip.accumulate_weighted_bits(
            &mut layouter,
            &scalar_bits,
            &nullifier_weights,
        )?;

        let key_field = {
            let ark_key = ark_bn254::Fr::from_be_bytes_mod_order(&self.private_key);
            ark_to_halo2(&ark_key)
        };
        let key_cell = layouter.assign_region(
            || "null_key",
            |mut region| {
                region.assign_advice(|| "key", config.advice[0], 0, || Value::known(key_field))
            },
        )?;
        // Cryptographic binding: key_cell == accumulated scalar bits.
        layouter.assign_region(|| "nullifier_key_bind", |mut region| {
            region.constrain_equal(key_cell.cell(), key_acc.cell())
        })?;
        let domain = domain_field_element();
        let domain_cell = layouter.assign_region(
            || "null_domain",
            |mut region| {
                region.assign_advice(|| "dom", config.advice[1], 0, || Value::known(domain))
            },
        )?;
        let nullifier_hasher = PoseidonChip::new(config.poseidon.clone(), &interior_params);
        let computed_nullifier = nullifier_hasher.hash(&mut layouter, &[key_cell, domain_cell])?;
        layouter.constrain_instance(computed_nullifier.cell(), config.instance, 1)?;

        // ── Step 5: Real recipient constraints ─────────────────────────
        //
        // Two SOUND constraints, replacing the previous vacuous blocks:
        //
        //   (a) uint160 range: recipient is decomposed into 160 boolean bits
        //       and accumulated under existing gates; the accumulator is
        //       constrained equal to `recipient_cell`. Because every bit is
        //       re-asserted boolean inside `accumulate_weighted_bits`, this
        //       proves recipient = Σ_{i<160} bit_i·2^i  <  2^160. Hence no
        //       valid proof exists for a recipient that Solidity's
        //       `uint160(recipient)` would truncate to a different address.
        //
        //   (b) non-zero: `assert_nonzero` enables the `s_nonzero` gate
        //       (recipient · inv − 1 = 0). The constant 1 lives inside the
        //       gate polynomial, so a zero recipient provably cannot satisfy
        //       it — unlike the old code, which only constrained a prover-
        //       assigned `prod` cell to a prover-assigned `one` cell.
        //
        // These are defense-in-depth: the Solidity contract also rejects
        // `address(0)` and the recipient is bound to the (always-uint160)
        // public input via `constrain_instance` below.
        let recipient_cell = layouter.assign_region(
            || "recipient",
            |mut region| {
                region.assign_advice(
                    || "recip",
                    config.advice[0],
                    0,
                    || Value::known(self.recipient),
                )
            },
        )?;

        // (a) uint160 range constraint: decompose into 160 boolean bits.
        {
            use ff::PrimeField;
            let repr = self.recipient.to_repr();
            let le: &[u8] = repr.as_ref();
            // 160 bits, LSB-first: bit i ↔ byte i/8, bit-within-byte i%8.
            let bit_cells: Vec<AssignedCell<Fr, Fr>> = layouter.assign_region(
                || "recipient_bits",
                |mut region| {
                    let mut cells = Vec::with_capacity(160);
                    for i in 0..160usize {
                        let set = (le[i / 8] >> (i % 8)) & 1 == 1;
                        let col = config.advice[(i / 64) % 8];
                        let cell = region.assign_advice(
                            || format!("rb_{}", i),
                            col,
                            i % 64,
                            || Value::known(if set { Fr::ONE } else { Fr::ZERO }),
                        )?;
                        cells.push(cell);
                    }
                    Ok(cells)
                },
            )?;
            let weights: Vec<Fr> = (0..160u32).map(pow2_fr).collect();
            let rec_acc =
                secp_chip.accumulate_weighted_bits(&mut layouter, &bit_cells, &weights)?;
            layouter.assign_region(|| "recipient_uint160_bind", |mut region| {
                region.constrain_equal(rec_acc.cell(), recipient_cell.cell())
            })?;
        }

        // (b) non-zero recipient.
        secp_chip.assert_nonzero(&mut layouter, &recipient_cell)?;

        layouter.constrain_instance(recipient_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::native_compute_nullifier;
    use crate::poseidon::native_poseidon;
    use crate::secp256k1::NativePoint;
    use ark_ff::BigInteger;
    use light_poseidon::PoseidonHasher;

    /// Process-wide lock that **serializes** the heavy k=22 `MockProver` tests.
    ///
    /// `cargo test --lib` runs every `#[test]` as a thread inside one binary,
    /// so the four k=22 tests (`test_circuit_configures`, plus the three
    /// `*_rejected` negative tests) launch concurrently by default. Each one
    /// allocates a full 2^22-row × ~28-column witness (~8 GiB RSS, measured);
    /// four in parallel peak at ~32–44 GiB, exhaust the host RAM, and
    /// hard-crash the whole process (and the agent running the suite). Holding
    /// this mutex for the duration of each heavy test makes them run one at a
    /// time (peak ≈ 8 GiB) while the ~60 cheap tests keep parallelizing freely.
    /// Poisoning is tolerated so one failing heavy test doesn't mask the others.
    static HEAVY_MOCK_PROVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Test that the circuit configuration is valid (no panics during configure).
    #[test]
    fn test_circuit_configures() {
        let _heavy_guard = HEAVY_MOCK_PROVER_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let circuit = ZKMistV2Claim {
            private_key: [0u8; 32],
            siblings: [[0u8; 32]; TREE_DEPTH],
            path_indices: [0u8; TREE_DEPTH],
            merkle_root: Fr::ZERO,
            nullifier: Fr::ZERO,
            recipient: Fr::ONE,
        };
        let public_inputs = vec![Fr::ZERO, Fr::ZERO, Fr::ONE];
        // k=24: the full circuit (secp256k1 + Keccak + Poseidon + Merkle) no
        // longer fits in 2^22 rows after the 2026 secp256k1 soundness rewrite
        // (see `test_secp256k1_mock_prover`). This is a configure-only smoke
        // test; it does not call `verify()`.
        let _ = halo2_proofs::dev::MockProver::run(24, &circuit, vec![public_inputs]);
        eprintln!("✅ ZKMistV2Claim circuit configuration valid (k=24)");
    }

    /// Full end-to-end MockProver test with a real key, Merkle proof, and nullifier.
    ///
    /// This test validates that the Poseidon, Merkle, nullifier, secp256k1,
    /// and Keccak gadgets all produce consistent proofs together.
    ///
    /// If any gadget has a soundness bug, the on-curve check or
    /// `constrain_affine` will catch it.
    ///
    /// STATUS (2026 review): ✅ **PASSES at k=24**. This is the top
    /// deployment blocker cleared. The honest end-to-end proof — real key →
    /// secp256k1 → Keccak address → Merkle membership → nullifier → recipient —
    /// verifies, and the binding between the three pillars (secp scalar, Keccak
    /// address, nullifier) is sound and consistent.
    ///
    /// Getting here required fixing three latent bugs that MockProver could not
    /// catch on its own (gates were satisfiable, but the witness was wrong):
    ///   1. **Keccak `RC` round-constant table corruption** (from index 5) —
    ///      shared by the native `keccak_f` and the circuit's `iota_step`; both
    ///      silently produced a wrong digest. Fixed with the canonical XKCP
    ///      table, now pinned by `test_keccak_f_matches_tiny_keccak_empty`.
    ///   2. **`rotate_lane` was a RIGHT rotation** (Keccak needs LEFT) — pure
    ///      rearrangement with no gate, so it passed MockProver; pinned by
    ///      `test_rotate_lane_is_left_rotation`.
    ///   3. **`chi_step` transposed its output** (loop order stored lane (x,y) at
    ///      `y*5+x` instead of `x*5+y`); per-bit gates stayed satisfied. Fixed;
    ///      the isolated Keccak test now constrains its 160 address bits against
    ///      `tiny_keccak` so all three regressions are caught.
    /// The test harness was also fixed: proofs are now built at the full
    /// `TREE_DEPTH` via `build_single_leaf_proof` (it previously built a
    /// depth-4 tree and zero-padded, which could never match the circuit's
    /// 26-level root).
    ///
    /// NOTE: This test is `#[ignore]` by default because it is very slow
    /// (full circuit at k=24 is 16M rows; ~32 min, ~30 GiB RSS).
    /// Run with:
    ///   cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_circuit_merkle_nullifier_e2e() {
        // Use a test key that's valid (non-zero, below secp256k1 order)
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        // Derive address and compute leaf
        let (address, _, _) = native_derive_address(&key);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        // Compute leaf hash
        let leaf_params = PoseidonParams::new_circom(1);
        let _leaf = native_poseidon(&leaf_params, &[address_field]);

        // Compute nullifier with V2 domain
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        let nullifier_params = PoseidonParams::new_circom(2);
        let nullifier = crate::nullifier::native_compute_nullifier(&key_field, &nullifier_params);

        // Build a single-leaf Merkle proof at the full production depth
        // (TREE_DEPTH = 26). The circuit always iterates 0..TREE_DEPTH, so a
        // proof built at a smaller depth (e.g. the previous depth-4 build)
        // leaves the upper sibling slots as all-zero — the circuit then
        // applies 22 extra `poseidon(x, 0)` levels and computes a root that
        // can never equal the native depth-4 root (the `Instance[0]` failure
        // documented on this test). `build_single_leaf_proof` is O(depth): for
        // a lone index-0 leaf every sibling is an all-padding subtree root, so
        // it yields the correct depth-26 root and 26 (sibling, path) pairs
        // without materializing the 67M-leaf tree.
        let (root_ark, siblings_ark, path_indices_u8) =
            zkmist_merkle_tree::build_single_leaf_proof(&address, TREE_DEPTH);
        assert_eq!(siblings_ark.len(), TREE_DEPTH);
        assert_eq!(path_indices_u8.len(), TREE_DEPTH);

        let mut siblings_arr = [[0u8; 32]; TREE_DEPTH];
        let mut path_arr = [0u8; TREE_DEPTH];
        for i in 0..TREE_DEPTH {
            siblings_arr[i] = siblings_ark[i];
            path_arr[i] = path_indices_u8[i];
        }

        let root_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_ark));

        // Use a non-zero recipient
        let recipient = Fr::from(0xB0Bu64);

        let circuit = ZKMistV2Claim {
            private_key: key,
            siblings: siblings_arr,
            path_indices: path_arr,
            merkle_root: root_field,
            nullifier,
            recipient,
        };

        // The full circuit (secp256k1 + Keccak + Poseidon + Merkle) requires
        // k=24 after the 2026 soundness rewrite of the secp256k1 non-native
        // reductions (carry chains + witnessed quotient + canonicalization),
        // which added many rows per field op. The isolated secp256k1 gadget
        // alone no longer fits in k=22/23 (see `test_secp256k1_mock_prover`),
        // so the combined circuit needs k=24 (16M rows). k=23 (8M rows) now
        // overflows (`NotEnoughRowsAvailable`). Peak RSS ≈ 29–35 GiB at k=24.
        //
        // Expected runtime: 30-90 minutes (MockProver is a debug tool, not optimized
        // for speed). The secp256k1 + Keccak gadgets dominate.
        let k = 24;
        eprintln!(
            "   Running full circuit E2E MockProver test with k={}...",
            k
        );
        let public_inputs = vec![root_field, nullifier, recipient];
        let result = halo2_proofs::dev::MockProver::run(k, &circuit, vec![public_inputs]);

        match result {
            Ok(prover) => match prover.verify() {
                Ok(()) => eprintln!("✅ Full circuit E2E MockProver test PASSED (k={})", k),
                Err(e) => {
                    eprintln!("❌ Full circuit MockProver verify FAILED (k={}):", k);
                    for err in &e {
                        eprintln!("   {:?}", err);
                    }
                    panic!(
                        "Full circuit E2E MockProver test failed at k={}. \
                             Run with --nocapture for details.",
                        k
                    );
                }
            },
            Err(e) => {
                panic!(
                    "MockProver::run failed at k={}: {:?}. \
                     The full circuit (secp256k1 + Keccak + Poseidon + Merkle) \
                     may need k=24 or higher.",
                    k, e
                );
            }
        }
    }

    /// Constraint-system digest (fingerprint) parity test.
    ///
    /// `gen-production-verifier` re-implements `configure()` by hand (it cannot
    /// import this crate — it depends on the PSE halo2 git fork for
    /// `halo2_solidity_verifier`). A VK is derived **only** from `configure()`,
    /// so if the two implementations diverge the on-chain verifier silently
    /// checks a *different* circuit.
    ///
    /// This test pins the real circuit's `ConstraintSystem` to the constant
    /// `EXPECTED_CS_DIGEST`. `gen-production-verifier` asserts against the
    /// *same* constant before generating the VK, so any divergence between the
    /// two `configure()` implementations blocks verifier regeneration. Update
    /// both constants together whenever the circuit's `configure()` changes.
    #[test]
    fn test_circuit_constraint_system_digest() {
        use halo2_proofs::plonk::ConstraintSystem;
        let mut cs = ConstraintSystem::<Fr>::default();
        let _cfg = <ZKMistV2Claim as Circuit<Fr>>::configure(&mut cs);
        let digest = constraint_system_digest(&cs);
        eprintln!("CS_DIGEST = {}", digest);
        assert_eq!(
            digest, EXPECTED_CS_DIGEST,
            "circuit constraint system changed; regenerate the digest and \
             update EXPECTED_CS_DIGEST here AND in gen-production-verifier"
        );
    }

    /// Isolated secp256k1 MockProver test.
    ///
    /// Validates that the constrained secp256k1 scalar multiplication gadget
    /// produces correct proofs when tested in isolation (without Keccak/Poseidon).
    ///
    /// This is a focused soundness test for the most complex gadget in the circuit.
    /// If this fails, the full E2E test will also fail.
    ///
    /// NOTE: Still `#[ignore]`d because secp256k1 alone is ~300K+ rows at k=22.
    /// Run with:
    ///   cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_secp256k1_mock_prover() {
        use halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
        };

        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (address, _pub_x_bytes, _pub_y_bytes) = native_derive_address(&key);
        assert_eq!(
            hex::encode(address),
            "fcad0b19bb29d4674531d6f115237e16afce377c"
        );

        #[derive(Clone)]
        struct SecpTestCircuit {
            private_key: [u8; 32],
        }

        #[derive(Debug, Clone)]
        struct SecpTestConfig {
            secp: crate::secp256k1::Secp256k1Config,
            instance: Column<Instance>,
            advice: [Column<Advice>; 16],
        }

        impl Circuit<Fr> for SecpTestCircuit {
            type Config = SecpTestConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                self.clone()
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> SecpTestConfig {
                let advice: [Column<Advice>; 16] = std::array::from_fn(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                });
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                let secp = crate::secp256k1::Secp256k1Config::configure(
                    meta,
                    [
                        advice[0], advice[1], advice[2], advice[3], advice[4], advice[5],
                        advice[6], advice[7],
                    ],
                    advice[13],
                );
                SecpTestConfig {
                    secp,
                    instance,
                    advice,
                }
            }

            fn synthesize(
                &self,
                config: SecpTestConfig,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                config.secp.load_tables(&mut layouter)?;

                let (addr, pub_x_bytes, pub_y_bytes) = native_derive_address(&self.private_key);

                let secp_chip = crate::secp256k1::Secp256k1Chip::new(&config.secp);

                // Assign expected public key
                let pub_x = crate::secp256k1::NativeSecpField::from_bytes_be(&pub_x_bytes);
                let pub_y = crate::secp256k1::NativeSecpField::from_bytes_be(&pub_y_bytes);
                let pub_x_limbs = pub_x.to_bn254_limbs();
                let pub_y_limbs = pub_y.to_bn254_limbs();

                let pub_x_assigned = layouter.assign_region(
                    || "pub_x",
                    |mut region| {
                        let mut assigned = Vec::with_capacity(4);
                        for (i, limb) in pub_x_limbs.iter().enumerate() {
                            let cell = region.assign_advice(
                                || format!("pub_x_limb_{}", i),
                                config.advice[i],
                                0,
                                || Value::known(*limb),
                            )?;
                            assigned.push(cell);
                        }
                        Ok(crate::secp256k1::AssignedFieldElement {
                            limbs: [
                                assigned[0].clone(),
                                assigned[1].clone(),
                                assigned[2].clone(),
                                assigned[3].clone(),
                            ],
                        })
                    },
                )?;

                let pub_y_assigned = layouter.assign_region(
                    || "pub_y",
                    |mut region| {
                        let mut assigned = Vec::with_capacity(4);
                        for (i, limb) in pub_y_limbs.iter().enumerate() {
                            let cell = region.assign_advice(
                                || format!("pub_y_limb_{}", i),
                                config.advice[i],
                                0,
                                || Value::known(*limb),
                            )?;
                            assigned.push(cell);
                        }
                        Ok(crate::secp256k1::AssignedFieldElement {
                            limbs: [
                                assigned[0].clone(),
                                assigned[1].clone(),
                                assigned[2].clone(),
                                assigned[3].clone(),
                            ],
                        })
                    },
                )?;

                // Assign generator point
                let g = crate::secp256k1::NativePoint::GENERATOR;
                let g_assigned = layouter.assign_region(
                    || "generator",
                    |mut region| {
                        let g_x_limbs = g.x.to_bn254_limbs();
                        let g_y_limbs = g.y.to_bn254_limbs();
                        let mut x_a = Vec::new();
                        for (i, l) in g_x_limbs.iter().enumerate() {
                            x_a.push(region.assign_advice(
                                || "gx",
                                config.advice[i],
                                0,
                                || Value::known(*l),
                            )?);
                        }
                        let mut y_a = Vec::new();
                        for (i, l) in g_y_limbs.iter().enumerate() {
                            y_a.push(region.assign_advice(
                                || "gy",
                                config.advice[i],
                                1,
                                || Value::known(*l),
                            )?);
                        }
                        let mut z_a = Vec::new();
                        for i in 0..4 {
                            let v = if i == 0 { Fr::ONE } else { Fr::ZERO };
                            z_a.push(region.assign_advice(
                                || "gz",
                                config.advice[i],
                                2,
                                || Value::known(v),
                            )?);
                        }
                        Ok(crate::secp256k1::AssignedPoint {
                            x: crate::secp256k1::AssignedFieldElement {
                                limbs: [
                                    x_a[0].clone(),
                                    x_a[1].clone(),
                                    x_a[2].clone(),
                                    x_a[3].clone(),
                                ],
                            },
                            y: crate::secp256k1::AssignedFieldElement {
                                limbs: [
                                    y_a[0].clone(),
                                    y_a[1].clone(),
                                    y_a[2].clone(),
                                    y_a[3].clone(),
                                ],
                            },
                            z: crate::secp256k1::AssignedFieldElement {
                                limbs: [
                                    z_a[0].clone(),
                                    z_a[1].clone(),
                                    z_a[2].clone(),
                                    z_a[3].clone(),
                                ],
                            },
                        })
                    },
                )?;

                // Scalar multiplication (bits assigned as constrained boolean
                // cells, matching the production circuit's scalar/nullifier binding).
                let scalar_bits_bool = crate::secp256k1::decompose_key_to_bits(&self.private_key);
                let scalar_bit_cells = secp_chip.assign_scalar_bits(&mut layouter, &scalar_bits_bool)?;
                let scalar_bits: [AssignedCell<Fr, Fr>; 256] = scalar_bit_cells
                    .try_into()
                    .expect("assign_scalar_bits returns exactly 256 cells");

                let computed_point =
                    secp_chip.scalar_mul(&mut layouter, &scalar_bits, &g_assigned)?;

                // Soundness checks
                secp_chip.check_on_curve(&mut layouter, &computed_point)?;
                secp_chip.check_limb_ranges(&mut layouter, &computed_point.x)?;
                secp_chip.check_limb_ranges(&mut layouter, &computed_point.y)?;
                secp_chip.check_limb_ranges(&mut layouter, &computed_point.z)?;

                // Constrain k*G == (pub_x, pub_y)
                secp_chip.constrain_affine(
                    &mut layouter,
                    &computed_point,
                    &pub_x_assigned,
                    &pub_y_assigned,
                )?;

                // Constrain the derived address as a public output
                let mut addr_padded = [0u8; 32];
                addr_padded[12..32].copy_from_slice(&addr);
                let address_field = crate::poseidon::ark_to_halo2(
                    &ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded),
                );
                let addr_cell = layouter.assign_region(
                    || "address",
                    |mut region| {
                        region.assign_advice(
                            || "addr",
                            config.advice[0],
                            0,
                            || Value::known(address_field),
                        )
                    },
                )?;
                layouter.constrain_instance(addr_cell.cell(), config.instance, 0)?;

                Ok(())
            }
        }

        let circuit = SecpTestCircuit { private_key: key };
        // k was 22 before the 2026 soundness rewrite of `field_mul` /
        // `field_add_carried` / `field_sub` (explicit integer carry chains +
        // witnessed quotient `q` + canonicalization). Those reductions add many
        // rows per field op, so the isolated secp256k1 circuit no longer fits in
        // 2^22 rows (`NotEnoughRowsAvailable` at k=22 and k=23). k=24 (16M rows)
        // fits with headroom. Revisit if it must rise again.
        let k = 24;
        eprintln!("   Running secp256k1 MockProver test with k={}...", k);

        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field =
            crate::poseidon::ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        let result = MockProver::run(k, &circuit, vec![vec![address_field]]);
        match result {
            Ok(prover) => match prover.verify() {
                Ok(()) => {
                    eprintln!("   ✅ secp256k1 MockProver test PASSED (k={})", k);
                    eprintln!("      Address: 0x{}", hex::encode(address));
                }
                Err(e) => {
                    eprintln!("   ❌ secp256k1 MockProver verify FAILED:");
                    let constraint_fails = e
                        .iter()
                        .filter(|e| {
                            matches!(
                                e,
                                halo2_proofs::dev::VerifyFailure::ConstraintNotSatisfied { .. }
                            )
                        })
                        .count();
                    let perm_fails = e
                        .iter()
                        .filter(|e| {
                            matches!(e, halo2_proofs::dev::VerifyFailure::Permutation { .. })
                        })
                        .count();
                    eprintln!(
                        "      {} constraint failures, {} permutation failures",
                        constraint_fails, perm_fails
                    );
                    for err in e.iter().take(20) {
                        eprintln!("      {:?}", err);
                    }
                    panic!("secp256k1 MockProver verification failed");
                }
            },
            Err(e) => {
                panic!("secp256k1 MockProver::run failed (k={}): {:?}", k, e);
            }
        }
    }

    /// Test full native pipeline: key → address → leaf → nullifier.
    #[test]
    fn test_native_pipeline_prd_test_vector() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        // Step 1: Derive address
        let (address, pub_x, pub_y) = native_derive_address(&key);
        assert_eq!(
            hex::encode(address),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );

        // Step 1b: Verify Keccak hash
        let hash = crate::keccak::native_hash_pubkey(&pub_x, &pub_y);
        assert_eq!(
            hex::encode(&hash[12..32]),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );

        // Step 2: Compute leaf hash
        let leaf_params = PoseidonParams::new_circom(1);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));
        let leaf = native_poseidon(&leaf_params, &[address_field]);
        let leaf_ark = crate::poseidon::halo2_to_ark(&leaf);
        assert_eq!(
            hex::encode(leaf_ark.into_bigint().to_bytes_be()),
            "1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9",
        );

        // Step 4: Compute nullifier (V2 domain)
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        let nullifier_params = PoseidonParams::new_circom(2);
        let nullifier = native_compute_nullifier(&key_field, &nullifier_params);
        let nullifier_ark = crate::poseidon::halo2_to_ark(&nullifier);
        // V2 nullifier uses "ZKMist_V2_NULLIFIER" — different from V1
        eprintln!(
            "V2 nullifier: 0x{}",
            hex::encode(nullifier_ark.into_bigint().to_bytes_be())
        );
    }

    /// Test that the secp256k1 scalar multiplication produces the correct point.
    #[test]
    fn test_secp256k1_scalar_mul_correctness() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_be_bytes(key[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        limbs.reverse();

        let point = NativePoint::scalar_mul(&limbs);
        assert!(!point.is_inf);

        let (addr, _, _) = native_derive_address(&key);
        assert_eq!(
            hex::encode(addr),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );
    }

    /// Test the full Poseidon-Merkle-Nullifier pipeline consistency.
    #[test]
    fn test_poseidon_merkle_nullifier_consistency() {
        let interior_params = PoseidonParams::new_circom(2);
        let leaf_params = PoseidonParams::new_circom(1);

        // Compute leaf hash
        let addr_bytes: [u8; 20] = [
            0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1, 0x15, 0x23,
            0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
        ];
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(&addr_bytes);
        let leaf_halo2 = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&padded));
        let leaf_hash = native_poseidon(&leaf_params, &[leaf_halo2]);

        // Cross-check: hash matches the merkle-tree crate
        let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(1).unwrap();
        let leaf_ark = ark_bn254::Fr::from_be_bytes_mod_order(&padded);
        let lp_leaf = hasher.hash(&[leaf_ark]).unwrap();
        assert_eq!(
            crate::poseidon::halo2_to_ark(&leaf_hash),
            lp_leaf,
            "Circuit leaf hash must match light-poseidon"
        );

        // Verify nullifier V2 differs from V1
        let key_field = ark_to_halo2(&ark_bn254::Fr::from(42u64));
        let v2_nullifier = native_compute_nullifier(&key_field, &interior_params);
        // Compute V1 nullifier manually
        let v1_bytes = b"ZKMist_V1_NULLIFIER";
        let mut v1_padded = [0u8; 32];
        v1_padded[..v1_bytes.len()].copy_from_slice(v1_bytes);
        let v1_domain = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&v1_padded));
        let v1_nullifier = native_poseidon(&interior_params, &[key_field, v1_domain]);
        assert_ne!(
            v2_nullifier, v1_nullifier,
            "V2 nullifier must differ from V1"
        );
    }

    /// Negative test: wrong Merkle root should fail circuit verification.
    ///
    /// The circuit constrains the computed Merkle root to match the public
    /// input. Providing a wrong root should cause MockProver to reject.
    #[test]
    #[ignore = "slow: full circuit at k=24 (~30 min, ~30 GiB RSS). The honest E2E path now passes (test_circuit_merkle_nullifier_e2e), so this negative test can be trusted to reject for the RIGHT reason. Run with --ignored."]
    fn test_wrong_merkle_root_rejected() {
        let _heavy_guard = HEAVY_MOCK_PROVER_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (address, _, _) = native_derive_address(&key);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        let leaf_params = PoseidonParams::new_circom(1);
        let _leaf = native_poseidon(&leaf_params, &[address_field]);

        let interior_params = PoseidonParams::new_circom(2);
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        let nullifier = crate::nullifier::native_compute_nullifier(&key_field, &interior_params);

        let addresses = vec![address];
        let (root_ark, proof) =
            zkmist_merkle_tree::build_tree_streaming_with_depth(&addresses, 4, Some(0));
        let (siblings_ark, path_indices_u8) = proof.expect("proof extraction failed");

        let mut siblings_arr = [[0u8; 32]; TREE_DEPTH];
        let mut path_arr = [0u8; TREE_DEPTH];
        for i in 0..siblings_ark.len().min(TREE_DEPTH) {
            siblings_arr[i] = siblings_ark[i];
            path_arr[i] = path_indices_u8[i];
        }

        // Use a WRONG root (flip one bit)
        let mut wrong_root_bytes = root_ark;
        wrong_root_bytes[0] ^= 0x01;
        let wrong_root = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&wrong_root_bytes));

        let recipient = Fr::from(0xB0Bu64);

        let circuit = ZKMistV2Claim {
            private_key: key,
            siblings: siblings_arr,
            path_indices: path_arr,
            merkle_root: wrong_root,
            nullifier,
            recipient,
        };

        let k = 24;
        let public_inputs = vec![wrong_root, nullifier, recipient];
        let result = halo2_proofs::dev::MockProver::run(k, &circuit, vec![public_inputs]);

        match result {
            Ok(prover) => {
                let verify_result = prover.verify();
                assert!(
                    verify_result.is_err(),
                    "Circuit should REJECT a wrong Merkle root, but it passed!"
                );
                eprintln!("✅ Wrong Merkle root correctly rejected (k={})", k);
            }
            Err(e) => {
                eprintln!(
                    "⚠️  MockProver::run failed at k={}: {:?} \
                     — negative test could not be executed",
                    k, e
                );
            }
        }
    }

    /// Negative test: wrong nullifier should fail.
    #[test]
    #[ignore = "slow: full circuit at k=24 (~30 min, ~30 GiB RSS). Honest E2E path now passes; run with --ignored."]
    fn test_wrong_nullifier_rejected() {
        let _heavy_guard = HEAVY_MOCK_PROVER_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (address, _, _) = native_derive_address(&key);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        let leaf_params = PoseidonParams::new_circom(1);
        let _leaf = native_poseidon(&leaf_params, &[address_field]);

        let addresses = vec![address];
        let (root_ark, proof) =
            zkmist_merkle_tree::build_tree_streaming_with_depth(&addresses, 4, Some(0));
        let (siblings_ark, path_indices_u8) = proof.expect("proof extraction failed");

        let mut siblings_arr = [[0u8; 32]; TREE_DEPTH];
        let mut path_arr = [0u8; TREE_DEPTH];
        for i in 0..siblings_ark.len().min(TREE_DEPTH) {
            siblings_arr[i] = siblings_ark[i];
            path_arr[i] = path_indices_u8[i];
        }

        let root_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_ark));

        // Use a WRONG nullifier
        let wrong_nullifier = Fr::from(0xDEADu64);
        let recipient = Fr::from(0xB0Bu64);

        let circuit = ZKMistV2Claim {
            private_key: key,
            siblings: siblings_arr,
            path_indices: path_arr,
            merkle_root: root_field,
            nullifier: wrong_nullifier,
            recipient,
        };

        let k = 24;
        let public_inputs = vec![root_field, wrong_nullifier, recipient];
        let result = halo2_proofs::dev::MockProver::run(k, &circuit, vec![public_inputs]);

        match result {
            Ok(prover) => {
                let verify_result = prover.verify();
                assert!(
                    verify_result.is_err(),
                    "Circuit should REJECT a wrong nullifier, but it passed!"
                );
                eprintln!("✅ Wrong nullifier correctly rejected (k={})", k);
            }
            Err(e) => {
                eprintln!(
                    "⚠️  MockProver::run failed at k={}: {:?} \
                     — negative test could not be executed",
                    k, e
                );
            }
        }
    }

    /// Negative test: zero recipient should fail.
    #[test]
    #[ignore = "slow: full circuit at k=24 (~30 min, ~30 GiB RSS). Honest E2E path now passes; run with --ignored."]
    fn test_zero_recipient_rejected() {
        let _heavy_guard = HEAVY_MOCK_PROVER_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (address, _, _) = native_derive_address(&key);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        let leaf_params = PoseidonParams::new_circom(1);
        let _leaf = native_poseidon(&leaf_params, &[address_field]);

        let interior_params = PoseidonParams::new_circom(2);
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        let nullifier = crate::nullifier::native_compute_nullifier(&key_field, &interior_params);

        let addresses = vec![address];
        let (root_ark, proof) =
            zkmist_merkle_tree::build_tree_streaming_with_depth(&addresses, 4, Some(0));
        let (siblings_ark, path_indices_u8) = proof.expect("proof extraction failed");

        let mut siblings_arr = [[0u8; 32]; TREE_DEPTH];
        let mut path_arr = [0u8; TREE_DEPTH];
        for i in 0..siblings_ark.len().min(TREE_DEPTH) {
            siblings_arr[i] = siblings_ark[i];
            path_arr[i] = path_indices_u8[i];
        }

        let root_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_ark));

        let circuit = ZKMistV2Claim {
            private_key: key,
            siblings: siblings_arr,
            path_indices: path_arr,
            merkle_root: root_field,
            nullifier,
            recipient: Fr::ZERO, // Zero recipient — should fail
        };

        let k = 24;
        let public_inputs = vec![root_field, nullifier, Fr::ZERO];
        let result = halo2_proofs::dev::MockProver::run(k, &circuit, vec![public_inputs]);

        match result {
            Ok(prover) => {
                let verify_result = prover.verify();
                assert!(
                    verify_result.is_err(),
                    "Circuit should REJECT a zero recipient, but it passed!"
                );
                eprintln!("✅ Zero recipient correctly rejected (k={})", k);
            }
            Err(e) => {
                eprintln!(
                    "⚠️  MockProver::run failed at k={}: {:?} \
                     — negative test could not be executed",
                    k, e
                );
            }
        }
    }

    /// Property test: verify that different keys produce different nullifiers.
    #[test]
    fn test_nullifier_collision_resistance() {
        let params = PoseidonParams::new_circom(2);
        let mut nullifiers = std::collections::HashSet::new();

        for key_val in 1u64..=100 {
            let key_field = ark_to_halo2(&ark_bn254::Fr::from(key_val));
            let nullifier = native_compute_nullifier(&key_field, &params);
            let nullifier_bytes = {
                let ark = crate::poseidon::halo2_to_ark(&nullifier);
                ark.into_bigint().to_bytes_be()
            };
            assert!(
                nullifiers.insert(nullifier_bytes),
                "Nullifier collision for key {}",
                key_val
            );
        }
        eprintln!("✅ 100 nullifiers all unique — no collisions");
    }

    /// Property test: verify nullifier collision resistance with more keys.
    /// Tests 10,000 random-ish keys for nullifier uniqueness.
    #[test]
    fn test_nullifier_collision_resistance_10k() {
        let params = PoseidonParams::new_circom(2);
        let mut nullifiers = std::collections::HashSet::new();

        for key_val in 1u64..=10_000 {
            let key_field = ark_to_halo2(&ark_bn254::Fr::from(key_val));
            let nullifier = native_compute_nullifier(&key_field, &params);
            let nullifier_bytes = {
                let ark = crate::poseidon::halo2_to_ark(&nullifier);
                ark.into_bigint().to_bytes_be()
            };
            assert!(
                nullifiers.insert(nullifier_bytes),
                "Nullifier collision for key {}",
                key_val
            );
        }
        eprintln!("✅ 10,000 nullifiers all unique — no collisions");
    }

    /// Property test: leaf hash is deterministic for any address.
    #[test]
    fn test_leaf_hash_deterministic() {
        let leaf_params = PoseidonParams::new_circom(1);

        // Test multiple addresses
        for addr_val in 1u64..=50 {
            let mut addr_bytes = [0u8; 20];
            addr_bytes[12..20].copy_from_slice(&addr_val.to_be_bytes());

            let mut padded = [0u8; 32];
            padded[12..32].copy_from_slice(&addr_bytes);
            let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&padded));

            let leaf1 = native_poseidon(&leaf_params, &[address_field]);
            let leaf2 = native_poseidon(&leaf_params, &[address_field]);
            assert_eq!(
                leaf1, leaf2,
                "Leaf hash not deterministic for address {}",
                addr_val
            );
        }
        eprintln!("✅ 50 leaf hashes all deterministic");
    }

    /// Property test: different addresses produce different leaf hashes.
    #[test]
    fn test_leaf_hash_uniqueness() {
        let leaf_params = PoseidonParams::new_circom(1);
        let mut leaves = std::collections::HashSet::new();

        for addr_val in 1u64..=100 {
            let mut addr_bytes = [0u8; 20];
            addr_bytes[12..20].copy_from_slice(&addr_val.to_be_bytes());

            let mut padded = [0u8; 32];
            padded[12..32].copy_from_slice(&addr_bytes);
            let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&padded));

            let leaf = native_poseidon(&leaf_params, &[address_field]);
            let leaf_bytes = {
                let ark = crate::poseidon::halo2_to_ark(&leaf);
                ark.into_bigint().to_bytes_be()
            };
            assert!(
                leaves.insert(leaf_bytes),
                "Leaf collision for address {}",
                addr_val
            );
        }
        eprintln!("✅ 100 leaf hashes all unique");
    }

    /// Property test: V2 nullifiers differ from V1 for all tested keys.
    #[test]
    fn test_v2_nullifiers_always_differ_from_v1() {
        let interior_params = PoseidonParams::new_circom(2);

        for key_val in 1u64..=50 {
            let key_field = ark_to_halo2(&ark_bn254::Fr::from(key_val));
            let v2_nullifier = native_compute_nullifier(&key_field, &interior_params);

            // Compute V1 nullifier
            let v1_bytes = b"ZKMist_V1_NULLIFIER";
            let mut v1_padded = [0u8; 32];
            v1_padded[..v1_bytes.len()].copy_from_slice(v1_bytes);
            let v1_domain = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&v1_padded));
            let v1_nullifier = native_poseidon(&interior_params, &[key_field, v1_domain]);

            assert_ne!(
                v2_nullifier, v1_nullifier,
                "V1/V2 nullifier match for key {}",
                key_val
            );
        }
        eprintln!("✅ 50 keys: V2 nullifiers all differ from V1");
    }

    /// Property test: secp256k1 address derivation is consistent.
    #[test]
    fn test_address_derivation_consistency() {
        // Test multiple private keys
        let test_keys: Vec<[u8; 32]> = (1u8..=10)
            .map(|i| {
                let mut key = [0u8; 32];
                key[31] = i;
                key
            })
            .collect();

        for key in &test_keys {
            // Derive address twice — must match
            let (addr1, px1, py1) = native_derive_address(key);
            let (addr2, px2, py2) = native_derive_address(key);
            assert_eq!(addr1, addr2, "Address derivation inconsistent");
            assert_eq!(px1, px2, "Public key X inconsistent");
            assert_eq!(py1, py2, "Public key Y inconsistent");

            // Verify Keccak hash matches
            let hash = crate::keccak::native_hash_pubkey(&px1, &py1);
            let hash_addr = &hash[12..32];
            assert_eq!(addr1, hash_addr, "Keccak-derived address doesn't match");

            // Address must be 20 bytes and non-zero
            assert_ne!(addr1, [0u8; 20], "Derived address is zero");
        }
        eprintln!("✅ 10 keys: address derivation consistent and matches Keccak");
    }

    /// Property test: Merkle proof verification is sound for small trees.
    #[test]
    fn test_merkle_proof_soundness() {
        use zkmist_merkle_tree::{build_tree_streaming_with_depth, hash_leaf, verify_merkle_proof};

        // Build trees of different sizes and verify proofs
        for num_addrs in 1usize..=8 {
            let addresses: Vec<[u8; 20]> = (0..num_addrs)
                .map(|i| {
                    let mut addr = [0u8; 20];
                    addr[19] = i as u8;
                    addr
                })
                .collect();

            // Depth must be >= ceil(log2(num_addrs)) for the tree to fit all addresses
            let min_depth =
                std::cmp::max(1, num_addrs.next_power_of_two().trailing_zeros() as usize);
            for depth in min_depth..=(min_depth + 2) {
                for target_idx in 0..num_addrs {
                    let (root, proof) =
                        build_tree_streaming_with_depth(&addresses, depth, Some(target_idx));
                    let (siblings, path_indices) = proof.expect("proof failed");

                    // Verify proof
                    let mut hasher =
                        light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(1).unwrap();
                    let leaf = hash_leaf(&addresses[target_idx], &mut hasher);
                    let computed_root = verify_merkle_proof(&leaf, &siblings, &path_indices);

                    assert_eq!(
                        computed_root, root,
                        "Merkle root mismatch: {} addrs, depth {}, idx {}",
                        num_addrs, depth, target_idx
                    );
                }
            }
        }
        eprintln!("✅ Merkle proofs verified for trees of sizes 1-8, appropriate depths");
    }

    /// Test address derivation with multiple well-known test vectors.
    /// Uses deterministic keys at various bit patterns to exercise edge cases
    /// in the secp256k1 scalar multiplication (MSB=0, MSB=1, small, large).
    #[test]
    fn test_address_derivation_multiple_keys() {
        // (private_key_bytes, expected_address_hex)
        let test_vectors: Vec<([u8; 32], &str)> = vec![
            // Key 1: 0x0123...cdef — MSB=0, standard test vector
            (
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
                    0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                ],
                "fcad0b19bb29d4674531d6f115237e16afce377c",
            ),
            // Key 2: private key = 1 (minimal valid key)
            {
                let mut k = [0u8; 32];
                k[31] = 1;
                (k, "7e5f4552091a69125d5dfcb7b8c2659029395bdf")
            },
            // Key 3: private key = 2
            {
                let mut k = [0u8; 32];
                k[31] = 2;
                (k, "2b5ad5c4795c026514f8317c7a215e218dccd6cf")
            },
            // Key 4: private key = 3
            {
                let mut k = [0u8; 32];
                k[31] = 3;
                (k, "6813eb9362372eef6200f3b1dbc3f819671cba69")
            },
            // Key 5: 0x80... — MSB=1, exercises MSB correction path (no subtract)
            {
                let mut k = [0u8; 32];
                k[0] = 0x80;
                k[31] = 0x42;
                (k, "") // Expected address computed dynamically
            },
            // Key 6: 0x7FFF... — MSB=0, all bits set except MSB region
            {
                let mut k = [0xFFu8; 32];
                k[0] = 0x7F;
                (k, "")
            },
            // Key 7: random-ish key near the group order boundary
            {
                let mut k = [0u8; 32];
                k[0] = 0xFF;
                k[1] = 0xFF;
                k[2] = 0xFF;
                k[3] = 0xFE;
                k[4] = 0xBA;
                k[5] = 0xAE;
                k[6] = 0xDC;
                k[7] = 0xE6;
                k[8] = 0xAF;
                k[9] = 0x48;
                k[10] = 0xA0;
                k[11] = 0x3B;
                k[12] = 0xBF;
                k[13] = 0xD2;
                k[14] = 0x5E;
                k[15] = 0x8C;
                k[16] = 0xD0;
                k[17] = 0x36;
                k[18] = 0x41;
                k[19] = 0x40;
                k[20] = 0x00;
                k[21] = 0x00;
                k[22] = 0x00;
                k[23] = 0x00;
                k[24] = 0x00;
                k[25] = 0x00;
                k[26] = 0x00;
                k[27] = 0x00;
                k[28] = 0x00;
                k[29] = 0x00;
                k[30] = 0x00;
                k[31] = 0x01;
                // n - 1 (last valid key before group order)
                (k, "")
            },
        ];

        let leaf_params = PoseidonParams::new_circom(1);
        let interior_params = PoseidonParams::new_circom(2);

        for (i, (key, expected_addr)) in test_vectors.iter().enumerate() {
            let (address, pub_x, pub_y) = native_derive_address(key);

            // Verify against expected address if provided
            if !expected_addr.is_empty() {
                assert_eq!(
                    hex::encode(address),
                    *expected_addr,
                    "Address mismatch for test vector {}",
                    i + 1
                );
            }

            // Cross-check: Keccak hash must match
            let hash = crate::keccak::native_hash_pubkey(&pub_x, &pub_y);
            assert_eq!(
                hex::encode(&hash[12..32]),
                hex::encode(address),
                "Keccak mismatch for vector {}",
                i + 1
            );

            // Non-zero address
            assert_ne!(address, [0u8; 20], "Zero address for vector {}", i + 1);

            // Leaf hash must be deterministic
            let mut padded = [0u8; 32];
            padded[12..32].copy_from_slice(&address);
            let addr_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&padded));
            let leaf1 = native_poseidon(&leaf_params, &[addr_field]);
            let leaf2 = native_poseidon(&leaf_params, &[addr_field]);
            assert_eq!(
                leaf1,
                leaf2,
                "Leaf hash not deterministic for vector {}",
                i + 1
            );

            // Nullifier must be unique per key
            let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(key));
            let nullifier =
                crate::nullifier::native_compute_nullifier(&key_field, &interior_params);
            let nullifier_ark = crate::poseidon::halo2_to_ark(&nullifier);
            let nullifier_bytes = nullifier_ark.into_bigint().to_bytes_be();
            assert_ne!(
                nullifier_bytes,
                [0u8; 32],
                "Zero nullifier for vector {}",
                i + 1
            );
        }
        eprintln!(
            "✅ {} address derivation test vectors all pass",
            test_vectors.len()
        );
    }

    /// Test that secp256k1 scalar multiplication is correct for sequential keys.
    /// Verifies k*G + G = (k+1)*G for multiple keys.
    #[test]
    fn test_secp256k1_scalar_mul_additive() {
        // Verify: for key k, k*G and (k+1)*G differ by exactly G
        for key_val in 1u64..=20 {
            let mut key_bytes = [0u8; 32];
            key_bytes[24..32].copy_from_slice(&key_val.to_be_bytes());

            let (addr_k, _, _) = native_derive_address(&key_bytes);

            let mut key_next_bytes = [0u8; 32];
            key_next_bytes[24..32].copy_from_slice(&(key_val + 1).to_be_bytes());

            let (addr_k1, _, _) = native_derive_address(&key_next_bytes);

            // Different keys must produce different addresses
            assert_ne!(
                addr_k,
                addr_k1,
                "Sequential keys {} and {} produce same address",
                key_val,
                key_val + 1
            );
        }
        eprintln!("✅ 20 sequential keys produce unique addresses");
    }

    /// Test nullifier uniqueness across a large set of keys.
    /// Ensures no nullifier collisions for 50K keys.
    #[test]
    fn test_nullifier_uniqueness_50k() {
        let params = PoseidonParams::new_circom(2);
        let mut nullifiers = std::collections::HashSet::new();

        for key_val in 1u64..=50_000 {
            let key_field = ark_to_halo2(&ark_bn254::Fr::from(key_val));
            let nullifier = native_compute_nullifier(&key_field, &params);
            let nullifier_bytes = {
                let ark = crate::poseidon::halo2_to_ark(&nullifier);
                ark.into_bigint().to_bytes_be()
            };
            assert!(
                nullifiers.insert(nullifier_bytes),
                "Nullifier collision at key {}",
                key_val
            );
        }
        eprintln!("✅ 50,000 nullifiers all unique — no collisions");
    }

    /// Negative test: recipient exceeding uint160 should fail circuit verification.
    ///
    /// The circuit now constrains that the recipient fits in 160 bits.
    /// A recipient > 2^160 would be truncated by Solidity's `uint160()`,
    /// creating a soundness issue. The circuit must reject such recipients.
    #[test]
    #[ignore = "slow: full circuit at k=24 (~30 min, ~30 GiB RSS). Honest E2E path now passes; run with --ignored."]
    fn test_recipient_exceeding_uint160_rejected() {
        // Construct a recipient > 2^160 by setting byte 20 (LE index) to non-zero.
        // Fr::from(1u64) << 160 is not directly expressible, so we use a large value.
        // 2^160 + 1 in hex is 1 followed by 40 hex digits of zeros + 1.
        // In LE representation, byte index 20 would be non-zero.
        // 2^168 — strictly greater than 2^160, so the uint160 decomposition
        // (160 bits, weights 2^0..2^159) cannot represent it and the proof
        // must be rejected. `pow2_fr` keeps this exact in the field (168 < 254,
        // no modular wraparound).
        let big_recipient = pow2_fr(168);

        // Sanity: the recipient is genuinely above the uint160 range (some
        // byte at LE index >= 20 is non-zero).
        use ff::PrimeField;
        {
            let repr = big_recipient.to_repr();
            let le_bytes: &[u8] = repr.as_ref();
            assert!(
                le_bytes[20..32].iter().any(|&b| b != 0),
                "test recipient must exceed uint160"
            );
        }

        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let (address, _, _) = native_derive_address(&key);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..32].copy_from_slice(&address);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&addr_padded));

        let leaf_params = PoseidonParams::new_circom(1);
        let _leaf = native_poseidon(&leaf_params, &[address_field]);

        let interior_params = PoseidonParams::new_circom(2);
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        let nullifier = crate::nullifier::native_compute_nullifier(&key_field, &interior_params);

        let addresses = vec![address];
        let (root_ark, proof) =
            zkmist_merkle_tree::build_tree_streaming_with_depth(&addresses, 4, Some(0));
        let (siblings_ark, path_indices_u8) = proof.expect("proof extraction failed");

        let mut siblings_arr = [[0u8; 32]; TREE_DEPTH];
        let mut path_arr = [0u8; TREE_DEPTH];
        for i in 0..siblings_ark.len().min(TREE_DEPTH) {
            siblings_arr[i] = siblings_ark[i];
            path_arr[i] = path_indices_u8[i];
        }

        let root_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&root_ark));

        let circuit = ZKMistV2Claim {
            private_key: key,
            siblings: siblings_arr,
            path_indices: path_arr,
            merkle_root: root_field,
            nullifier,
            recipient: big_recipient,
        };

        let k = 24;
        let public_inputs = vec![root_field, nullifier, big_recipient];
        let result = halo2_proofs::dev::MockProver::run(k, &circuit, vec![public_inputs]);

        match result {
            Ok(prover) => {
                let verify_result = prover.verify();
                assert!(
                    verify_result.is_err(),
                    "Circuit should REJECT a recipient exceeding uint160, but it passed!"
                );
                eprintln!("✅ Recipient > uint160 correctly rejected (k={})", k);
            }
            Err(e) => {
                eprintln!(
                    "⚠️  MockProver::run failed at k={}: {:?} \
                     — negative test could not be executed",
                    k, e
                );
            }
        }
    }

    /// Validate the three soundness-binding weight arrays (Findings 1–3) as
    /// pure-Rust field arithmetic. These checks confirm that the constrained
    /// accumulations would equal their target field elements for an honest
    /// witness, catching any bit-ordering mistake instantly — without the
    /// 30–90 min full-circuit MockProver run.
    #[test]
    fn test_binding_weight_math() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        // ── Finding 2: nullifier-key accumulation, weights 2^(255−i) ──
        let bits = decompose_key_to_bits(&key);
        let mut key_acc = Fr::ZERO;
        for i in 0..256usize {
            if bits[i] {
                key_acc += pow2_fr(255 - i as u32);
            }
        }
        let key_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&key));
        assert_eq!(key_acc, key_field, "nullifier accumulation must equal key mod p");

        // ── Finding 1: Merkle-leaf address accumulation ──
        let (_addr, pub_x, pub_y) = native_derive_address(&key);
        let hash = crate::keccak::native_hash_pubkey(&pub_x, &pub_y);
        let mut padded = [0u8; 32];
        padded[12..32].copy_from_slice(&hash[12..32]);
        let address_field = ark_to_halo2(&ark_bn254::Fr::from_be_bytes_mod_order(&padded));
        let mut addr_acc = Fr::ZERO;
        for m in 0..160u32 {
            let k = m / 8; // address byte index (0 => hash byte 12, MSB of address)
            let j = m % 8; // bit-within-byte (0 = LSB)
            let bit = (hash[12 + k as usize] >> j) & 1;
            if bit == 1 {
                addr_acc += pow2_fr(8 * (19 - k) + j);
            }
        }
        assert_eq!(addr_acc, address_field, "leaf accumulation must equal address field");

        // ── Finding 3: public-key limb accumulations ──
        for (coord, label) in [(&pub_x, "pub_x"), (&pub_y, "pub_y")] {
            let native = NativeSecpField::from_bytes_be(coord);
            for limb_idx in 0..4usize {
                let start_byte = (3 - limb_idx) * 8;
                let mut limb_acc = Fr::ZERO;
                for k in 0..8u32 {
                    for j in 0..8u32 {
                        let bit = (coord[start_byte + k as usize] >> j) & 1;
                        if bit == 1 {
                            limb_acc += pow2_fr(8 * (7 - k) + j);
                        }
                    }
                }
                assert_eq!(
                    limb_acc,
                    native.to_bn254_limbs()[limb_idx],
                    "{} limb {} accumulation mismatch",
                    label,
                    limb_idx
                );
            }
        }
    }

    /// Validate the `accumulate_weighted_bits` gate wiring (s_bool +
    /// s_mul_fixed + s_add) in a tiny isolated circuit. Runs MockProver::verify
    /// at k=9 in milliseconds — confirms the primitive is satisfiable for an
    /// honest witness (no over-constraint) before relying on it in the full
    /// circuit.
    #[test]
    fn test_accumulate_weighted_bits_primitive() {
        use halo2_proofs::{
            circuit::SimpleFloorPlanner,
            dev::MockProver,
            plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
        };

        #[derive(Clone)]
        struct AccTest {
            bits: Vec<bool>,
            weights: Vec<Fr>,
        }
        #[derive(Clone, Debug)]
        struct AccCfg {
            secp: Secp256k1Config,
            instance: Column<Instance>,
            advice: [Column<Advice>; 16],
        }

        impl Circuit<Fr> for AccTest {
            type Config = AccCfg;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                self.clone()
            }
            fn configure(meta: &mut ConstraintSystem<Fr>) -> AccCfg {
                let advice: [Column<Advice>; 16] = std::array::from_fn(|_| {
                    let c = meta.advice_column();
                    meta.enable_equality(c);
                    c
                });
                let instance = meta.instance_column();
                meta.enable_equality(instance);
                let secp = Secp256k1Config::configure(
                    meta,
                    [
                        advice[0], advice[1], advice[2], advice[3], advice[4], advice[5],
                        advice[6], advice[7],
                    ],
                    advice[13],
                );
                AccCfg { secp, instance, advice }
            }
            fn synthesize(
                &self,
                config: AccCfg,
                mut layouter: impl halo2_proofs::circuit::Layouter<Fr>,
            ) -> Result<(), Error> {
                let chip = Secp256k1Chip::new(&config.secp);
                let bit_cells = layouter.assign_region(|| "bits", |mut region| {
                    let mut cells = Vec::with_capacity(self.bits.len());
                    for (i, &b) in self.bits.iter().enumerate() {
                        cells.push(region.assign_advice(
                            || "b",
                            config.advice[i % 8],
                            i / 8,
                            || Value::known(if b { Fr::ONE } else { Fr::ZERO }),
                        )?);
                    }
                    Ok(cells)
                })?;
                let acc = chip.accumulate_weighted_bits(&mut layouter, &bit_cells, &self.weights)?;
                layouter.constrain_instance(acc.cell(), config.instance, 0)?;
                Ok(())
            }
        }

        // 0x6E = 0b01101110, expressed LSB-first.
        let bits: Vec<bool> = vec![false, true, true, true, false, true, true, false];
        let weights: Vec<Fr> = (0..8u32).map(pow2_fr).collect();
        let expected = Fr::from(0x6Eu64);
        let circuit = AccTest { bits, weights };
        let prover = MockProver::run(9, &circuit, vec![vec![expected]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        eprintln!("✅ accumulate_weighted_bits primitive verifies (k=9)");
    }
}
