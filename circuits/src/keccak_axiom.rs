//! Axiom-stack Keccak-256 gadget — Phase 3 of the axiom backend migration
//! (see `docs/axiom-backend-migration.md`).
//!
//! Ports the hand-rolled PSE `keccak.rs` to the halo2-base `Context` eDSL. A
//! fully-constrained, bit-level Keccak-f[1600]: the 1600-bit state is a vector
//! of constrained boolean cells; the five round steps are expressed as
//! polynomial identities on bits — `XOR(a,b)=a+b−2ab`, `AND=ab`,
//! `ANDNOT=(1−a)·b`. ρ and π are pure index rearrangements (free). This is the
//! last hand-rolled crypto gadget; with it, every primitive the circuit needs
//! (secp, Poseidon, Keccak) has an axiom-stack implementation.
//!
//! Scope: single-block hashing of up to 135 bytes (the rate is 136 bytes), which
//! covers ZKMist's only use — `keccak256(pubkey_x_be ‖ pubkey_y_be)` on a fixed
//! 64-byte input. The Keccak padding (0x01 … 0x80) is fixed for a given input
//! length, so only the input bits are witnesses.
//!
//! # Cost note
//!
//! The algebraic (non-table) χ step makes this a heavy gadget (~5·10⁵ advice
//! cells, MockProver k≈19). This matches the weight of the PSE bit-level
//! Keccak; the migration's big win is the secp gadget (3700 hand-rolled lines →
//! audited ~1.3·10⁵ cells). A lookup-table χ (as PSE `zkevm-circuits` uses)
//! would shrink Keccak further toward the k=18 target — tracked as a follow-up.

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context, QuantumCell::Constant,
};

// ── Keccak-f[1600] constants ─────────────────────────────────────────────

/// Number of Keccak-f rounds.
const ROUNDS: usize = 24;

/// ι round constants (canonical Keccak-f[1600]).
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// ρ rotation offsets, indexed `[x][y]`.
const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Keccak rate in bytes (1088 bits / 8). Single-block inputs must be `< RATE`.
const RATE: usize = 136;

/// Flat state index of bit `z` (0..64) of lane `(x, y)` (x,y ∈ 0..5). Lanes are
/// laid out `lane = x + 5*y`, matching the standard `state[x + 5*y]` indexing.
#[inline]
fn idx(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * 64 + z
}

// ── Bit primitives ───────────────────────────────────────────────────────

/// Constrain and return `a XOR b`, assuming `a, b` are constrained booleans.
/// Uses the identity `a ⊕ b = a + b − 2ab` (3 cells: `ab`, `a+b`, `−2ab+(a+b)`).
fn xor_bit(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    a: AssignedValue<Fr>,
    b: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    let ab = gate.mul(ctx, a, b);
    let apb = gate.add(ctx, a, b);
    gate.mul_add(ctx, ab, Constant(-Fr::from(2u64)), apb) // -2·ab + (a+b)
}

/// XOR a slice of ≥1 bits together (fold). Each input must be a constrained bit.
fn xor_bits(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    bits: &[AssignedValue<Fr>],
) -> AssignedValue<Fr> {
    let mut acc = bits[0];
    for b in &bits[1..] {
        acc = xor_bit(ctx, gate, acc, *b);
    }
    acc
}

// ── Keccak-f[1600] permutation (1600 constrained bits in/out) ────────────

/// Run Keccak-f[1600] on a 1600-bit state (flat, lane-major: bit `z` of lane
/// `(x,y)` at index `idx(x,y,z)`). Returns the permuted 1600-bit state.
pub fn keccak_f1600(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    state: Vec<AssignedValue<Fr>>,
) -> Vec<AssignedValue<Fr>> {
    keccak_f1600_rounds(ctx, range, state, ROUNDS)
}

/// Debug entry point: run only `nrounds` rounds (exposed for differential
/// testing against the native permutation).
pub fn keccak_f1600_rounds(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    state: Vec<AssignedValue<Fr>>,
    nrounds: usize,
) -> Vec<AssignedValue<Fr>> {
    assert_eq!(state.len(), 1600);
    let gate = range.gate();
    let mut a = state;

    for round in 0..nrounds {
        // ── θ ──
        // C[x][z] = ⊕_y a[x][y][z]
        let mut c = [[a[0]; 64]; 5]; // placeholder, overwritten
        for x in 0..5 {
            for z in 0..64 {
                let lane_bits: Vec<AssignedValue<Fr>> =
                    (0..5).map(|y| a[idx(x, y, z)]).collect();
                c[x][z] = xor_bits(ctx, gate, &lane_bits);
            }
        }
        // D[x][z] = C[(x+4)%5][z] ⊕ C[(x+1)%5][(z-1)%64]   (rotate_left(1) of the lane)
        let mut d = [[a[0]; 64]; 5];
        for x in 0..5 {
            for z in 0..64 {
                let left = c[(x + 4) % 5][z];
                let right = c[(x + 1) % 5][(z + 63) % 64];
                d[x][z] = xor_bit(ctx, gate, left, right);
            }
        }
        // a[x][y][z] ^= D[x][z]
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let i = idx(x, y, z);
                    a[i] = xor_bit(ctx, gate, a[i], d[x][z]);
                }
            }
        }

        // ── ρ + π (pure reindexing — no constraints) ──
        // B[y + 5*((2x+3y)%5)][z] = A[x][y][(z - RHO[x][y]) % 64]
        let mut b = vec![a[0]; 1600]; // placeholder; every entry overwritten
        for x in 0..5 {
            for y in 0..5 {
                let dest_lane = y + 5 * ((2 * x + 3 * y) % 5);
                let off = (RHO_OFFSETS[x][y] as usize) % 64;
                for z in 0..64 {
                    let src_z = (z + 64 - off) % 64;
                    b[dest_lane * 64 + z] = a[idx(x, y, src_z)];
                }
            }
        }

        // ── χ ──
        // A[x][y][z] = B[x][y][z] ⊕ ((¬B[(x+1)%5][y][z]) ∧ B[(x+2)%5][y][z])
        let mut new_a = vec![a[0]; 1600];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let cur = b[idx(x, y, z)];
                    let n1 = b[idx((x + 1) % 5, y, z)];
                    let n2 = b[idx((x + 2) % 5, y, z)];
                    let not_n1 = gate.not(ctx, n1); // 1 - n1
                    let andnot = gate.and(ctx, not_n1, n2); // (¬n1) ∧ n2
                    new_a[idx(x, y, z)] = xor_bit(ctx, gate, cur, andnot);
                }
            }
        }

        // ── ι ── A[0][0] ^= RC[round]  (flip bits where RC has a 1) ──
        let rc = RC[round];
        for z in 0..64 {
            if (rc >> z) & 1 == 1 {
                new_a[idx(0, 0, z)] = gate.not(ctx, new_a[idx(0, 0, z)]);
            }
        }

        a = new_a;
    }
    a
}

// ── Sponge: keccak256 of a single-block input (≤ 135 bytes) ──────────────

/// Pad an input of length `n` (0..=135) to the 136-byte rate and return the
/// 1088 rate bits (LSB-first per byte). Index `r*8 + b` holds bit `b` of byte
/// `r` for `r in 0..RATE`.
fn padded_rate_bits(n: usize) -> [bool; 1088] {
    assert!(n < RATE);
    let mut bits = [false; 1088];
    // 0x01 at byte n (LSB), 0x80 at the last rate byte (bit 7).
    bits[n * 8] = true;
    bits[(RATE - 1) * 8 + 7] = true;
    bits
}

/// Constrain and return `keccak256(input)` as 32 constrained byte cells (each
/// in `[0, 255]`), for a single-block `input` of length `0..=135` bytes. Each
/// `input` byte must already be constrained to `[0, 255]` (e.g. from the secp
/// byte-bridge).
pub fn keccak256(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    input: &[AssignedValue<Fr>],
) -> Vec<AssignedValue<Fr>> {
    let n = input.len();
    let gate = range.gate();
    let zero = ctx.load_constant(Fr::zero());
    let one = ctx.load_constant(Fr::one());

    // Decompose each input byte into 8 constrained LE bits.
    let mut input_bits: Vec<Vec<AssignedValue<Fr>>> = Vec::with_capacity(n);
    for byte in input {
        // range-check the byte, then bit-decompose (num_to_bits forces the byte
        // value = Σ bit·2^k with each bit constrained to {0,1}).
        range.range_check(ctx, *byte, 8);
        input_bits.push(gate.num_to_bits(ctx, *byte, 8));
    }

    // Assemble the 1600-bit state. Rate byte `r` bit `b` lives at index `r*8+b`
    // (since lane = r/8, lane-bit = (r%8)*8+b ⇒ flat = r*8+b). Capacity = 0.
    let pad = padded_rate_bits(n);
    let mut state: Vec<AssignedValue<Fr>> = vec![zero; 1600];
    for r in 0..RATE {
        for b in 0..8 {
            let bit_cell = if r < n {
                input_bits[r][b]
            } else if pad[r * 8 + b] {
                one
            } else {
                zero
            };
            state[r * 8 + b] = bit_cell;
        }
    }

    // Permute.
    let state = keccak_f1600(ctx, range, state);

    // Squeeze the first 32 bytes (bytes 0..32, i.e. lanes 0..3).
    let byte_bases = [1u64, 2, 4, 8, 16, 32, 64, 128].map(Fr::from);
    let mut hash_bytes = Vec::with_capacity(32);
    for byte_idx in 0..32u32 {
        let bits = &state[(byte_idx as usize) * 8..(byte_idx as usize + 1) * 8];
        let byte = gate.inner_product(
            ctx,
            bits.iter().copied(),
            byte_bases.iter().map(|c| Constant(*c)),
        );
        hash_bytes.push(byte);
    }
    hash_bytes
}
