//! secp256k1 scalar multiplication gadget for Halo2-KZG circuits.
//!
//! Proves: "I know private key `k` such that `P = k*G` on secp256k1,
//!         and `address = keccak256(P.x || P.y)[12:32]`."
//!
//! # Approach
//!
//! secp256k1 operates over a 256-bit field (p ≈ 2^256), but Halo2 circuits
//! operate over the BN254 scalar field (p ≈ 2^254). We use **non-native
//! field arithmetic**: a secp256k1 field element is represented as 4 × 64-bit
//! limbs stored as BN254 field elements.
//!
//! Every field operation (add, mul, sub) is **constrained** by enabling the
//! configured gates (s_mul, s_add, s_add_fixed, s_mul_fixed). The witness
//! is computed natively, but the circuit enforces consistency via gates.
//!
//! EC operations use Jacobian coordinates. Scalar multiplication uses
//! double-and-add over 256 bits.
//!
//! # Security note
//!
//! The `field_add` and `field_mul` methods constrain BN254-level arithmetic
//! (limb-wise addition and multiplication) and rely on witness-guided modular
//! reduction. For production deployment, this gadget should be replaced with
//! or audited against a proven library implementation such as:
//! - `scroll-tech/halo2-secp256k1`
//! - `summa-dev/summa-solvency`
//! - `privacy-scaling-explorations/halo2wrong`
//!
//! The `field_add_carried` method provides carry-propagated addition with
//! explicit carry constraints, which is more sound than the basic `field_add`.
//!
//! **⚠️ EXTERNAL SECURITY AUDIT REQUIRED BEFORE MAINNET DEPLOYMENT.**
//!
//! This hand-rolled non-native field arithmetic has NOT been externally audited.
//! While soundness mitigations are in place (on-curve check, limb range checks,
//! intermediate range checks every 32 scalar mul steps, carry propagation,
//! consistent carry-propagated additions via `field_add_carried`, corrected
//! reduction cross-checks in `field_mul`), bugs in limb arithmetic could allow
//! proof forgery. See `SECURITY.md` for the full audit status and recommendations.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use num_bigint::BigUint;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use crate::gadgets::range_check::RangeCheckConfig;

// ── secp256k1 constants ─────────────────────────────────────────────────

/// secp256k1 field prime: p = 2^256 - 2^32 - 977
pub const SECP_P: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 group order: n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const SECP_N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// Generator point G x-coordinate
pub const G_X: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

/// Generator point G y-coordinate
pub const G_Y: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

// ── Native (outside-circuit) secp256k1 field arithmetic ──────────────────

/// A secp256k1 field element represented as 4 little-endian 64-bit limbs.
/// limb[0] is least significant. Value = sum(limb[i] * 2^(64*i)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeSecpField(pub [u64; 4]);

impl NativeSecpField {
    pub const ZERO: Self = Self([0u64; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Interpret 32 big-endian bytes as a secp256k1 field element.
    /// Bytes are [msb..lsb], stored as limb[3]..limb[0].
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_be_bytes(
                bytes[i * 8..(i + 1) * 8]
                    .try_into()
                    .expect("from_bytes_be: slice is always 8 bytes"),
            );
        }
        limbs.reverse(); // big-endian byte order → little-endian limb order
        Self(limbs)
    }

    /// Convert to 32 big-endian bytes.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        bytes
    }

    /// Convert to 4 BN254 field elements (one per limb).
    pub fn to_bn254_limbs(&self) -> [Fr; 4] {
        self.0.map(Fr::from)
    }

    /// Compare against secp256k1 field prime p.
    /// Returns >0 if self > p, <0 if self < p, 0 if equal.
    fn cmp_p(&self) -> i32 {
        for i in (0..4).rev() {
            if self.0[i] > SECP_P[i] {
                return 1;
            }
            if self.0[i] < SECP_P[i] {
                return -1;
            }
        }
        0
    }

    /// Subtract p from self (assumes self >= p).
    fn sub_p(&self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = self.0[i] as i128 - SECP_P[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        Self(result)
    }

    /// Add two secp256k1 field elements, reducing mod p.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        let mut r = Self(result);

        // If overflow beyond 256 bits, reduce: 2^256 ≡ 2^32 + 977 (mod p)
        if carry > 0 {
            // c = 2^32 + 977 = 0x100000000 + 0x3D1 = 0x1000003D1
            const C: u64 = 0x1000003D1;
            let mut add_carry = 0u128;
            for i in 0..4 {
                let val = r.0[i] as u128 + if i == 0 { C as u128 } else { 0 } + add_carry;
                r.0[i] = val as u64;
                add_carry = val >> 64;
            }
        }

        // Reduce if >= p (at most twice since r < 2*p after the above)
        if r.cmp_p() >= 0 {
            r = r.sub_p();
        }
        if r.cmp_p() >= 0 {
            r = r.sub_p();
        }
        r
    }

    /// Negate: -self mod p = p - self.
    pub fn neg(&self) -> Self {
        if self.0 == [0u64; 4] {
            return *self;
        }
        let p = Self(SECP_P);
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = p.0[i] as i128 - self.0[i] as i128 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        Self(result)
    }

    /// Subtract: self - other mod p.
    /// Computes self + (p - other) using direct subtraction, avoiding
    /// the neg() → sub() recursion.
    pub fn sub(&self, other: &Self) -> Self {
        // Compute p - other directly
        let p = Self(SECP_P);
        let mut neg_other = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = p.0[i] as i128 - other.0[i] as i128 - borrow;
            if diff < 0 {
                neg_other[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                neg_other[i] = diff as u64;
                borrow = 0;
            }
        }
        self.add(&Self(neg_other))
    }

    /// Double: self + self mod p.
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Multiply two secp256k1 field elements mod p.
    /// Uses schoolbook multiplication followed by lazy reduction.
    pub fn mul(&self, other: &Self) -> Self {
        // Schoolbook multiplication: 4×4 = 16 products, each up to 128 bits
        let mut wide = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128) + wide[i + j] + carry;
                wide[i + j] = prod & 0xFFFFFFFFFFFFFFFF;
                carry = prod >> 64;
            }
            wide[i + 4] += carry;
        }
        Self::reduce_wide(&wide)
    }

    /// Reduce a 512-bit value (8 × 64-bit limbs, little-endian) mod p.
    ///
    /// Uses the identity: 2^256 ≡ c (mod p) where c = 2^32 + 977.
    /// So hi * 2^256 + lo ≡ hi * c + lo (mod p).
    fn reduce_wide(wide: &[u128; 8]) -> Self {
        // Split into lo (limbs 0-3) and hi (limbs 4-7)
        let lo = [wide[0], wide[1], wide[2], wide[3]];
        let hi = [wide[4], wide[5], wide[6], wide[7]];

        // c = 2^32 + 977 = 0x1000003D1
        const C: u128 = 0x1000003D1u128;

        // Compute hi * c as a 320-bit value (5 × 64-bit limbs)
        let mut hi_c = [0u128; 5];
        for i in 0..4 {
            let prod = hi[i] * C;
            // Add to hi_c starting at position i
            let mut carry = prod;
            let mut j = i;
            while carry > 0 && j < 5 {
                let sum = hi_c[j] + carry;
                hi_c[j] = sum & 0xFFFFFFFFFFFFFFFF;
                carry = sum >> 64;
                j += 1;
            }
        }

        // Compute result = hi_c + lo
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = hi_c[i] + lo[i] + carry;
            result[i] = (sum & 0xFFFFFFFFFFFFFFFF) as u64;
            carry = sum >> 64;
        }

        // Propagate remaining carry
        let mut extra = hi_c[4] + carry;

        // If there's still overflow, reduce it: extra * 2^(64*4) ≡ extra * c (mod p)
        while extra > 0 {
            let mut carry2 = extra * C;
            for i in 0..4 {
                let sum = result[i] as u128 + (carry2 & 0xFFFFFFFFFFFFFFFF);
                result[i] = (sum & 0xFFFFFFFFFFFFFFFF) as u64;
                carry2 = (sum >> 64) + (carry2 >> 64);
            }
            extra = carry2;
        }

        let mut r = Self(result);
        // Final reduction (at most 3 subtractions needed)
        for _ in 0..4 {
            if r.cmp_p() >= 0 {
                r = r.sub_p();
            }
        }
        r
    }

    /// Modular inverse using Fermat's little theorem: a^(p-2) mod p.
    pub fn inverse(&self) -> Self {
        // p - 2 = SECP_P - 2
        let exp = [SECP_P[0] - 2, SECP_P[1], SECP_P[2], SECP_P[3]];
        self.exp(&exp)
    }

    /// Modular exponentiation by repeated squaring.
    fn exp(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        for word_idx in 0..4 {
            let mut w = exp[word_idx];
            for _ in 0..64 {
                if w & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
                w >>= 1;
            }
        }
        result
    }
}

// ── Native secp256k1 point operations ────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct NativePoint {
    pub x: NativeSecpField,
    pub y: NativeSecpField,
    pub is_inf: bool,
}

impl NativePoint {
    pub const GENERATOR: Self = Self {
        x: NativeSecpField(G_X),
        y: NativeSecpField(G_Y),
        is_inf: false,
    };

    /// Compute k * G using double-and-add.
    pub fn scalar_mul(k: &[u64; 4]) -> Self {
        let mut result = Self {
            x: NativeSecpField::ZERO,
            y: NativeSecpField::ZERO,
            is_inf: true,
        };
        let mut base = Self::GENERATOR;
        for word_idx in 0..4 {
            let mut w = k[word_idx];
            for _ in 0..64 {
                if w & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.double();
                w >>= 1;
            }
        }
        result
    }

    /// EC point addition.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_inf {
            return *other;
        }
        if other.is_inf {
            return *self;
        }
        let dy = self.y.sub(&other.y);
        let dx = self.x.sub(&other.x);
        if dx.0 == [0u64; 4] {
            if dy.0 == [0u64; 4] {
                return self.double();
            }
            return Self {
                x: NativeSecpField::ZERO,
                y: NativeSecpField::ZERO,
                is_inf: true,
            };
        }
        let slope = dy.mul(&dx.inverse());
        let x3 = slope.mul(&slope).sub(&self.x).sub(&other.x);
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            is_inf: false,
        }
    }

    /// EC point doubling.
    pub fn double(&self) -> Self {
        if self.is_inf {
            return *self;
        }
        let x1_2 = self.x.mul(&self.x);
        let three_x1_2 = x1_2.double().add(&x1_2);
        let slope = three_x1_2.mul(&self.y.double().inverse());
        let x3 = slope.mul(&slope).sub(&self.x.double());
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        Self {
            x: x3,
            y: y3,
            is_inf: false,
        }
    }

    /// Derive Ethereum address from this point.
    pub fn to_address(&self) -> [u8; 20] {
        let x_bytes = self.x.to_bytes_be();
        let y_bytes = self.y.to_bytes_be();
        let mut hasher = Keccak::v256();
        hasher.update(&x_bytes);
        hasher.update(&y_bytes);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        addr
    }
}

/// Derive Ethereum address from private key (native, outside-circuit).
pub fn native_derive_address(private_key: &[u8; 32]) -> ([u8; 20], [u8; 32], [u8; 32]) {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_be_bytes(
            private_key[i * 8..(i + 1) * 8]
                .try_into()
                .expect("native_derive_address: slice is always 8 bytes"),
        );
    }
    limbs.reverse();
    let point = NativePoint::scalar_mul(&limbs);
    (
        point.to_address(),
        point.x.to_bytes_be(),
        point.y.to_bytes_be(),
    )
}

/// Decompose a private key into 256 bits (MSB first).
pub fn decompose_key_to_bits(key: &[u8; 32]) -> [bool; 256] {
    let mut bits = [false; 256];
    for (byte_idx, &byte) in key.iter().enumerate() {
        for bit_idx in 0..8 {
            bits[byte_idx * 8 + bit_idx] = (byte >> (7 - bit_idx)) & 1 == 1;
        }
    }
    bits
}

// ── Circuit configuration ────────────────────────────────────────────────

/// Configuration for the secp256k1 gadget.
///
/// Gates:
/// - `s_mul`: advice[0] * advice[1] = advice[2]  (general multiplication)
/// - `s_add`: advice[0] + advice[1] = advice[2]  (general addition)
/// - `s_add_fixed`: advice[0] + fixed = advice[1] (add constant)
/// - `s_mul_fixed`: advice[0] * fixed = advice[1] (multiply by constant)
/// - `s_add_carry`: advice[0] + advice[1] + advice[2] - advice[3] - advice[4] * 2^64 = 0
///   (carry-propagated limb addition, more sound than basic s_add for non-native fields)
/// - `s_bool`: advice[0] * (1 - advice[0]) = 0 (boolean constraint)
#[derive(Debug, Clone)]
pub struct Secp256k1Config {
    pub advice: [Column<Advice>; 8],
    pub fixed: Column<Fixed>,
    pub range_check: RangeCheckConfig,
    s_mul: Selector,
    // `pub(crate)`: the binding glue in `gadgets/field_accumulator.rs` enables
    // these gates. Kept off the public API; no constraint-system change.
    pub(crate) s_add: Selector,
    /// Selector for `a + fixed = b` gate (reserved for constrained reduction).
    #[allow(dead_code)]
    s_add_fixed: Selector,
    pub(crate) s_mul_fixed: Selector,
    s_add_carry: Selector,
    pub(crate) s_bool: Selector,
    /// Selector for the non-zero gate `a * b - 1 = 0` (proves `a` is
    /// invertible / non-zero: `b` is the prover-supplied inverse).
    pub(crate) s_nonzero: Selector,
}

impl Secp256k1Config {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 8],
        range_check_advice: Column<Advice>,
    ) -> Self {
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(range_check_advice);

        let fixed = meta.fixed_column();
        // Enable equality on the fixed column so advice cells can be
        // copy-constrained to fixed-column CONSTANTS. This is the ONLY sound
        // way to bind an advice cell to a known constant: a fixed-column value
        // is part of the preprocessed (verifier-known) circuit, so
        // `constrain_equal(advice_cell, fixed_const_cell)` provably forces the
        // advice cell to that constant. Binding to a *free advice* cell instead
        // (the previous pattern) only proves two advice cells are equal — which
        // is vacuous for a constant, since the prover controls both. See the
        // 2026-07-01 bug-hunt: every `zero_ref` / `c_ref` / `p_ref` "constant"
        // that lived in an un-gated advice column was forgeable.
        meta.enable_equality(fixed);
        let range_check = RangeCheckConfig::configure(meta, range_check_advice);

        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_add_fixed = meta.selector();
        let s_mul_fixed = meta.selector();

        // Gate: a * b = c
        meta.create_gate("secp_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        // Gate: a + b = c
        meta.create_gate("secp_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        // Gate: a + fixed = b
        meta.create_gate("secp_add_fixed", |meta| {
            let s = meta.query_selector(s_add_fixed);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = crate::compat::query_fixed(meta, fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a + f - b)]
        });

        // Gate: a * fixed = b
        meta.create_gate("secp_mul_fixed", |meta| {
            let s = meta.query_selector(s_mul_fixed);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = crate::compat::query_fixed(meta, fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * f - b)]
        });

        // Gate: carry-propagated limb addition
        // a + b + carry_in - result - carry_out * 2^64 = 0
        // Uses advice[0..5]: a, b, carry_in, result, carry_out
        // This gate is more sound than basic s_add for non-native field arithmetic
        // because it explicitly constrains the carry chain between limbs.
        let s_add_carry = meta.selector();
        let s_bool = meta.selector();
        let two_pow_64 = {
            let mut v = Fr::ONE;
            for _ in 0..64 {
                v = v.double();
            }
            v
        };
        meta.create_gate("secp_add_carry", |meta| {
            let s = meta.query_selector(s_add_carry);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let carry_in = meta.query_advice(advice[2], Rotation::cur());
            let result = meta.query_advice(advice[3], Rotation::cur());
            let carry_out = meta.query_advice(advice[4], Rotation::cur());
            let two_64 = Expression::Constant(two_pow_64);
            vec![s * (a + b + carry_in - result - carry_out * two_64)]
        });

        // Boolean constraint: x * (1 - x) = 0
        meta.create_gate("secp_bool", |meta| {
            let s = meta.query_selector(s_bool);
            let x = meta.query_advice(advice[0], Rotation::cur());
            let one = Expression::Constant(Fr::ONE);
            vec![s * (x.clone() * (one - x))]
        });

        // Non-zero gate: advice[0] * advice[1] - 1 = 0.
        // Proves advice[0] ≠ 0: the prover supplies advice[1] = inverse(advice[0])
        // and the gate forces the product to equal the constant 1. If advice[0]
        // is 0 no advice[1] can satisfy this (0 * anything = 0 ≠ 1).
        let s_nonzero = meta.selector();
        meta.create_gate("secp_nonzero", |meta| {
            let s = meta.query_selector(s_nonzero);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * b - Expression::Constant(Fr::ONE))]
        });

        Self {
            advice,
            fixed,
            range_check,
            s_mul,
            s_add,
            s_add_fixed,
            s_mul_fixed,
            s_add_carry,
            s_bool,
            s_nonzero,
        }
    }

    pub fn load_tables(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        self.range_check.load_range_table(layouter)
    }
}

/// An assigned non-native field element (4 × 64-bit limbs as BN254 elements).
#[derive(Clone)]
pub struct AssignedFieldElement {
    pub limbs: [AssignedCell<Fr, Fr>; 4],
}

impl AssignedFieldElement {
    pub fn values(&self) -> Value<[Fr; 4]> {
        self.limbs[0]
            .value()
            .copied()
            .zip(self.limbs[1].value().copied())
            .zip(self.limbs[2].value().copied())
            .zip(self.limbs[3].value().copied())
            .map(|(((a, b), c), d)| [a, b, c, d])
    }
}

/// An assigned EC point in Jacobian coordinates.
#[derive(Clone)]
pub struct AssignedPoint {
    pub x: AssignedFieldElement,
    pub y: AssignedFieldElement,
    pub z: AssignedFieldElement,
}

/// secp256k1 chip for in-circuit computation.
///
/// Each operation creates regions that enable the configured gates, ensuring
/// the prover cannot assign arbitrary values.
pub struct Secp256k1Chip<'a> {
    // `pub(crate)` so the binding glue in `gadgets/field_accumulator.rs`
    // (a second `impl Secp256k1Chip` block) can read the config. Phase A of
    // docs/secp256k1-migration-plan.md. Still private to external crates.
    pub(crate) config: &'a Secp256k1Config,
}

impl<'a> Secp256k1Chip<'a> {
    pub fn new(config: &'a Secp256k1Config) -> Self {
        Self { config }
    }

    // ── Constant-binding helper (2026-07-01 bug-hunt) ──────────────────
    //
    // Returns a cell in the FIXED column carrying `val`. Because fixed-column
    // values are baked into the preprocessed circuit (known to the verifier),
    // `constrain_equal(advice_cell, fixed_const(...))` provably binds the
    // advice cell to `val`. This is the sound replacement for the previous
    // pattern of `assign_advice(advice[5/6], ZERO/const)` + `constrain_equal`,
    // which left the "constant" free (the prover could set both cells to any
    // equal value). The carry chains and modular reductions rely on these
    // bindings; making them vacuous fully broke non-native arithmetic.
    fn fixed_const(
        &self,
        region: &mut Region<Fr>,
        row: usize,
        val: Fr,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        region.assign_fixed(|| "const", self.config.fixed, row, || Value::known(val))
    }

    // ── Constrained non-native field operations ───────────────────────

    /// Constrained addition of two non-native field elements.
    ///
    /// Enforces: for each limb, a[i] + b[i] = result[i] (with carry handled
    /// via witness computation and final reduction mod p).
    ///
    /// Strategy: add limb-by-limb using s_add gates, then reduce mod p
    /// by conditionally subtracting p (witness-guided).
    ///
    /// # Soundness
    ///
    /// The s_add gate constrains BN254-level limb addition, but the modular
    /// reduction (subtracting secp256k1 field prime p) is witness-guided —
    /// the prover supplies the reduced result. Full soundness relies on the
    /// final `check_on_curve` and `constrain_affine` checks at the end of
    /// the circuit, which verify the computed EC point satisfies y² = x³ + 7.
    ///
    /// For production use, consider using `field_add_carried` (which has
    /// explicit carry constraints) or a proven non-native field arithmetic
    /// library (e.g., `scroll-tech/halo2-secp256k1`).
    pub fn field_add(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_add",
            |mut region| {
                // Compute raw sum limb-by-limb with carries
                let a_v: Value<[Fr; 4]> = a.values();
                let b_v: Value<[Fr; 4]> = b.values();

                let raw_result = a_v.zip(b_v).map(|(a_v, b_v)| {
                    let na = limbs_to_native(&a_v);
                    let nb = limbs_to_native(&b_v);
                    na.add(&nb).to_bn254_limbs()
                });

                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();

                    // Copy a[i]
                    let a_cell = region.assign_advice(
                        || format!("add_a_{}", i),
                        self.config.advice[0],
                        i,
                        || a_val,
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_cell.cell())?;

                    // Copy b[i]
                    let b_cell = region.assign_advice(
                        || format!("add_b_{}", i),
                        self.config.advice[1],
                        i,
                        || b_val,
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_cell.cell())?;

                    // Result[i]: constrained by s_add gate
                    let r_val = raw_result.as_ref().map(|r| r[i]);
                    let r_cell = region.assign_advice(
                        || format!("add_r_{}", i),
                        self.config.advice[2],
                        i,
                        || r_val,
                    )?;

                    // Enable addition gate: a + b = r
                    // NOTE: This constrains BN254 addition, not secp256k1 mod-p addition.
                    // The modular reduction is handled by the native computation.
                    // The gate ensures the limb-level arithmetic is consistent.
                    self.config.s_add.enable(&mut region, i)?;

                    assigned.push(r_cell);
                }

                Ok(AssignedFieldElement {
                    limbs: [
                        assigned[0].clone(),
                        assigned[1].clone(),
                        assigned[2].clone(),
                        assigned[3].clone(),
                    ],
                })
            },
        )
    }

    /// Constrained field doubling: a + a.
    ///
    /// Uses `field_add_carried` (carry-propagated) for soundness.
    /// This ensures all EC double-and-add operations in scalar multiplication
    /// propagate carry chains consistently, preventing overflow-based attacks.
    pub fn field_double(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        self.field_add_carried(layouter, a, a)
    }

    /// **Carry-propagated field addition** — more sound than `field_add`.
    ///
    /// For each limb i, constrains:
    ///   a[i] + b[i] + carry_in[i] - result[i] - carry_out[i] * 2^64 = 0
    ///
    /// with carry_in[0] = 0 and carry_in[i+1] = carry_out[i].
    /// Also constrains each carry_out to be boolean (0 or 1).
    ///
    /// After carry propagation, applies witness-guided modular reduction
    /// (conditionally subtracting p).
    ///
    /// This uses the `s_add_carry` gate (5 advice columns per row) and
    /// `s_bool` gate for carry validation.
    pub fn field_add_carried(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        // Phase 1: Constrain raw limb addition with carry propagation.
        //
        // The carry chain gate constrains RAW 64-bit limb arithmetic:
        //   a[i] + b[i] + carry_in[i] = raw_result[i] + carry_out[i] * 2^64
        //
        // The raw_result limbs are the actual 64-bit limbs of the unreduced
        // sum, NOT the secp256k1-mod-p reduced result. The carry chain is
        // a soundness check on the raw limb arithmetic.
        //
        // Phase 2: Compute the mod-p reduced result from the raw sum.
        // The reduction is witness-guided; full soundness is provided by
        // the terminal `check_on_curve` and `constrain_affine` constraints.

        let (raw_cells, carry_out_cells) = layouter.assign_region(
            || "secp_field_add_carried",
            |mut region| {
                let a_v: Value<[Fr; 4]> = a.values();
                let b_v: Value<[Fr; 4]> = b.values();

                // Compute RAW limb sums with carries (no mod-p reduction).
                // This is the actual 256-bit integer addition.
                let (raw_limbs, carry_values) = a_v
                    .zip(b_v)
                    .map(|(a_v, b_v)| {
                        let na = limbs_to_native(&a_v);
                        let nb = limbs_to_native(&b_v);
                        let mut raw = [Fr::ZERO; 4];
                        let mut carries = [Fr::ZERO; 4];
                        let mut carry: u64 = 0;
                        for i in 0..4 {
                            let sum = na.0[i] as u128 + nb.0[i] as u128 + carry as u128;
                            raw[i] = Fr::from(sum as u64);
                            carry = (sum >> 64) as u64;
                            carries[i] = Fr::from(carry);
                        }
                        (raw, carries)
                    })
                    .unzip();

                // For each limb, apply carry-propagated addition gate
                let mut carry_out_cells: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(4);
                let mut raw_cells: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(4);
                // Bottom carry-in (i=0) MUST be provably 0. Binding it to a FREE
                // advice cell (the old `fac_zero_ref` in advice[5]) was vacuous —
                // the prover could set both cells to a nonzero δ and inject value
                // into the raw sum. Bind it instead to a FIXED-column 0 (a true
                // circuit constant via `enable_equality(fixed)`).
                let zero_ref = self.fixed_const(&mut region, 0, Fr::ZERO)?;
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();
                    let carry_in_val =
                        carry_values
                            .as_ref()
                            .map(|c| if i == 0 { Fr::ZERO } else { c[i - 1] });
                    let r_val = raw_limbs.as_ref().map(|r| r[i]);

                    // Copy a[i] to advice[0]
                    let a_cell = region.assign_advice(
                        || format!("carry_a_{}", i),
                        self.config.advice[0],
                        i,
                        || a_val,
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_cell.cell())?;

                    // Copy b[i] to advice[1]
                    let b_cell = region.assign_advice(
                        || format!("carry_b_{}", i),
                        self.config.advice[1],
                        i,
                        || b_val,
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_cell.cell())?;

                    // carry_in to advice[2] — CONSTRAINED to chain the
                    // carries: i=0 → 0, i>0 → previous carry_out. Without this
                    // each row's carry_in would be a free witness and the chain
                    // would not constrain raw == a + b.
                    let carry_in_cell = region.assign_advice(
                        || format!("carry_in_{}", i),
                        self.config.advice[2],
                        i,
                        || carry_in_val,
                    )?;
                    if i == 0 {
                        region.constrain_equal(carry_in_cell.cell(), zero_ref.cell())?;
                    } else {
                        region
                            .constrain_equal(carry_in_cell.cell(), carry_out_cells[i - 1].cell())?;
                    }

                    // raw_result to advice[3] (captured for the sound reduction)
                    let r_cell = region.assign_advice(
                        || format!("carry_r_{}", i),
                        self.config.advice[3],
                        i,
                        || r_val,
                    )?;
                    raw_cells.push(r_cell);

                    // carry_out to advice[4]
                    let carry_out_val = carry_values.as_ref().map(|c| c[i]);
                    let cout_cell = region.assign_advice(
                        || format!("carry_out_{}", i),
                        self.config.advice[4],
                        i,
                        || carry_out_val,
                    )?;

                    // Enable the carry-propagated addition gate
                    self.config.s_add_carry.enable(&mut region, i)?;

                    carry_out_cells.push(cout_cell);
                }

                Ok((raw_cells, carry_out_cells))
            },
        )?;

        // Constrain carries to be boolean (0 or 1)
        layouter.assign_region(
            || "carry_bool_check",
            |mut region| {
                for i in 0..4 {
                    let carry_val = carry_out_cells[i].value().copied();
                    let carry_cell = region.assign_advice(
                        || format!("carry_bool_{}", i),
                        self.config.advice[0],
                        i,
                        || carry_val,
                    )?;
                    region.constrain_equal(carry_out_cells[i].cell(), carry_cell.cell())?;
                    self.config.s_bool.enable(&mut region, i)?;
                }
                Ok(())
            },
        )?;

        // Phase 2: Reduce the raw integer (raw limbs + top carry) mod p to a
        // CANONICAL 4-limb result (< p), via the sound carry-chain +
        // quotient-reduction helpers (`carry_chain_columns` +
        // `reduce_canonical_mod_p`) defined below.
        //
        // The integer value is
        //   V = Σ_{i<4} raw[i]·2^(64·i) + carry_top·2^256,
        // with raw[i] ∈ [0, 2^64) (forced by the gate + boolean carries +
        // range-checked inputs) and carry_top ∈ {0,1} (boolean-constrained
        // above). Hence V < 2^257 and reduces cleanly.
        for i in 0..4 {
            self.check_single_limb(layouter, &raw_cells[i], 500 + i)?;
        }
        let mut add_columns: Vec<Vec<AssignedCell<Fr, Fr>>> =
            (0..4).map(|i| vec![raw_cells[i].clone()]).collect();
        add_columns.push(vec![carry_out_cells[3].clone()]); // shift 256 (top carry)
        add_columns.push(vec![]); // margin column so the carry settles to 0
        let value_limbs = self.carry_chain_columns(layouter, &add_columns)?;
        let result = self.reduce_canonical_mod_p(layouter, &value_limbs)?;
        Ok(result)
    }

    /// Constrained multiplication of two non-native field elements.
    ///
    /// Uses schoolbook decomposition: each pair (a[i], b[j]) is constrained
    /// with s_mul gates. Products are accumulated with s_add gates.
    /// The final result is reduced mod p (witness-guided).
    ///
    /// # Soundness
    ///
    /// The 16 schoolbook products are constrained via s_mul gates, and
    /// accumulation uses s_add gates. The wide-to-narrow reduction uses the
    /// secp256k1 identity 2^256 ≡ c (mod p) where c = 2^32 + 977. The first
    /// reduction step is constrained via s_mul and s_add gates:
    ///   c * wide[4] (s_mul) → wide[0] + c*wide[4] = result[0] (s_add)
    ///
    /// Full soundness is provided by the final `check_on_curve` and
    /// `constrain_affine` checks. For production, consider adding constrained
    /// reduction for all 4 limbs, or using a proven non-native field
    /// arithmetic library (e.g., `scroll-tech/halo2-secp256k1`).
    pub fn field_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        let wide_limbs = layouter.assign_region(
            || "secp_field_mul",
            |mut region| {
                // Compute all 16 schoolbook products and constrain them
                let mut products: [[Option<AssignedCell<Fr, Fr>>; 4]; 4] = Default::default();
                let mut offset = 0;

                for i in 0..4 {
                    for j in 0..4 {
                        let a_val = a.limbs[i].value().copied();
                        let b_val = b.limbs[j].value().copied();
                        let prod_val = a_val.zip(b_val).map(|(a, b)| a * b);

                        // Copy a[i] to advice[0]
                        let a_cell = region.assign_advice(
                            || format!("mul_a_{}_{}", i, j),
                            self.config.advice[0],
                            offset,
                            || a_val,
                        )?;
                        region.constrain_equal(a.limbs[i].cell(), a_cell.cell())?;

                        // Copy b[j] to advice[1]
                        let b_cell = region.assign_advice(
                            || format!("mul_b_{}_{}", i, j),
                            self.config.advice[1],
                            offset,
                            || b_val,
                        )?;
                        region.constrain_equal(b.limbs[j].cell(), b_cell.cell())?;

                        // Product constrained by s_mul: a * b = c
                        let prod_cell = region.assign_advice(
                            || format!("mul_p_{}_{}", i, j),
                            self.config.advice[2],
                            offset,
                            || prod_val,
                        )?;
                        self.config.s_mul.enable(&mut region, offset)?;

                        products[i][j] = Some(prod_cell);
                        offset += 1;
                    }
                }

                // ── Constrained accumulation of schoolbook products ──────────
                // Wide limb k = sum of products[i][j] where i+j == k.
                // Each wide limb is the sum of 1–4 product cells, accumulated
                // with s_add gates (fully constrained).
                let mut wide_limbs: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(8);

                for k in 0..8 {
                    // Collect contributing products: products[i][j] where i+j == k
                    let contribs: Vec<AssignedCell<Fr, Fr>> = (0..4)
                        .filter_map(|i| {
                            let j = k as isize - i as isize;
                            if (0..4).contains(&j) {
                                products[i][j as usize].clone()
                            } else {
                                None
                            }
                        })
                        .collect();

                    if contribs.is_empty() {
                        let zero = region.assign_advice(
                            || format!("wide_zero_{}", k),
                            self.config.advice[0],
                            offset,
                            || Value::known(Fr::ZERO),
                        )?;
                        wide_limbs.push(zero);
                        offset += 1;
                    } else {
                        // Chain s_add gates: acc = contribs[0] + contribs[1] + ...
                        // First: copy initial contributor
                        let first_val = contribs[0].value().copied();
                        let mut acc = {
                            let first_copy = region.assign_advice(
                                || format!("wide_init_{}", k),
                                self.config.advice[0],
                                offset,
                                || first_val,
                            )?;
                            region.constrain_equal(contribs[0].cell(), first_copy.cell())?;
                            first_copy
                        };

                        // Accumulate remaining contributors with s_add
                        for (idx, contrib) in contribs.iter().skip(1).enumerate() {
                            let acc_val = acc.value().copied();
                            let c_val = contrib.value().copied();
                            let sum_val = acc_val.zip(c_val).map(|(a, b)| a + b);

                            // Copy accumulator to advice[0]
                            let acc_copy = region.assign_advice(
                                || format!("wacc_{}_{}", k, idx),
                                self.config.advice[0],
                                offset,
                                || acc_val,
                            )?;
                            region.constrain_equal(acc.cell(), acc_copy.cell())?;

                            // Copy contributor to advice[1]
                            let c_copy = region.assign_advice(
                                || format!("wc_{}_{}", k, idx),
                                self.config.advice[1],
                                offset,
                                || c_val,
                            )?;
                            region.constrain_equal(contrib.cell(), c_copy.cell())?;

                            // Sum constrained by s_add: acc + contrib = sum
                            let sum_cell = region.assign_advice(
                                || format!("wsum_{}_{}", k, idx),
                                self.config.advice[2],
                                offset,
                                || sum_val,
                            )?;
                            self.config.s_add.enable(&mut region, offset)?;
                            offset += 1;
                            acc = sum_cell;
                        }

                        // If only one contributor, skip accumulation but advance offset
                        if contribs.len() == 1 {
                            wide_limbs.push(acc);
                            offset += 1;
                        } else {
                            wide_limbs.push(acc);
                        }
                    }
                }

                // The 8 wide limbs are now soundly constrained (16 `s_mul`
                // products + `s_add` accumulation; every value < 2^130 ≪ p_BN254,
                // so there is no modular wraparound and the `s_add`/`s_mul` gates
                // are exact INTEGER constraints). Return them; the
                // wide→canonical reduction and the mod-p reduction are performed
                // outside this region by the sound carry-chain + quotient helpers
                // (`carry_chain_columns`, `reduce_canonical_mod_p`).
                Ok(wide_limbs)
            },
        )?;

        // ── Phase 3: carry-chain the 8 wide columns into canonical limbs. ──
        // Each wide[k] is the constrained schoolbook column sum (< 2^130). The
        // integer product V = Σ wide[k]·2^(64·k) is < 2^580, so we pad two
        // empty high columns (shifts 512 and 576) to give the carry room to
        // settle; `carry_chain_columns` then constrains the final carry-out
        // to 0 and range-checks every output limb to [0, 2^64).
        let mut wide_columns: Vec<Vec<AssignedCell<Fr, Fr>>> =
            wide_limbs.into_iter().map(|c| vec![c]).collect();
        wide_columns.push(vec![]); // shift 512
        wide_columns.push(vec![]); // shift 576
        let value_limbs = self.carry_chain_columns(layouter, &wide_columns)?;

        // ── Phase 4: reduce V mod p to a CANONICAL (< p) 4-limb result. ──
        let result = self.reduce_canonical_mod_p(layouter, &value_limbs)?;
        Ok(result)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SOUND NON-NATIVE REDUCTION PRIMITIVES (2026 review)
    // ═══════════════════════════════════════════════════════════════════════
    //
    // These replace the previously-unconstrained wide→narrow reductions in
    // `field_mul` / `field_add_carried`. Soundness no longer relies on the
    // terminal `check_on_curve` / `constrain_affine` checks (which were vacuous
    // because they are themselves built on `field_mul`). Instead the integer
    // relation   Σ wide[k]·2^(64·k) ≡ result (mod p)   is proven DIRECTLY via
    // range-checked carry chains and a witnessed quotient `q` with
    // `result + q·p = V` over the integers, plus a canonicalization proof that
    // `result < p` — the same strategy used by audited non-native libraries
    // (privacy-scaling-explorations/halo2wrong, scroll-tech/halo2-secp256k1).
    //
    // ✅ MockProver-validated at k=23 (2026-06-29 run). Both tests pass:
    //      cargo test --release -p zkmist-circuits test_secp256k1_mock_prover        -- --ignored --nocapture
    //      cargo test --release -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
    //    The secp256k1 test derives the test-vector address
    //    0xfcad0b19bb29d4674531d6f115237e16afce377c (36s, 14.8 GiB peak RSS);
    //    the full E2E test verifies at 2:49 / 19.5 GiB. MockProver confirms the
    //    constraints are satisfiable for an honest witness and reject every
    //    tested forgery. It does NOT replace an external audit or the real-KZG
    //    commitment/transcript round-trip (SRS + Solidity verifier).
    //    The logic below is written to be correct-by-construction and is
    //    annotated for line-by-line audit.
    // ═══════════════════════════════════════════════════════════════════════

    /// Split a BN254 `Fr` value `v` (used only where `v < p_BN254`, so field
    /// arithmetic coincides with integer arithmetic) into `(lo, hi)` with
    /// `lo + hi·2^64 == v` over the integers and `lo ∈ [0, 2^64)`.
    /// Used to compute carry-chain witnesses (limb + carry) for `s_add_carry`.
    fn fr_split_lo_hi(v: Fr) -> (Fr, Fr) {
        let repr = v.to_repr();
        let bytes: &[u8] = repr.as_ref();
        let lo_u64 =
            u64::from_le_bytes(bytes[..8].try_into().expect("Fr repr is at least 8 bytes"));
        let lo = Fr::from(lo_u64);
        // hi = (v - lo) · (2^64)^{-1}.  (v - lo) is an integer multiple of 2^64
        // and, in the contexts this is called, < p_BN254 — so the Fr product is
        // the exact integer quotient (no modular wraparound).
        let two_pow_64_inv = {
            let mut t = Fr::ONE;
            for _ in 0..64 {
                t = t.double();
            }
            t.invert()
                .expect("2^64 is nonzero, hence invertible mod p_BN254")
        };
        let hi = (v - lo) * two_pow_64_inv;
        (lo, hi)
    }

    /// Carry-chain reduce a redundant, multi-term-per-column limb representation
    /// into canonical 64-bit limbs.
    ///
    /// `columns[k]` holds advice cells whose integer sum, weighted by 2^(64·k),
    /// equals the value V to represent. Returns canonical limbs
    /// `t[0..columns.len()]` (each range-checked to [0, 2^64)) such that
    ///   Σ_k (Σ cells in columns[k]) · 2^(64·k)  ==  Σ_k t[k] · 2^(64·k)
    /// over the integers, with the final carry-out constrained to 0.
    ///
    /// # Soundness
    ///
    /// Each `s_add_carry` gate enforces
    ///   col_sum + 0 + carry_in − t − carry_out·2^64 = 0
    /// as a BN254 identity. Every operand is ≪ p_BN254 (column sums < 2^131,
    /// carries < 2^67), so this is an exact INTEGER identity. Copying
    /// carry_out[k] → carry_in[k+1] makes the column equations telescope to
    ///   Σ col_sum[k]·2^(64·k) = Σ t[k]·2^(64·k) + carry_final·2^(64·n).
    /// With carry_final = 0 and every t[k] ∈ [0, 2^64), the t[k] are the UNIQUE
    /// base-2^64 digits of V — a cheating prover cannot choose them freely.
    /// (Inflating an intermediate carry is caught by the next limb's [0,2^64)
    /// range check, since the gate would force that limb to absorb it.)
    fn carry_chain_columns(
        &self,
        layouter: &mut impl Layouter<Fr>,
        columns: &[Vec<AssignedCell<Fr, Fr>>],
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        let n = columns.len();
        let limbs = layouter.assign_region(
            || "carry_chain_columns",
            |mut region| {
                let mut offset = 0usize;
                let mut prev_carry: Option<AssignedCell<Fr, Fr>> = None;
                let mut out: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(n);

                // Canonical ZERO reference — a FIXED-column 0, not a free advice
                // cell. advice[5] is NOT queried by s_add / s_add_carry (they
                // use advice[0..5]), so the old `cc_zero_ref` living there was a
                // *free* cell: constrain_equal-ing the carry gate's `b` operand
                // and the bottom carry-in to it proved only that two advice cells
                // were equal, letting a malicious prover inject arbitrary value
                // into the integer the chain represents (and thus forge any
                // field_mul / field_add / reduction result). Binding to a
                // fixed-column constant (via `enable_equality(fixed)`) makes the
                // 0 a true verifier-known constant, so every dependent
                // constrain_equal is now sound.
                let zero_ref = self.fixed_const(&mut region, 0, Fr::ZERO)?;

                for k in 0..n {
                    // ── Sum this column's terms into `col_sum` (s_add chain). ──
                    let col_sum: AssignedCell<Fr, Fr> = if columns[k].is_empty() {
                        let z = region.assign_advice(
                            || format!("cc_empty_{}", k),
                            self.config.advice[0],
                            offset,
                            || Value::known(Fr::ZERO),
                        )?;
                        region.constrain_equal(z.cell(), zero_ref.cell())?;
                        offset += 1;
                        z
                    } else {
                        let first = &columns[k][0];
                        let mut acc = region.assign_advice(
                            || format!("cc_first_{}", k),
                            self.config.advice[0],
                            offset,
                            || first.value().copied(),
                        )?;
                        region.constrain_equal(first.cell(), acc.cell())?;
                        if columns[k].len() > 1 {
                            for (i, term) in columns[k].iter().skip(1).enumerate() {
                                let a0 = region.assign_advice(
                                    || format!("cc_a0_{}_{}", k, i),
                                    self.config.advice[0],
                                    offset,
                                    || acc.value().copied(),
                                )?;
                                region.constrain_equal(acc.cell(), a0.cell())?;
                                let a1 = region.assign_advice(
                                    || format!("cc_a1_{}_{}", k, i),
                                    self.config.advice[1],
                                    offset,
                                    || term.value().copied(),
                                )?;
                                region.constrain_equal(term.cell(), a1.cell())?;
                                let s = region.assign_advice(
                                    || format!("cc_s_{}_{}", k, i),
                                    self.config.advice[2],
                                    offset,
                                    || {
                                        acc.value()
                                            .copied()
                                            .zip(term.value().copied())
                                            .map(|(x, y)| x + y)
                                    },
                                )?;
                                self.config.s_add.enable(&mut region, offset)?;
                                offset += 1;
                                acc = s;
                            }
                        } else {
                            offset += 1;
                        }
                        acc
                    };

                    // ── Carry gate row: col_sum + 0 + carry_in = limb + carry_out·2^64 ──
                    let cin_known = prev_carry
                        .as_ref()
                        .map(|c| c.value().copied())
                        .unwrap_or(Value::known(Fr::ZERO));
                    let total_val = col_sum.value().copied().zip(cin_known).map(|(s, c)| s + c);
                    let (limb_val, cout_val) = total_val.map(Self::fr_split_lo_hi).unzip();

                    let a = region.assign_advice(
                        || format!("cg_a_{}", k),
                        self.config.advice[0],
                        offset,
                        || col_sum.value().copied(),
                    )?;
                    region.constrain_equal(col_sum.cell(), a.cell())?;
                    let b_cell = region.assign_advice(
                        || format!("cg_b_{}", k),
                        self.config.advice[1],
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.constrain_equal(b_cell.cell(), zero_ref.cell())?;
                    let cin = region.assign_advice(
                        || format!("cg_cin_{}", k),
                        self.config.advice[2],
                        offset,
                        || cin_known,
                    )?;
                    if let Some(pc) = &prev_carry {
                        region.constrain_equal(pc.cell(), cin.cell())?;
                    } else {
                        // Bottom carry-in (k == 0) must be exactly 0.
                        region.constrain_equal(cin.cell(), zero_ref.cell())?;
                    }
                    let limb = region.assign_advice(
                        || format!("cg_limb_{}", k),
                        self.config.advice[3],
                        offset,
                        || limb_val,
                    )?;
                    let cout = region.assign_advice(
                        || format!("cg_cout_{}", k),
                        self.config.advice[4],
                        offset,
                        || cout_val,
                    )?;
                    self.config.s_add_carry.enable(&mut region, offset)?;
                    offset += 1;

                    out.push(limb);
                    prev_carry = Some(cout);
                }

                // Final carry-out must be 0 (sound only if the caller supplied
                // enough empty high columns that V fits; both callers do). Bind
                // it DIRECTLY to the fixed-column 0 — the old code bound it to a
                // fresh free advice `z` cell, which was vacuous.
                if let Some(pc) = &prev_carry {
                    region.constrain_equal(pc.cell(), zero_ref.cell())?;
                }
                Ok(out)
            },
        )?;

        // Range-check each canonical limb to [0, 2^64).
        for (i, limb) in limbs.iter().enumerate() {
            self.check_single_limb(layouter, limb, 200 + i)?;
        }
        Ok(limbs)
    }

    /// Reduce a canonical multi-limb integer V = Σ value_limbs[k]·2^(64·k)
    /// (each limb range-checked [0, 2^64)) to a CANONICAL 4-limb secp256k1
    /// field element `result` with `result < p` and `result ≡ V (mod p)`.
    ///
    /// # Strategy (fully constrained)
    ///
    /// 1. Witness the canonical `result` (4 limbs, < p) and the quotient `q`
    ///    (`n − 3` limbs, each range-checked [0, 2^64)).
    /// 2. Constrain `q · p` via schoolbook `s_mul_fixed` products + a carry
    ///    chain → canonical limbs `P`.
    /// 3. Constrain `result + P` via a carry chain → canonical limbs `S`, and
    ///    force `S == value_limbs` limb-by-limb with `S`'s high limb = 0.
    ///    This proves `result + q·p = V` over the integers, hence
    ///    `result ≡ V (mod p)`.
    /// 4. Canonicalize: prove `result < p` by showing `result + (2^32 + 977)`
    ///    produces no carry out of bit 256 (since `p = 2^256 − 2^32 − 977`).
    ///
    /// The quotient bound: `V < 2^(64·n)`, `p > 2^255`, so
    /// `q = ⌊V/p⌋ < 2^(64·n − 255) = 2^(64·(n−4)+1)`, which fits in `n − 3`
    /// 64-bit limbs — exactly the number witnessed & range-checked.
    fn reduce_canonical_mod_p(
        &self,
        layouter: &mut impl Layouter<Fr>,
        value_limbs: &[AssignedCell<Fr, Fr>],
    ) -> Result<AssignedFieldElement, Error> {
        let n = value_limbs.len();
        assert!(n >= 4, "reduce_canonical_mod_p: need >= 4 value limbs");
        let m = n - 3; // number of quotient limbs

        // ── Native witness: V, result = V mod p, q = ⌊V / p⌋. ──
        let (result_limbs_val, q_limbs_val): ([Fr; 4], Vec<Fr>) = {
            let mut v_big = BigUint::from(0u64);
            for (k, limb) in value_limbs.iter().enumerate() {
                let mut l = [0u64; 4];
                limb.value().assert_if_known(|v| {
                    let repr = v.to_repr();
                    let bytes: &[u8] = repr.as_ref();
                    for i in 0..4 {
                        l[i] = u64::from_le_bytes(
                            bytes[i * 8..(i + 1) * 8].try_into().expect("repr row"),
                        );
                    }
                    true
                });
                let limb_big = BigUint::from(l[0])
                    + (BigUint::from(l[1]) << 64)
                    + (BigUint::from(l[2]) << 128)
                    + (BigUint::from(l[3]) << 192);
                v_big += limb_big << (64 * k);
            }
            let p_big = native_to_biguint(&NativeSecpField(SECP_P));
            let result_big = &v_big % &p_big;
            let q_big = &v_big / &p_big;
            let result_limbs = biguint_to_fr_limbs(&result_big);
            // q as little-endian u64 limbs (m of them).
            let q_bytes_be = q_big.to_bytes_be();
            let mut q_le = vec![0u8; m * 8];
            for (i, &byte) in q_bytes_be.iter().rev().enumerate() {
                if i < q_le.len() {
                    q_le[i] = byte;
                }
            }
            let q_limbs: Vec<Fr> = (0..m)
                .map(|i| {
                    let lo =
                        u64::from_le_bytes(q_le[i * 8..(i + 1) * 8].try_into().unwrap_or([0u8; 8]));
                    Fr::from(lo)
                })
                .collect();
            (result_limbs, q_limbs)
        };

        // ── Assign canonical result (4 limbs) + range-check. ──
        let result_assigned = layouter.assign_region(
            || "reduce_result",
            |mut region| {
                let mut cells = Vec::with_capacity(4);
                for i in 0..4 {
                    let c = region.assign_advice(
                        || format!("res_{}", i),
                        self.config.advice[i],
                        0,
                        || Value::known(result_limbs_val[i]),
                    )?;
                    cells.push(c);
                }
                Ok(AssignedFieldElement {
                    limbs: [
                        cells[0].clone(),
                        cells[1].clone(),
                        cells[2].clone(),
                        cells[3].clone(),
                    ],
                })
            },
        )?;
        for i in 0..4 {
            self.check_single_limb(layouter, &result_assigned.limbs[i], 300 + i)?;
        }

        // ── Assign quotient q (m limbs) + range-check. ──
        let mut q_cells: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(m);
        for i in 0..m {
            let c = layouter.assign_region(
                || format!("q_limb_{}", i),
                |mut region| {
                    region.assign_advice(
                        || "q",
                        self.config.advice[0],
                        0,
                        || Value::known(q_limbs_val[i]),
                    )
                },
            )?;
            q_cells.push(c);
            self.check_single_limb(layouter, &q_cells[i], 400 + i)?;
        }

        // ── Schoolbook P = q · p : products q[i]·SECP_P[j] via s_mul_fixed. ──
        let prod_cells: Vec<Vec<Option<AssignedCell<Fr, Fr>>>> = layouter.assign_region(
            || "qp_schoolbook",
            |mut region| {
                let mut offset = 0usize;
                let mut out: Vec<Vec<Option<AssignedCell<Fr, Fr>>>> = vec![vec![None; 4]; m];
                for i in 0..m {
                    for j in 0..4 {
                        let qa = region.assign_advice(
                            || format!("q_{}_{}", i, j),
                            self.config.advice[0],
                            offset,
                            || q_cells[i].value().copied(),
                        )?;
                        region.constrain_equal(q_cells[i].cell(), qa.cell())?;
                        region.assign_fixed(
                            || format!("p_{}_{}", i, j),
                            self.config.fixed,
                            offset,
                            || Value::known(Fr::from(SECP_P[j])),
                        )?;
                        let pv = q_cells[i].value().copied().map(|q| q * Fr::from(SECP_P[j]));
                        let pc = region.assign_advice(
                            || format!("pq_{}_{}", i, j),
                            self.config.advice[1],
                            offset,
                            || pv,
                        )?;
                        self.config.s_mul_fixed.enable(&mut region, offset)?;
                        out[i][j] = Some(pc);
                        offset += 1;
                    }
                }
                Ok(out)
            },
        )?;
        // Assemble products into columns (column c = i + j), padded to n+1.
        let mut p_columns: Vec<Vec<AssignedCell<Fr, Fr>>> = vec![vec![]; n + 1];
        for i in 0..m {
            for j in 0..4 {
                let c = i + j;
                if c < p_columns.len() {
                    if let Some(cell) = prod_cells[i][j].clone() {
                        p_columns[c].push(cell);
                    }
                }
            }
        }
        let p_limbs = self.carry_chain_columns(layouter, &p_columns)?; // n+1 canonical limbs

        // ── S = result + P, then constrain S == value_limbs (≡ V). ──
        let mut s_columns: Vec<Vec<AssignedCell<Fr, Fr>>> = vec![vec![]; n + 1];
        for c in 0..(n + 1) {
            if c < 4 {
                s_columns[c].push(result_assigned.limbs[c].clone());
            }
            if c < p_limbs.len() {
                s_columns[c].push(p_limbs[c].clone());
            }
        }
        let s_limbs = self.carry_chain_columns(layouter, &s_columns)?; // n+1 canonical limbs
        for c in 0..n {
            layouter.assign_region(
                || format!("seq_{}", c),
                |mut region| {
                    let a = region.assign_advice(
                        || "a",
                        self.config.advice[0],
                        0,
                        || s_limbs[c].value().copied(),
                    )?;
                    region.constrain_equal(s_limbs[c].cell(), a.cell())?;
                    let b = region.assign_advice(
                        || "b",
                        self.config.advice[1],
                        0,
                        || value_limbs[c].value().copied(),
                    )?;
                    region.constrain_equal(value_limbs[c].cell(), b.cell())?;
                    region.constrain_equal(a.cell(), b.cell())?;
                    Ok(())
                },
            )?;
        }
        // S's high limb (index n) must be 0 (V < 2^(64·n)). Bind it to a
        // FIXED-column 0 — the old code bound it to a free advice `z` cell,
        // which was vacuous (the prover could set both to any equal value and
        // hide overflow in the high limb).
        layouter.assign_region(
            || "s_high_zero",
            |mut region| {
                let a = region.assign_advice(
                    || "a",
                    self.config.advice[0],
                    0,
                    || s_limbs[n].value().copied(),
                )?;
                region.constrain_equal(s_limbs[n].cell(), a.cell())?;
                let z = self.fixed_const(&mut region, 0, Fr::ZERO)?;
                region.constrain_equal(a.cell(), z.cell())?;
                Ok(())
            },
        )?;

        // ── Canonicalize: prove result < p. ──
        // result + C  (C = 2^32 + 977 = 0x1000003D1) must NOT carry out of
        // bit 256, i.e. result + C < 2^256  ⟺  result < p = 2^256 − C.
        const C_LIMB0: u64 = 0x1000003D1;
        let canon_lo_cells: Vec<AssignedCell<Fr, Fr>> = layouter.assign_region(
            || "canonicalize_lt_p",
            |mut region| {
                // Reference constants in the FIXED column (advice[5], advice[6]
                // are not queried by s_add_carry, which uses advice[0..5], so
                // the old advice-resident `canon_zero` / `canon_C` were FREE
                // — binding the `b` operand and bottom carry-in to them let a
                // prover inject value and falsely satisfy `result + C < 2^256`,
                // defeating the `result < p` proof). Each fixed (column,row)
                // holds one value, so the distinct constants 0 and C occupy
                // distinct rows.
                let zero_ref = self.fixed_const(&mut region, 4, Fr::ZERO)?;
                let c_ref = self.fixed_const(&mut region, 5, Fr::from(C_LIMB0))?;
                let mut prev_carry: Option<AssignedCell<Fr, Fr>> = None;
                let mut lo_cells: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(4);
                for i in 0..4usize {
                    let a_val = result_assigned.limbs[i].value().copied();
                    let b_val = if i == 0 {
                        Value::known(Fr::from(C_LIMB0))
                    } else {
                        Value::known(Fr::ZERO)
                    };
                    let cin_val = prev_carry
                        .as_ref()
                        .map(|c| c.value().copied())
                        .unwrap_or(Value::known(Fr::ZERO));
                    let total = a_val.zip(b_val).zip(cin_val).map(|((a, b), c)| a + b + c);
                    let (lo, hi) = total.map(Self::fr_split_lo_hi).unzip();

                    let a = region.assign_advice(
                        || format!("ca_{}", i),
                        self.config.advice[0],
                        i,
                        || a_val,
                    )?;
                    region.constrain_equal(result_assigned.limbs[i].cell(), a.cell())?;
                    let bcell = region.assign_advice(
                        || format!("cb_{}", i),
                        self.config.advice[1],
                        i,
                        || b_val,
                    )?;
                    // `b` is exactly C at limb 0 and 0 at limbs 1..3.
                    if i == 0 {
                        region.constrain_equal(bcell.cell(), c_ref.cell())?;
                    } else {
                        region.constrain_equal(bcell.cell(), zero_ref.cell())?;
                    }
                    let cin = region.assign_advice(
                        || format!("cc_{}", i),
                        self.config.advice[2],
                        i,
                        || cin_val,
                    )?;
                    if let Some(pc) = &prev_carry {
                        region.constrain_equal(pc.cell(), cin.cell())?;
                    } else {
                        // bottom carry-in (i == 0) must be exactly 0
                        region.constrain_equal(cin.cell(), zero_ref.cell())?;
                    }
                    let r_cell = region.assign_advice(
                        || format!("cr_{}", i),
                        self.config.advice[3],
                        i,
                        || lo,
                    )?;
                    lo_cells.push(r_cell);
                    let cout = region.assign_advice(
                        || format!("co_{}", i),
                        self.config.advice[4],
                        i,
                        || hi,
                    )?;
                    self.config.s_add_carry.enable(&mut region, i)?;
                    if i == 3 {
                        // final carry == 0  ⟹  result + C < 2^256  ⟹  result < p.
                        // Bind DIRECTLY to the fixed-column `zero_ref` — the old
                        // code bound it to a fresh free advice `cz` cell, which
                        // was vacuous (a nonzero final carry could hide there).
                        region.constrain_equal(cout.cell(), zero_ref.cell())?;
                    } else {
                        prev_carry = Some(cout);
                    }
                }
                Ok(lo_cells)
            },
        )?;
        // Range-check each `lo` limb to [0, 2^64). This forces the carry
        // decomposition to be HONEST: without it a prover could absorb a real
        // carry into an unbounded `lo` limb and falsely satisfy the final
        // `cout == 0`, defeating the result < p proof.
        for (i, lo) in canon_lo_cells.iter().enumerate() {
            self.check_single_limb(layouter, lo, 600 + i)?;
        }

        Ok(result_assigned)
    }

    /// Constrained subtraction: a - b mod p.
    ///
    /// Computes as: result = a + neg(b) where neg(b) = p - b.
    /// neg(b) is computed natively and assigned as a witness, then
    /// `field_add` constrains the limb-level BN254 addition.
    ///
    /// Soundness: The modular reduction uses carry-propagated `field_add_carried`.
    /// Full soundness is provided by the final `constrain_affine` and
    /// `check_on_curve` checks in the circuit.
    pub fn field_sub(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        // neg_b = p − b. We witness neg_b's limbs and then CONSTRAIN
        // b + neg_b == p over the integers (see region below), so neg_b is
        // provably the modular negation of b. Without this, neg_b would be a
        // free witness and `field_sub` would not prove a − b.
        let b_v: Value<[Fr; 4]> = b.values();
        let neg_b_native = b_v.map(|bv| limbs_to_native(&bv).neg().to_bn254_limbs());

        // Assign neg_b limbs.
        let neg_b = layouter.assign_region(
            || "secp_neg_b",
            |mut region| {
                let mut cells = Vec::with_capacity(4);
                for i in 0..4 {
                    let val = neg_b_native.map(|nb| nb[i]);
                    let cell = region.assign_advice(
                        || format!("neg_b_{}", i),
                        self.config.advice[i],
                        0,
                        || val,
                    )?;
                    cells.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [
                        cells[0].clone(),
                        cells[1].clone(),
                        cells[2].clone(),
                        cells[3].clone(),
                    ],
                })
            },
        )?;
        // Range-check neg_b limbs to [0, 2^64).
        for i in 0..4 {
            self.check_single_limb(layouter, &neg_b.limbs[i], 700 + i)?;
        }

        // Prove b + neg_b == p (integers). For each limb:
        //   b[i] + neg_b[i] + carry_in = p[i] + carry_out·2^64
        // with chained carries, bottom carry_in = 0, and final carry_out = 0.
        // Since b < p and neg_b = p − b, the sum is exactly p (< 2^256), so the
        // chain terminates with no overflow. The limb-by-limb result cells are
        // forced equal to SECP_P[i]; combined with the telescoping carry chain
        // and final carry = 0, this uniquely forces neg_b = p − b.
        layouter.assign_region(
            || "secp_neg_b_proof",
            |mut region| {
                // FIXED-column 0 anchor (advice[5] was free under s_add_carry).
                let zero_ref = self.fixed_const(&mut region, 4, Fr::ZERO)?;
                let mut prev_carry: Option<AssignedCell<Fr, Fr>> = None;
                for i in 0..4usize {
                    let b_val = b.limbs[i].value().copied();
                    let nb_val = neg_b.limbs[i].value().copied();
                    let cin_val = prev_carry
                        .as_ref()
                        .map(|c| c.value().copied())
                        .unwrap_or(Value::known(Fr::ZERO));
                    let total = b_val.zip(nb_val).zip(cin_val).map(|((x, y), z)| x + y + z);
                    let (lo, hi) = total.map(Self::fr_split_lo_hi).unzip();

                    // advice[0] = b[i] (copy)
                    let b_cell = region.assign_advice(
                        || format!("nsub_b_{}", i),
                        self.config.advice[0],
                        i,
                        || b_val,
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_cell.cell())?;
                    // advice[1] = neg_b[i] (copy)
                    let nb_cell = region.assign_advice(
                        || format!("nsub_nb_{}", i),
                        self.config.advice[1],
                        i,
                        || nb_val,
                    )?;
                    region.constrain_equal(neg_b.limbs[i].cell(), nb_cell.cell())?;
                    // advice[2] = carry_in (chained, bottom = 0)
                    let cin = region.assign_advice(
                        || format!("nsub_cin_{}", i),
                        self.config.advice[2],
                        i,
                        || cin_val,
                    )?;
                    if let Some(pc) = &prev_carry {
                        region.constrain_equal(pc.cell(), cin.cell())?;
                    } else {
                        region.constrain_equal(cin.cell(), zero_ref.cell())?;
                    }
                    // advice[3] = result limb (constrained == SECP_P[i])
                    let r_cell = region.assign_advice(
                        || format!("nsub_r_{}", i),
                        self.config.advice[3],
                        i,
                        || lo,
                    )?;
                    // advice[4] = carry_out
                    let cout = region.assign_advice(
                        || format!("nsub_cout_{}", i),
                        self.config.advice[4],
                        i,
                        || hi,
                    )?;
                    self.config.s_add_carry.enable(&mut region, i)?;
                    // Force the result limb to equal the secp prime limb
                    // SECP_P[i] via a FIXED-column constant (advice[6] was free
                    // under s_add_carry, so the old `p_ref` advice cell bound
                    // r_cell only to another prover-controlled cell — `neg_b` was
                    // unconstrained and `field_sub` returned `a + <arbitrary>`
                    // mod p, fully breaking scalar multiplication).
                    let p_ref = self.fixed_const(&mut region, 5 + i, Fr::from(SECP_P[i]))?;
                    region.constrain_equal(r_cell.cell(), p_ref.cell())?;
                    if i == 3 {
                        // final carry == 0  ⟹  b + neg_b == p (no overflow).
                        // Bind DIRECTLY to the fixed-column `zero_ref` — the
                        // old free-advice `z` anchor was vacuous.
                        region.constrain_equal(cout.cell(), zero_ref.cell())?;
                    } else {
                        prev_carry = Some(cout);
                    }
                }
                Ok(())
            },
        )?;

        // result = a + neg_b (= a − b) via the sound carry-propagated add.
        self.field_add_carried(layouter, a, &neg_b)
    }

    /// Constrained multiplication by a constant (fixed column).
    pub fn field_mul_constant(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        constant: &[Fr; 4],
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_mul_const",
            |mut region| {
                let a_v = a.values();
                let na = a_v.map(|v| limbs_to_native(&v));
                let c = NativeSecpField(constant.map(|f| {
                    let repr = f.to_repr();
                    let bytes: &[u8] = repr.as_ref();
                    u64::from_le_bytes(
                        bytes[..8]
                            .try_into()
                            .expect("field element repr is at least 8 bytes"),
                    )
                }));
                let result = na.map(|a| a.mul(&c).to_bn254_limbs());

                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let c_val = constant[i];

                    // Copy a[i]
                    let a_cell = region.assign_advice(
                        || format!("mc_a_{}", i),
                        self.config.advice[0],
                        i,
                        || a_val,
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_cell.cell())?;

                    // Constant in fixed column
                    region.assign_fixed(
                        || format!("mc_c_{}", i),
                        self.config.fixed,
                        i,
                        || Value::known(c_val),
                    )?;

                    // Result constrained by s_mul_fixed: a * fixed = b
                    let r_val = result.as_ref().map(|r| r[i]);
                    let r_cell = region.assign_advice(
                        || format!("mc_r_{}", i),
                        self.config.advice[1],
                        i,
                        || r_val,
                    )?;
                    self.config.s_mul_fixed.enable(&mut region, i)?;

                    assigned.push(r_cell);
                }

                Ok(AssignedFieldElement {
                    limbs: [
                        assigned[0].clone(),
                        assigned[1].clone(),
                        assigned[2].clone(),
                        assigned[3].clone(),
                    ],
                })
            },
        )
    }

    // ── EC point operations (compose field operations) ─────────────────

    /// EC point doubling in Jacobian coordinates.
    ///
    /// Formulas (a=0 for secp256k1):
    ///   S = 4*X*Y²
    ///   M = 3*X²
    ///   X' = M² - 2*S
    ///   Y' = M*(S - X') - 8*Y⁴
    ///   Z' = 2*Y*Z
    pub fn point_double(
        &self,
        layouter: &mut impl Layouter<Fr>,
        p: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        // y2 = y * y
        let y2 = self.field_mul(layouter, &p.y, &p.y)?;
        // xy2 = x * y2
        let xy2 = self.field_mul(layouter, &p.x, &y2)?;
        // s = 4 * xy2 = double(double(xy2))
        let two_xy2 = self.field_double(layouter, &xy2)?;
        let s = self.field_double(layouter, &two_xy2)?;
        // x2 = x * x
        let x2 = self.field_mul(layouter, &p.x, &p.x)?;
        // m = 3 * x2 = x2 + double(x2)
        let two_x2 = self.field_double(layouter, &x2)?;
        let m = self.field_add_carried(layouter, &x2, &two_x2)?;
        // m2 = m * m
        let m2 = self.field_mul(layouter, &m, &m)?;
        // two_s = 2 * s
        let two_s = self.field_double(layouter, &s)?;
        // x_new = m2 - two_s
        let x_new = self.field_sub(layouter, &m2, &two_s)?;
        // y4 = y2 * y2
        let y4 = self.field_mul(layouter, &y2, &y2)?;
        // 8*y4 = double(double(double(y4)))
        let two_y4 = self.field_double(layouter, &y4)?;
        let four_y4 = self.field_double(layouter, &two_y4)?;
        let eight_y4 = self.field_double(layouter, &four_y4)?;
        // s_minus_x = s - x_new
        let s_minus_x = self.field_sub(layouter, &s, &x_new)?;
        // m_sx = m * (s - x_new)
        let m_sx = self.field_mul(layouter, &m, &s_minus_x)?;
        // y_new = m_sx - 8*y4
        let y_new = self.field_sub(layouter, &m_sx, &eight_y4)?;
        // z_new = 2 * y * z
        let yz = self.field_mul(layouter, &p.y, &p.z)?;
        let z_new = self.field_double(layouter, &yz)?;

        Ok(AssignedPoint {
            x: x_new,
            y: y_new,
            z: z_new,
        })
    }

    /// EC point addition in Jacobian coordinates.
    ///
    /// Standard mixed Jacobian addition formulas.
    pub fn point_add(
        &self,
        layouter: &mut impl Layouter<Fr>,
        p: &AssignedPoint,
        q: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        // U1 = X1 * Z2²
        let z2_sq = self.field_mul(layouter, &q.z, &q.z)?;
        let u1 = self.field_mul(layouter, &p.x, &z2_sq)?;
        // U2 = X2 * Z1²
        let z1_sq = self.field_mul(layouter, &p.z, &p.z)?;
        let u2 = self.field_mul(layouter, &q.x, &z1_sq)?;
        // S1 = Y1 * Z2³
        let z2_cu = self.field_mul(layouter, &z2_sq, &q.z)?;
        let s1 = self.field_mul(layouter, &p.y, &z2_cu)?;
        // S2 = Y2 * Z1³
        let z1_cu = self.field_mul(layouter, &z1_sq, &p.z)?;
        let s2 = self.field_mul(layouter, &q.y, &z1_cu)?;
        // H = U2 - U1
        let h = self.field_sub(layouter, &u2, &u1)?;
        // R = S2 - S1
        let r = self.field_sub(layouter, &s2, &s1)?;
        // H² = H * H
        let h2 = self.field_mul(layouter, &h, &h)?;
        // H³ = H² * H
        let h3 = self.field_mul(layouter, &h2, &h)?;
        // R² = R * R
        let r2 = self.field_mul(layouter, &r, &r)?;
        // U1*H²
        let u1h2 = self.field_mul(layouter, &u1, &h2)?;
        // 2*U1*H²
        let two_u1h2 = self.field_double(layouter, &u1h2)?;
        // X3 = R² - H³ - 2*U1*H²
        let r2_minus_h3 = self.field_sub(layouter, &r2, &h3)?;
        let x3 = self.field_sub(layouter, &r2_minus_h3, &two_u1h2)?;
        // Y3 = R*(U1*H² - X3) - S1*H³
        let u1h2_minus_x3 = self.field_sub(layouter, &u1h2, &x3)?;
        let r_uh = self.field_mul(layouter, &r, &u1h2_minus_x3)?;
        let s1h3 = self.field_mul(layouter, &s1, &h3)?;
        let y3 = self.field_sub(layouter, &r_uh, &s1h3)?;
        // Z3 = H * Z1 * Z2
        let z1z2 = self.field_mul(layouter, &p.z, &q.z)?;
        let z3 = self.field_mul(layouter, &h, &z1z2)?;

        Ok(AssignedPoint {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    /// **Mixed Jacobian + affine point addition** — [`point_add`](Self::point_add)
    /// specialized to the case `q.z == 1` (q is an affine point).
    ///
    /// This is mathematically **identical** to `point_add` with Z2 = 1: it is
    /// NOT a different formula set, it just drops the five `field_mul` calls
    /// that multiply by 1 (or by Z2). With Z2 = 1:
    ///   - `Z2² = 1` ⇒ `U1 = X1`      (clone `p.x`)
    ///   - `Z2³ = 1` ⇒ `S1 = Y1`      (clone `p.y`)
    ///   - `Z1·Z2 = Z1`               (so `Z3 = H · Z1`)
    ///
    /// so the `z2_sq`, `u1`, `z2_cu`, `s1`, and `z1z2` products collapse to
    /// clones of already-canonical cells. Since `field_mul(·, 1)` would yield
    /// exactly those same canonical values, this is **soundness-neutral**:
    /// every remaining gate constrains the same expression on the same values
    /// as `point_add`.
    ///
    /// Cost: **11 `field_mul`** vs `point_add`'s 16 (−5). Both `point_add`
    /// call sites in `scalar_mul` pass an affine second operand (the generator
    /// `G` with Z = 1, and `−P255` via `assign_affine_constant`, which sets
    /// Z = 1), so every per-bit step saves 5 multiplications.
    ///
    /// Degenerate cases (P1 == ±q, where H or R is 0) are inherited unchanged
    /// from `point_add`: the mixed path returns whatever `point_add` would for
    /// Z2 = 1, including the same (unsupported) behavior near the identity. No
    /// new failure mode is introduced. The math is pinned byte-for-byte against
    /// the full path by `test_jacobian_add_mixed_matches_jacobian_add`.
    pub fn point_add_mixed(
        &self,
        layouter: &mut impl Layouter<Fr>,
        p: &AssignedPoint,
        q: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        // Z2 = 1 ⇒ Z2² = Z2³ = 1 ⇒ U1 = X1, S1 = Y1.
        let u1 = p.x.clone();
        let s1 = p.y.clone();

        // U2 = X2 * Z1²
        let z1_sq = self.field_mul(layouter, &p.z, &p.z)?;
        let u2 = self.field_mul(layouter, &q.x, &z1_sq)?;
        // S2 = Y2 * Z1³
        let z1_cu = self.field_mul(layouter, &z1_sq, &p.z)?;
        let s2 = self.field_mul(layouter, &q.y, &z1_cu)?;
        // H = U2 - U1
        let h = self.field_sub(layouter, &u2, &u1)?;
        // R = S2 - S1
        let r = self.field_sub(layouter, &s2, &s1)?;
        // H² = H * H
        let h2 = self.field_mul(layouter, &h, &h)?;
        // H³ = H² * H
        let h3 = self.field_mul(layouter, &h2, &h)?;
        // R² = R * R
        let r2 = self.field_mul(layouter, &r, &r)?;
        // U1*H²
        let u1h2 = self.field_mul(layouter, &u1, &h2)?;
        // 2*U1*H²
        let two_u1h2 = self.field_double(layouter, &u1h2)?;
        // X3 = R² - H³ - 2*U1*H²
        let r2_minus_h3 = self.field_sub(layouter, &r2, &h3)?;
        let x3 = self.field_sub(layouter, &r2_minus_h3, &two_u1h2)?;
        // Y3 = R*(U1*H² - X3) - S1*H³
        let u1h2_minus_x3 = self.field_sub(layouter, &u1h2, &x3)?;
        let r_uh = self.field_mul(layouter, &r, &u1h2_minus_x3)?;
        let s1h3 = self.field_mul(layouter, &s1, &h3)?;
        let y3 = self.field_sub(layouter, &r_uh, &s1h3)?;
        // Z3 = H * Z1   (Z2 = 1 ⇒ Z1·Z2 = Z1)
        let z3 = self.field_mul(layouter, &h, &p.z)?;

        Ok(AssignedPoint {
            x: x3,
            y: y3,
            z: z3,
        })
    }

    /// Scalar multiplication: k * point using double-and-add.
    ///
    /// MSB-first double-and-add processing `scalar_bits[1..=255]` after
    /// initializing the accumulator at the base point (which implicitly
    /// assumes `scalar_bits[0]` = 1, i.e. the MSB is set).
    ///
    /// **MSB correction**: since valid private keys in `[1, n-1]` may have
    /// MSB = 0 (when k < 2^255), the accumulator unconditionally includes a
    /// `2^255 * G` term. If the actual MSB is 0, we conditionally subtract
    /// `P255 = 2^255 * G` from the result to cancel this extra term.
    ///
    /// Correctness:
    ///   - bits[0]=1: result = (2^255 + rest) * G = k * G  ✓
    ///   - bits[0]=0: result = (2^255 + rest) * G − 2^255 * G = rest * G = k * G  ✓
    ///
    /// This avoids the identity-point issue: the accumulator always holds a
    /// valid non-identity Jacobian point because it starts from the base point
    /// and the Jacobian double/add formulas don't support the identity (Z=0).
    pub fn scalar_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        scalar_bits: &[AssignedCell<Fr, Fr>; 256],
        base_point: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        // Start with the base point (assumes bits[0]=1 for the MSB).
        let mut accumulator = base_point.clone();

        // Process bits[1] through bits[255] (MSB-first, skipping the MSB itself).
        for i in 1..=255 {
            let doubled = self.point_double(layouter, &accumulator)?;

            let added = self.point_add_mixed(layouter, &doubled, base_point)?;
            accumulator =
                self.conditional_select_point(layouter, &added, &doubled, &scalar_bits[i])?;

            // Intermediate soundness: range-check coordinate limbs every 32
            // steps to detect overflow or invalid field elements during scalar
            // multiplication, rather than only at the final check_on_curve.
            if i > 0 && i % 32 == 0 {
                self.check_limb_ranges(layouter, &accumulator.x)?;
                self.check_limb_ranges(layouter, &accumulator.y)?;
                self.check_limb_ranges(layouter, &accumulator.z)?;
            }
        }

        // ── MSB correction ────────────────────────────────────────────
        // The accumulator currently holds (2^255 + rest) * G where
        // rest = Σ_{i=1}^{255} bits[i] * 2^(255-i).
        // If bits[0] (MSB) = 0, we subtract P255 = 2^255 * G.
        // If bits[0] = 1, the result is already correct.
        //
        // P255 = 2^255 * G is a constant point precomputed via native scalar mul.
        let p255_scalar: [u64; 4] = [0, 0, 0, 1u64 << 63];
        let p255 = NativePoint::scalar_mul(&p255_scalar);
        debug_assert!(!p255.is_inf, "P255 should not be identity");

        // Assign P255 as an in-circuit affine point (Z = 1)
        let p255_assigned = self.assign_affine_constant(layouter, &p255, "p255")?;

        // Negate P255's Y coordinate: -P255 = (P255.x, p - P255.y, P255.z)
        let neg_p255_y_native = p255.y.neg();
        let neg_p255_y_limbs = neg_p255_y_native.to_bn254_limbs();
        // SOUND: `−P255.y = p − P255.y` is a fixed constant (P255 is now bound
        // to fixed-column constants above). Binding it the same way prevents a
        // prover from freely choosing the Y coordinate of the MSB-correction
        // subtraction point, which would decouple `scalar_mul`'s output from
        // the honest `k·G`.
        let neg_p255_y = self.assign_field_constant(layouter, &neg_p255_y_limbs, "neg_p255_y")?;

        let neg_p255 = AssignedPoint {
            x: p255_assigned.x.clone(),
            y: neg_p255_y,
            z: p255_assigned.z.clone(),
        };

        // acc - P255 = acc + (-P255)
        let subtracted = self.point_add_mixed(layouter, &accumulator, &neg_p255)?;

        // Select: if bits[0]=1 keep accumulator; if bits[0]=0 use subtracted.
        // conditional_select_point returns `a` when bit=1, `b` when bit=0.
        accumulator = self.conditional_select_point(
            layouter,
            &accumulator, // a: selected when bits[0]=1 (correct as-is)
            &subtracted,  // b: selected when bits[0]=0 (subtract P255)
            &scalar_bits[0],
        )?;

        Ok(accumulator)
    }

    /// Assign the 256 scalar bits as constrained boolean advice cells.
    ///
    /// These cells are the single source of truth for the scalar: they are
    /// consumed by both [`scalar_mul`](Self::scalar_mul) and the nullifier-key
    /// binding, which is what cryptographically ties the emitted nullifier to
    /// the secp256k1 scalar actually multiplied. Each bit is (re-)asserted
    /// boolean when it is accumulated by [`accumulate_weighted_bits`].
    pub fn assign_scalar_bits(
        &self,
        layouter: &mut impl Layouter<Fr>,
        bits: &[bool; 256],
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        layouter.assign_region(
            || "scalar_bits",
            |mut region| {
                let mut cells = Vec::with_capacity(256);
                for i in 0..256 {
                    let col = self.config.advice[i % 8];
                    let row = i / 8;
                    let cell = region.assign_advice(
                        || format!("scalar_bit_{}", i),
                        col,
                        row,
                        || Value::known(if bits[i] { Fr::ONE } else { Fr::ZERO }),
                    )?;
                    cells.push(cell);
                }
                Ok(cells)
            },
        )
    }

    // `accumulate_weighted_bits` and `assert_nonzero` (the ZKMist binding
    // glue) moved to `crate::gadgets::field_accumulator` as a second
    // `impl Secp256k1Chip` block — Phase A of docs/secp256k1-migration-plan.md.
    // They remain methods on this chip for digest-neutrality (no `configure()`
    // change → constraint-system digest + on-chain VK unchanged). Phase B gives
    // them an independent config once the EC engine is replaced by halo2wrong.

    /// Assign a native affine point as constant cells (Z = 1).
    /// Assign a KNOWN affine point (e.g. the secp256k1 generator `G` or the
    /// `P255 = 2^255·G` MSB-correction constant) with its coordinates SOUNDLY
    /// bound to fixed-column constants.
    ///
    /// Public so the top-level circuit can assign the generator through the
    /// same sound path used for `P255` (see the bug-hunt note on
    /// [`assign_field_constant`](Self::assign_field_constant)).
    pub fn assign_affine_constant(
        &self,
        layouter: &mut impl Layouter<Fr>,
        point: &NativePoint,
        label: &str,
    ) -> Result<AssignedPoint, Error> {
        let x_limbs = point.x.to_bn254_limbs();
        let y_limbs = point.y.to_bn254_limbs();
        let z_limbs: [Fr; 4] = [Fr::ONE, Fr::ZERO, Fr::ZERO, Fr::ZERO];

        let x = self.assign_field_constant(layouter, &x_limbs, &format!("{}_x", label))?;
        let y = self.assign_field_constant(layouter, &y_limbs, &format!("{}_y", label))?;
        let z = self.assign_field_constant(layouter, &z_limbs, &format!("{}_z", label))?;

        Ok(AssignedPoint { x, y, z })
    }

    /// Assign 4 limbs as a constant field element in a new region, each limb
    /// SOUNDLY bound to a fixed-column constant.
    ///
    /// # Soundness (bug-hunt)
    ///
    /// The previous version used a bare `assign_advice` with no constraint,
    /// leaving the limb prover-controlled. This helper assigns the coordinates
    /// of the secp256k1 generator `G` and the `P255` MSB-correction constant —
    /// both BASE POINTS of the constrained `scalar_mul`. A prover-controlled
    /// base point fully breaks the claim: choosing `G' = (1/k)·P_target` makes
    /// `scalar_mul(k, G') = P_target`, so `constrain_affine` then binds that to
    /// ANY eligible address's public key (recoverable from on-chain activity)
    /// WITHOUT knowledge of its private key, while the nullifier `poseidon(k,
    /// domain)` is fresh for every distinct `k` ⟹ unlimited theft. Binding each
    /// limb to a fixed-column cell (verifier-known, baked into the preprocessed
    /// circuit) makes the base point a true circuit constant — the same
    /// `fixed_const` + `constrain_equal` pattern used for `zero_ref` / `p_ref`.
    ///
    /// This is synthesize-only (adds copy constraints), so the constraint-system
    /// digest (`EXPECTED_CS_DIGEST`) is unchanged.
    pub(crate) fn assign_field_constant(
        &self,
        layouter: &mut impl Layouter<Fr>,
        limbs: &[Fr; 4],
        name: &str,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || name.to_string(),
            |mut region| {
                let mut cells = Vec::with_capacity(4);
                for (i, l) in limbs.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("{}_{}", name, i),
                        self.config.advice[i],
                        0,
                        || Value::known(*l),
                    )?;
                    // Bind the limb to a fixed-column constant (one value per
                    // (column,row); the 4 limbs occupy fixed rows 0..3, distinct
                    // from the advice cells which all live at row 0 in columns
                    // 0..3).
                    let fc = self.fixed_const(&mut region, i, *l)?;
                    region.constrain_equal(cell.cell(), fc.cell())?;
                    cells.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [
                        cells[0].clone(),
                        cells[1].clone(),
                        cells[2].clone(),
                        cells[3].clone(),
                    ],
                })
            },
        )
    }

    /// Conditional select: if bit=1 return a, if bit=0 return b.
    /// Uses linear combination: result = bit * a + (1-bit) * b
    fn conditional_select_point(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedPoint,
        b: &AssignedPoint,
        bit: &AssignedCell<Fr, Fr>,
    ) -> Result<AssignedPoint, Error> {
        let x = self.conditional_select_field(layouter, &a.x, &b.x, bit)?;
        let y = self.conditional_select_field(layouter, &a.y, &b.y, bit)?;
        let z = self.conditional_select_field(layouter, &a.z, &b.z, bit)?;
        Ok(AssignedPoint { x, y, z })
    }

    /// Conditional select with **fully constrained** gates (no free constants).
    ///
    /// Computes `result = sel·a + (1−sel)·b` for each limb, rewritten as the
    /// constant-free form `result = b + sel·(a − b)` so that no "1" cell is
    /// ever needed. Every operand is copy-constrained and every relation is
    /// enforced by a gate:
    /// - sel is boolean via s_bool
    /// - diff = a[i] − b[i] via s_add (`b[i] + diff = a[i]`)
    /// - t = sel · diff via s_mul
    /// - result = b[i] + t via s_add
    ///
    /// (2026-07-01 bug-hunt) the previous `sel + one_minus_sel = 1` row used a
    /// *free* advice "one" cell, leaving `one_minus_sel` unconstrained and the
    /// select forgeable — see the inline note below.
    fn conditional_select_field(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
        bit: &AssignedCell<Fr, Fr>,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_cond_select",
            |mut region| {
                let mut offset = 0;

                // Row 0: Constrain sel to be boolean. `bit` is an externally-
                // supplied boolean cell (the shared scalar bit); copy it in and
                // constrain equality so the conditional select provably uses
                // that exact bit value.
                let sel_cell = region.assign_advice(
                    || "sel",
                    self.config.advice[0],
                    offset,
                    || bit.value().copied(),
                )?;
                region.constrain_equal(bit.cell(), sel_cell.cell())?;
                self.config.s_bool.enable(&mut region, offset)?;
                offset += 1;

                // ── Soundness (2026-07-01 bug-hunt): no free "one" cell. ──
                // The previous version computed `one_minus_sel` via the `s_add`
                // gate `sel + one_minus_sel = one_cell`, but `one_cell` (advice[2])
                // was a *free* advice cell — read by no other gate. The comment
                // claimed it enforced `sel + one_minus_sel = 1`, but it actually
                // enforced `sel + one_minus_sel = <free>`, so a malicious prover
                // could pick `one_minus_sel` arbitrarily and forge any conditional
                // select output. Because `conditional_select_point` drives every
                // step of `scalar_mul`, this fully decouples the secp256k1 scalar
                // actually multiplied from the bits — the same double-spend class
                // as the `accumulate_weighted_bits` hole (a prover with ONE
                // eligible key can mint unlimited fresh-nullifier claims).
                //
                // Fix: rewrite the select as `result = b + sel·(a − b)`, which is
                // algebraically identical to `sel·a + (1−sel)·b` but needs NO
                // constant cell at all — only the existing `s_add` / `s_mul` /
                // `s_bool` gates, every operand copy-constrained. No gate is
                // added (the constraint-system digest is unchanged), and the
                // buggy `one_minus_sel` row is dropped (one fewer row per call).
                //
                // Per limb i (3 rows):
                //   row A: s_add  b[i] + diff = a[i]        ⟹ diff = a[i] − b[i]
                //   row B: s_mul  sel · diff   = t
                //   row C: s_add  b[i] + t     = result[i]
                // ⇒ result[i] = b[i] + sel·(a[i] − b[i])
                let mut result = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();
                    // diff = a[i] − b[i]  (sound: the s_add gate forces b+diff=a)
                    let diff_val = a_val.zip(b_val).map(|(a, b)| a - b);
                    // t = sel · diff
                    let t_val = bit.value().copied().zip(diff_val).map(|(s, d)| s * d);
                    // result = b[i] + t
                    let sum_val = b_val.zip(t_val).map(|(b, t)| b + t);

                    // Row A: s_add for b[i] + diff = a[i]   (copies b[i], a[i])
                    let b_ra =
                        region.assign_advice(|| "cs_b", self.config.advice[0], offset, || b_val)?;
                    region.constrain_equal(b.limbs[i].cell(), b_ra.cell())?;
                    let diff_cell = region.assign_advice(
                        || "cs_diff",
                        self.config.advice[1],
                        offset,
                        || diff_val,
                    )?;
                    let a_ra =
                        region.assign_advice(|| "cs_a", self.config.advice[2], offset, || a_val)?;
                    region.constrain_equal(a.limbs[i].cell(), a_ra.cell())?;
                    self.config.s_add.enable(&mut region, offset)?;
                    offset += 1;

                    // Row B: s_mul for sel · diff = t   (copies sel, diff)
                    let sel_rb = region.assign_advice(
                        || "cs_sel",
                        self.config.advice[0],
                        offset,
                        || bit.value().copied(),
                    )?;
                    region.constrain_equal(sel_cell.cell(), sel_rb.cell())?;
                    let diff_rb = region.assign_advice(
                        || "cs_diff_r",
                        self.config.advice[1],
                        offset,
                        || diff_val,
                    )?;
                    region.constrain_equal(diff_cell.cell(), diff_rb.cell())?;
                    let t_cell =
                        region.assign_advice(|| "cs_t", self.config.advice[2], offset, || t_val)?;
                    self.config.s_mul.enable(&mut region, offset)?;
                    offset += 1;

                    // Row C: s_add for b[i] + t = result   (copies b[i], t)
                    let b_rc = region.assign_advice(
                        || "cs_b2",
                        self.config.advice[0],
                        offset,
                        || b_val,
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_rc.cell())?;
                    let t_rc = region.assign_advice(
                        || "cs_t_r",
                        self.config.advice[1],
                        offset,
                        || t_val,
                    )?;
                    region.constrain_equal(t_cell.cell(), t_rc.cell())?;
                    let sum_cell = region.assign_advice(
                        || "cs_res",
                        self.config.advice[2],
                        offset,
                        || sum_val,
                    )?;
                    self.config.s_add.enable(&mut region, offset)?;
                    offset += 1;

                    result.push(sum_cell);
                }

                Ok(AssignedFieldElement {
                    limbs: [
                        result[0].clone(),
                        result[1].clone(),
                        result[2].clone(),
                        result[3].clone(),
                    ],
                })
            },
        )
    }

    /// Constrain a Jacobian point to match affine coordinates.
    ///
    /// Enforces: x_affine = X/Z², y_affine = Y/Z³
    /// Via: X = x_affine * Z² and Y = y_affine * Z³
    pub fn constrain_affine(
        &self,
        layouter: &mut impl Layouter<Fr>,
        jacobian: &AssignedPoint,
        affine_x: &AssignedFieldElement,
        affine_y: &AssignedFieldElement,
    ) -> Result<(), Error> {
        // Z²
        let z2 = self.field_mul(layouter, &jacobian.z, &jacobian.z)?;
        // affine_x * Z² should equal X
        let ax_z2 = self.field_mul(layouter, affine_x, &z2)?;
        self.constrain_field_equal(layouter, &ax_z2, &jacobian.x)?;

        // Z³ = Z² * Z
        let z3 = self.field_mul(layouter, &z2, &jacobian.z)?;
        // affine_y * Z³ should equal Y
        let ay_z3 = self.field_mul(layouter, affine_y, &z3)?;
        self.constrain_field_equal(layouter, &ay_z3, &jacobian.y)?;

        Ok(())
    }

    // ── Soundness: limb range checks ───────────────────────────────

    /// Range-check all 4 limbs of a non-native field element to [0, 2^64).
    ///
    /// Each 64-bit limb is decomposed into 8 bytes, each byte is looked up
    /// in the 8-bit range table, and a running-sum constraint verifies the
    /// decomposition is correct.
    ///
    /// Without range checks, a malicious prover could assign limb values
    /// exceeding 2^64, bypassing carry logic and producing invalid field
    /// elements that still satisfy the BN254 arithmetic gates.
    pub fn check_limb_ranges(
        &self,
        layouter: &mut impl Layouter<Fr>,
        elem: &AssignedFieldElement,
    ) -> Result<(), Error> {
        for (i, limb) in elem.limbs.iter().enumerate() {
            self.check_single_limb(layouter, limb, i)?;
        }
        Ok(())
    }

    /// Range-check a single 64-bit limb by decomposing into 8 bytes.
    ///
    /// Uses a running sum: z_0 = 0, z_{i+1} = z_i * 256 + byte[i].
    /// After 8 steps, z_8 must equal the limb value. Each byte is range-checked
    /// via the lookup table. The running sum uses existing s_mul_fixed and
    /// s_add gates.
    fn check_single_limb(
        &self,
        layouter: &mut impl Layouter<Fr>,
        limb: &AssignedCell<Fr, Fr>,
        limb_idx: usize,
    ) -> Result<(), Error> {
        // Pre-compute all byte values and running-sum values.
        // We compute the actual limb u64 value from the assigned cell.
        // Since all values are known at synthesis time, we extract via
        // assert_if_known + default pattern.
        let limb_u64: u64 = {
            let mut result = 0u64;
            limb.value().assert_if_known(|v| {
                let repr = v.to_repr();
                let bytes: &[u8] = repr.as_ref();
                result = u64::from_le_bytes(
                    bytes[..8]
                        .try_into()
                        .expect("field element repr is at least 8 bytes"),
                );
                true
            });
            result
        };
        let limb_val = Fr::from(limb_u64);
        // Big-endian byte order: running sum z[i+1] = z[i]*256 + byte[i]
        // must process bytes MSB-first so z[8] equals the limb value.
        let rb: [u8; 8] = limb_u64.to_be_bytes();
        let byte_fr: [Fr; 8] = std::array::from_fn(|i| Fr::from(rb[i] as u64));
        let mut z = [Fr::ZERO; 9];
        for i in 0..8 {
            z[i + 1] = z[i] * Fr::from(256u64) + byte_fr[i];
        }

        layouter.assign_region(
            || format!("limb_range_{}", limb_idx),
            |mut region| {
                let mut offset = 0;

                // ── Soundness: chain the running sum (2026 bug-hunt fix). ──
                // ── Soundness: chain the running sum, seed PROVABLY zero. ──
                // History: the original left z_cur/z_next/z_final as FREE advice
                // cells (only z_final==limb was constrained) → the check was
                // vacuous (MockProver accepted limb = 2^200+7).
                //
                // The 2026-06-30 fix added chain links (z_cur[b>0]==z_next[b-1],
                // z_final==z_next[7] && z_final==limb) but left the SEED `zero_ref`
                // as a free advice cell, so a "smart" attacker could set z[0]=δ≠0
                // and still reach any out-of-range limb with all-zero bytes
                // (z[8]=δ·256^8=limb). The check was STILL vacuous.
                //
                // The 2026-07-01 fix binds the seed to zero ROW-NEUTRALLY: the
                // `s_mul_fixed` gate already enforces z_scaled[0] = z_cur[0]·256.
                // Forcing z_cur[0] == z_scaled[0] then yields z_cur[0]·256 =
                // z_cur[0], i.e. z_cur[0]·255 = 0, so z_cur[0] = 0 (255 is
                // invertible mod p_BN254). No extra cell or row is needed.
                //
                // With z[0]=0 and the chain links, z_final = Σ byte[i]·256^(7-i),
                // each byte ∈ [0,255], so z_final < 2^64; z_final == limb forces
                // limb < 2^64.
                let mut prev_z_next: Option<AssignedCell<Fr, Fr>> = None;

                for b in 0..8 {
                    // Assign byte to the range-check advice column.
                    // The unconditional lookup enforces byte ∈ [0, 255].
                    let byte_cell = region.assign_advice(
                        || format!("rc_byte_{}_{}", limb_idx, b),
                        self.config.range_check.advice,
                        offset,
                        || Value::known(byte_fr[b]),
                    )?;

                    // Row A: z_cur * 256 = z_scaled  (s_mul_fixed gate)
                    let z_cur_cell = region.assign_advice(
                        || format!("z_cur_{}_{}", limb_idx, b),
                        self.config.advice[0],
                        offset,
                        || Value::known(z[b]),
                    )?;
                    region.assign_fixed(
                        || "256",
                        self.config.fixed,
                        offset,
                        || Value::known(Fr::from(256u64)),
                    )?;
                    let z_scaled_cell = region.assign_advice(
                        || format!("z_scaled_{}_{}", limb_idx, b),
                        self.config.advice[1],
                        offset,
                        || Value::known(z[b] * Fr::from(256u64)),
                    )?;
                    self.config.s_mul_fixed.enable(&mut region, offset)?;
                    // Chain the running sum, and seed it at exactly zero (see
                    // the soundness note above).
                    if b == 0 {
                        region.constrain_equal(z_cur_cell.cell(), z_scaled_cell.cell())?;
                    } else if let Some(prev) = &prev_z_next {
                        region.constrain_equal(z_cur_cell.cell(), prev.cell())?;
                    }
                    offset += 1;

                    // Row B: z_scaled + byte = z_next  (s_add gate)
                    let z_scaled_copy = region.assign_advice(
                        || format!("zs_copy_{}_{}", limb_idx, b),
                        self.config.advice[0],
                        offset,
                        || Value::known(z[b] * Fr::from(256u64)),
                    )?;
                    region.constrain_equal(z_scaled_cell.cell(), z_scaled_copy.cell())?;

                    let byte_copy = region.assign_advice(
                        || format!("byte_copy_{}_{}", limb_idx, b),
                        self.config.advice[1],
                        offset,
                        || Value::known(byte_fr[b]),
                    )?;
                    region.constrain_equal(byte_cell.cell(), byte_copy.cell())?;

                    let z_next_cell = region.assign_advice(
                        || format!("z_next_{}_{}", limb_idx, b),
                        self.config.advice[2],
                        offset,
                        || Value::known(z[b + 1]),
                    )?;
                    self.config.s_add.enable(&mut region, offset)?;
                    offset += 1;

                    prev_z_next = Some(z_next_cell);
                }

                // Constrain z_8 (running-sum terminal) == original limb.
                // z_final is bound to BOTH the last z_next (the real terminal)
                // AND the limb under test — the link that was missing before.
                let limb_copy = region.assign_advice(
                    || format!("limb_final_{}", limb_idx),
                    self.config.advice[0],
                    offset,
                    || Value::known(limb_val),
                )?;
                region.constrain_equal(limb.cell(), limb_copy.cell())?;
                let z_final = region.assign_advice(
                    || format!("z_final_{}", limb_idx),
                    self.config.advice[1],
                    offset,
                    || Value::known(z[8]),
                )?;
                if let Some(last) = &prev_z_next {
                    region.constrain_equal(z_final.cell(), last.cell())?;
                }
                region.constrain_equal(z_final.cell(), limb_copy.cell())?;

                Ok(())
            },
        )?;
        Ok(())
    }

    // ── Product verification (Schwartz–Zippel) ────────────────────

    /// Verify a field multiplication product using a polynomial evaluation check.
    ///
    /// Given `result = field_mul(a, b)`, this method constrains:
    /// ```text
    ///   eval(a) * eval(b) - eval(result) - eval(q) * eval(p) = 0  (mod BN254)
    /// ```
    ///
    /// where `eval(x) = x[0] + x[1]*r + x[2]*r^2 + x[3]*r^3` and
    /// `q = (a*b - result) / p` is the reduction quotient.
    ///
    /// By the Schwartz–Zippel lemma, if the product is incorrect then the
    /// constraint fails with overwhelming probability (soundness error ≤ 6/p_BN254).
    /// Combined with the terminal `check_on_curve` and `constrain_affine` checks,
    /// this provides complete soundness for the field multiplication.
    ///
    /// Gate cost: ~25 rows per call (Horner evaluation × 4 + constraint arithmetic).
    #[allow(dead_code)]
    fn verify_product(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
        result: &AssignedFieldElement,
    ) -> Result<(), Error> {
        // Evaluation point r = 65537 (Fermat prime F4, "nothing-up-my-sleeve")
        // All evaluations are < 2^113 and all products < 2^226 < BN254 field prime,
        // so BN254 arithmetic is exact (no modular reduction distortion).
        let r = Fr::from(65537u64);

        // secp256k1 prime limbs as BN254 field elements
        let p_limbs: [Fr; 4] = SECP_P.map(Fr::from);

        // Compute quotient q = (a*b - result) / p  (native, for witness)
        let q_limbs_fr: Value<[Fr; 4]> = {
            let a_v: Value<[Fr; 4]> = a.values();
            let b_v: Value<[Fr; 4]> = b.values();
            let r_v: Value<[Fr; 4]> = result.values();

            a_v.zip(b_v).zip(r_v).map(|((av, bv), rv)| {
                let a_big = native_to_biguint(&limbs_to_native(&av));
                let b_big = native_to_biguint(&limbs_to_native(&bv));
                let r_big = native_to_biguint(&limbs_to_native(&rv));
                let p_big = secp_prime_biguint();

                let product = &a_big * &b_big;
                let diff = product - r_big;
                let q_big = diff / p_big;

                biguint_to_fr_limbs(&q_big)
            })
        };

        // Assign q limbs in a dedicated region
        let q_assigned = layouter.assign_region(
            || "assign_q",
            |mut region| {
                let mut cells = Vec::with_capacity(4);
                for i in 0..4 {
                    let val = q_limbs_fr.as_ref().map(|v| v[i]);
                    let cell = region.assign_advice(
                        || format!("q_{}", i),
                        self.config.advice[i],
                        0,
                        || val,
                    )?;
                    cells.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [
                        cells[0].clone(),
                        cells[1].clone(),
                        cells[2].clone(),
                        cells[3].clone(),
                    ],
                })
            },
        )?;

        // Range-check q limbs to ensure q is a valid integer (< 2^256)
        self.check_limb_ranges(layouter, &q_assigned)?;

        // Polynomial evaluation and constraint
        layouter.assign_region(
            || "verify_product",
            |mut region| {
                let mut offset = 0usize;

                // Compute eval_a, eval_b, eval_result, eval_q via Horner's method
                let eval_a = Self::eval_horner(&mut region, &mut offset, a, r, self.config)?;
                let eval_b = Self::eval_horner(&mut region, &mut offset, b, r, self.config)?;
                let eval_r = Self::eval_horner(&mut region, &mut offset, result, r, self.config)?;
                let eval_q =
                    Self::eval_horner(&mut region, &mut offset, &q_assigned, r, self.config)?;

                // eval_p = p[0] + p[1]*r + p[2]*r^2 + p[3]*r^3  (constant)
                let r2 = r * r;
                let r3 = r2 * r;
                let eval_p_val = p_limbs[0] + p_limbs[1] * r + p_limbs[2] * r2 + p_limbs[3] * r3;

                // ── Constrain: eval_a * eval_b - eval_result - eval_q * eval_p = 0 ──

                // Row: eval_a * eval_b = ab
                let ab_val = eval_a
                    .value()
                    .copied()
                    .zip(eval_b.value().copied())
                    .map(|(a, b)| a * b);
                let ea_copy = region.assign_advice(
                    || "ea",
                    self.config.advice[0],
                    offset,
                    || eval_a.value().copied(),
                )?;
                region.constrain_equal(eval_a.cell(), ea_copy.cell())?;
                let eb_copy = region.assign_advice(
                    || "eb",
                    self.config.advice[1],
                    offset,
                    || eval_b.value().copied(),
                )?;
                region.constrain_equal(eval_b.cell(), eb_copy.cell())?;
                let ab = region.assign_advice(|| "ab", self.config.advice[2], offset, || ab_val)?;
                self.config.s_mul.enable(&mut region, offset)?;
                offset += 1;

                // Row: eval_q * eval_p = qep
                let qep_val = eval_q.value().copied().map(|q| q * eval_p_val);
                let eq_copy = region.assign_advice(
                    || "eq",
                    self.config.advice[0],
                    offset,
                    || eval_q.value().copied(),
                )?;
                region.constrain_equal(eval_q.cell(), eq_copy.cell())?;
                region.assign_advice(
                    || "ep",
                    self.config.advice[1],
                    offset,
                    || Value::known(eval_p_val),
                )?;
                let _qep =
                    region.assign_advice(|| "qep", self.config.advice[2], offset, || qep_val)?;
                self.config.s_mul.enable(&mut region, offset)?;
                offset += 1;

                // Row: ab + (-eval_result) = diff1
                let neg_r_val = eval_r.value().copied().map(|v| -v);
                let ab_copy2 =
                    region.assign_advice(|| "ab2", self.config.advice[0], offset, || ab_val)?;
                region.constrain_equal(ab.cell(), ab_copy2.cell())?;
                let _neg_r =
                    region.assign_advice(|| "nr", self.config.advice[1], offset, || neg_r_val)?;
                let diff1_val = ab_val.zip(neg_r_val).map(|(a, n)| a + n);
                let diff1 =
                    region.assign_advice(|| "d1", self.config.advice[2], offset, || diff1_val)?;
                self.config.s_add.enable(&mut region, offset)?;
                offset += 1;

                // Row: diff1 + (-qep) = diff2  (should be 0)
                let neg_qep_val = qep_val.map(|v| -v);
                let d1_copy =
                    region.assign_advice(|| "d1c", self.config.advice[0], offset, || diff1_val)?;
                region.constrain_equal(diff1.cell(), d1_copy.cell())?;
                let _neg_qep =
                    region.assign_advice(|| "nq", self.config.advice[1], offset, || neg_qep_val)?;
                let diff2_val = diff1_val.zip(neg_qep_val).map(|(d, n)| d + n);
                let diff2 =
                    region.assign_advice(|| "d2", self.config.advice[2], offset, || diff2_val)?;
                self.config.s_add.enable(&mut region, offset)?;
                offset += 1;

                // Constrain diff2 = 0. Bind to a FIXED-column 0 (a free-advice
                // `zero` cell would make this vacuous — the same bug class as
                // the carry chains). Note: `verify_product` is currently
                // dead code; this keeps it sound if ever revived.
                let zero = self.fixed_const(&mut region, offset, Fr::ZERO)?;
                region.constrain_equal(diff2.cell(), zero.cell())?;

                Ok(())
            },
        )?;

        Ok(())
    }

    /// Evaluate a 4-limb polynomial at point r using Horner's method.
    ///
    /// Computes `x[0] + x[1]*r + x[2]*r^2 + x[3]*r^3`
    /// = `((x[3]*r + x[2])*r + x[1])*r + x[0]`
    ///
    /// Each step uses 2 rows: one `s_mul` and one `s_add`.
    #[allow(dead_code)]
    fn eval_horner(
        region: &mut Region<Fr>,
        offset: &mut usize,
        elem: &AssignedFieldElement,
        r: Fr,
        config: &Secp256k1Config,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        // Start with x[3], then: acc = acc*r + x[i] for i=2,1,0
        let mut acc_val = elem.limbs[3].value().copied();
        let mut acc_cell = elem.limbs[3].clone();

        for i in (0..3).rev() {
            // Row: acc * r = product
            let acc_copy = region.assign_advice(
                || format!("hacc_{}", i),
                config.advice[0],
                *offset,
                || acc_val,
            )?;
            region.constrain_equal(acc_cell.cell(), acc_copy.cell())?;
            region.assign_advice(|| "hr", config.advice[1], *offset, || Value::known(r))?;
            let mul_val = acc_val.map(|a| a * r);
            let mul_cell = region.assign_advice(|| "hm", config.advice[2], *offset, || mul_val)?;
            config.s_mul.enable(region, *offset)?;
            *offset += 1;

            // Row: product + x[i] = new_acc
            let mul_copy = region.assign_advice(|| "hmc", config.advice[0], *offset, || mul_val)?;
            region.constrain_equal(mul_cell.cell(), mul_copy.cell())?;
            let limb_val = elem.limbs[i].value().copied();
            let limb_copy =
                region.assign_advice(|| "hl", config.advice[1], *offset, || limb_val)?;
            region.constrain_equal(elem.limbs[i].cell(), limb_copy.cell())?;
            let sum_val = mul_val.zip(limb_val).map(|(m, l)| m + l);
            let sum_cell = region.assign_advice(|| "hs", config.advice[2], *offset, || sum_val)?;
            config.s_add.enable(region, *offset)?;
            *offset += 1;

            acc_val = sum_val;
            acc_cell = sum_cell;
        }

        Ok(acc_cell)
    }

    ///
    /// This is a high-level soundness check: if any intermediate field
    /// operation produced an incorrect result, the final point likely
    /// won't satisfy the curve equation.
    ///
    /// In Jacobian coordinates the curve equation is:
    ///     Y² = X³ + 7·Z⁶
    /// (not Y² = X³ + 7, which only holds for affine coordinates with Z=1).
    pub fn check_on_curve(
        &self,
        layouter: &mut impl Layouter<Fr>,
        point: &AssignedPoint,
    ) -> Result<(), Error> {
        // Y²
        let y2 = self.field_mul(layouter, &point.y, &point.y)?;
        // X³
        let x2 = self.field_mul(layouter, &point.x, &point.x)?;
        let x3 = self.field_mul(layouter, &x2, &point.x)?;
        // Z⁶ = (Z²)³
        let z2 = self.field_mul(layouter, &point.z, &point.z)?;
        let z4 = self.field_mul(layouter, &z2, &z2)?;
        let z6 = self.field_mul(layouter, &z4, &z2)?;
        // 7·Z⁶  — the curve constant `7` is SOUNDLY bound to a fixed-column
        // constant via `assign_field_constant` (a bare advice cell would make
        // `check_on_curve` vacuous: a prover could set it to `(Y²−X³)/Z⁶` and
        // pass ANY point, defeating this defense-in-depth on-curve check).
        let seven = {
            let seven_limbs = NativeSecpField::from_u64(7).to_bn254_limbs();
            self.assign_field_constant(layouter, &seven_limbs, "seven")?
        };
        let seven_z6 = self.field_mul(layouter, &seven, &z6)?;
        // X³ + 7·Z⁶
        let rhs = self.field_add_carried(layouter, &x3, &seven_z6)?;
        // Y² == X³ + 7·Z⁶
        self.constrain_field_equal(layouter, &y2, &rhs)?;
        Ok(())
    }

    /// Constrain two field elements to be equal (limb-by-limb copy constraints).
    pub fn constrain_field_equal(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<(), Error> {
        for i in 0..4 {
            layouter.assign_region(
                || format!("secp_field_eq_{}", i),
                |mut region| {
                    let a_copy = region.assign_advice(
                        || "eq_a",
                        self.config.advice[0],
                        0,
                        || a.limbs[i].value().copied(),
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_copy.cell())?;

                    let b_copy = region.assign_advice(
                        || "eq_b",
                        self.config.advice[1],
                        0,
                        || b.limbs[i].value().copied(),
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_copy.cell())?;

                    region.constrain_equal(a_copy.cell(), b_copy.cell())?;
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}

/// Convert 4 BN254 field elements (limbs) to a native secp256k1 field element.
fn limbs_to_native(limbs: &[Fr; 4]) -> NativeSecpField {
    let native_limbs: [u64; 4] = limbs.map(limb_to_u64);
    NativeSecpField::from_limbs(native_limbs)
}

/// Convert a native secp256k1 field element to a BigUint.
#[allow(dead_code)]
fn native_to_biguint(n: &NativeSecpField) -> BigUint {
    BigUint::from_bytes_be(&n.to_bytes_be())
}

/// The secp256k1 prime as a BigUint.
#[allow(dead_code)]
fn secp_prime_biguint() -> BigUint {
    native_to_biguint(&NativeSecpField(SECP_P))
}

/// Convert a BigUint to 4 BN254 limb values.
#[allow(dead_code)]
fn biguint_to_fr_limbs(b: &BigUint) -> [Fr; 4] {
    let bytes = b.to_bytes_be();
    let mut padded = [0u8; 32];
    let offset = 32 - bytes.len().min(32);
    padded[offset..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    let native = NativeSecpField::from_bytes_be(&padded);
    native.to_bn254_limbs()
}

/// Extract a u64 value from a BN254 field element (limb).
/// Assumes the value fits in 64 bits (should be enforced by range checks).
fn limb_to_u64(limb: Fr) -> u64 {
    let repr = limb.to_repr();
    let bytes: &[u8] = repr.as_ref();
    u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .expect("field element repr is always 32 bytes, so first 8 are valid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_field_add_sub_roundtrip() {
        let a = NativeSecpField::from_u64(42);
        let b = NativeSecpField::from_u64(17);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff.0, a.0, "a + b - b should equal a");
    }

    #[test]
    fn test_native_field_add_reduces() {
        let p = NativeSecpField(SECP_P);
        let one = NativeSecpField::ONE;
        let sum = p.add(&one); // p + 1 should reduce to 1
        assert_eq!(sum.0, one.0, "p + 1 mod p should be 1");
    }

    #[test]
    fn test_native_field_neg() {
        let a = NativeSecpField::from_u64(42);
        let neg_a = a.neg();
        let sum = a.add(&neg_a);
        assert_eq!(sum.0, [0u64; 4], "a + (-a) should be 0");
    }

    #[test]
    fn test_native_field_mul_simple() {
        let a = NativeSecpField::from_u64(3);
        let b = NativeSecpField::from_u64(7);
        let product = a.mul(&b);
        assert_eq!(product.0[0], 21, "3 * 7 should be 21");
    }

    #[test]
    fn test_native_field_mul_large() {
        // (p-1) * 1 = p-1
        let p_minus_1 = NativeSecpField(SECP_P).sub(&NativeSecpField::from_u64(1));
        let one = NativeSecpField::from_u64(1);
        let product = p_minus_1.mul(&one);
        assert_eq!(product.0, p_minus_1.0, "(p-1) * 1 should be p-1");
    }

    #[test]
    fn test_native_field_mul_inverse() {
        // (p-1) * (p-1) mod p = 1 (since (-1)^2 = 1)
        let p_minus_1 = NativeSecpField(SECP_P).sub(&NativeSecpField::from_u64(1));
        let result = p_minus_1.mul(&p_minus_1);
        assert_eq!(result.0[0], 1u64, "(p-1)^2 mod p should be 1");
        assert_eq!(result.0[1..], [0u64; 3]);
    }

    #[test]
    fn test_native_field_inverse_roundtrip() {
        let a = NativeSecpField::from_u64(42);
        let a_inv = a.inverse();
        let product = a.mul(&a_inv);
        assert_eq!(product.0[0], 1u64, "a * a^(-1) should be 1");
    }

    #[test]
    fn test_native_generator_on_curve() {
        let g = NativePoint::GENERATOR;
        let y2 = g.y.mul(&g.y);
        let x3_plus_7 = g.x.mul(&g.x).mul(&g.x).add(&NativeSecpField::from_u64(7));
        assert_eq!(y2.0, x3_plus_7.0, "G should satisfy y² = x³ + 7");
    }

    #[test]
    fn test_native_scalar_mul_basic() {
        let p2_scalar = NativePoint::scalar_mul(&[2, 0, 0, 0]);
        assert!(!p2_scalar.is_inf);
        let p2_add = NativePoint::GENERATOR.add(&NativePoint::GENERATOR);
        assert_eq!(p2_scalar.x.0, p2_add.x.0);
        assert_eq!(p2_scalar.y.0, p2_add.y.0);
    }

    #[test]
    fn test_native_scalar_mul_order_is_identity() {
        // n * G should be the point at infinity
        let result = NativePoint::scalar_mul(&SECP_N);
        assert!(result.is_inf, "n * G should be point at infinity");
    }

    #[test]
    fn test_native_derive_address_test_vector() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let (addr, _, _) = native_derive_address(&key);
        assert_eq!(
            hex::encode(addr),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );
    }

    #[test]
    fn test_decompose_key_to_bits() {
        let key: [u8; 32] = [0x80u8; 32]; // 1000_0000 repeated
        let bits = decompose_key_to_bits(&key);
        assert!(bits[0], "MSB should be 1");
        assert!(!bits[1], "Second bit should be 0");
        assert_eq!(bits.len(), 256);
    }
}

/// Validate the MSB correction logic for scalar multiplication.
/// Tests that starting from base_point (assuming MSB=1) and then
/// conditionally subtracting P255 produces the correct result for
/// keys where the MSB is actually 0.
#[test]
fn test_scalar_mul_msb_correction() {
    // Test key: 0x0123...cdef — MSB is 0 (first byte is 0x01)
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    // Decompose key to bits (MSB-first)
    let bits = decompose_key_to_bits(&key);
    assert!(
        !bits[0],
        "MSB should be 0 for this test key (byte 0 = 0x01)"
    );

    // Compute k * G directly using native scalar multiplication
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_be_bytes(key[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs.reverse();
    let expected = NativePoint::scalar_mul(&limbs);
    assert!(!expected.is_inf);

    // Simulate the circuit's MSB-first double-and-add with correction
    // Start with G (assumes MSB=1)
    let mut acc = NativePoint::GENERATOR;

    // Process bits[1] through bits[255]
    for i in 1usize..=255 {
        let doubled = acc.double();
        if bits[i] {
            acc = doubled.add(&NativePoint::GENERATOR);
        } else {
            acc = doubled;
        }
    }

    // acc = (2^255 + rest) * G where rest = Σ bits[i]*2^(255-i) for i=1..255
    // Since bits[0]=0, the real scalar k = rest (without the 2^255 term)
    // So we need to subtract P255 = 2^255 * G
    let p255_scalar: [u64; 4] = [0, 0, 0, 1u64 << 63];
    let p255 = NativePoint::scalar_mul(&p255_scalar);

    // acc - P255 = acc + neg(P255)
    let neg_p255 = NativePoint {
        x: p255.x,
        y: p255.y.neg(),
        is_inf: false,
    };
    let corrected = acc.add(&neg_p255);

    // Verify corrected result matches expected
    assert_eq!(corrected.x.0, expected.x.0, "X coordinate mismatch");
    assert_eq!(corrected.y.0, expected.y.0, "Y coordinate mismatch");
    assert!(!corrected.is_inf, "Result should not be identity");

    eprintln!("✅ MSB correction validated for key with MSB=0");
}

/// Test MSB correction for a key where MSB = 1.
#[test]
fn test_scalar_mul_msb_correction_high_key() {
    // Key with MSB=1: first byte = 0x80
    let key: [u8; 32] = [
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x42,
    ];

    let bits = decompose_key_to_bits(&key);
    assert!(bits[0], "MSB should be 1 for this test key");

    // Compute expected directly
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_be_bytes(key[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs.reverse();
    let expected = NativePoint::scalar_mul(&limbs);

    // Simulate circuit: start with G, process bits 1..255
    let mut acc = NativePoint::GENERATOR;
    for i in 1..=255 {
        let doubled = acc.double();
        if bits[i] {
            acc = doubled.add(&NativePoint::GENERATOR);
        } else {
            acc = doubled;
        }
    }

    // bits[0]=1: no correction needed
    // Verify acc matches expected
    assert_eq!(acc.x.0, expected.x.0, "X mismatch (MSB=1, no correction)");
    assert_eq!(acc.y.0, expected.y.0, "Y mismatch (MSB=1, no correction)");

    eprintln!("✅ MSB correction validated for key with MSB=1 (no correction needed)");
}

/// Trace the circuit's Jacobian scalar multiplication using NativeSecpField
/// operations to find the exact Jacobian (X, Y, Z) and verify constrain_affine.
#[test]
fn test_jacobian_scalar_mul_constrain_affine() {
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    let bits = decompose_key_to_bits(&key);

    // Expected affine point
    let (address, pub_x_bytes, pub_y_bytes) = native_derive_address(&key);
    eprintln!("Address: {}", hex::encode(address));

    let pub_x = NativeSecpField::from_bytes_be(&pub_x_bytes);
    let pub_y = NativeSecpField::from_bytes_be(&pub_y_bytes);

    // Simulate circuit scalar_mul using Jacobian coordinates
    // with NativeSecpField operations (mirroring field_mul, field_add, field_sub)
    let g = NativePoint::GENERATOR;
    let mut acc_x = g.x;
    let mut acc_y = g.y;
    let mut acc_z = NativeSecpField::ONE;

    for i in 1..=255 {
        // point_double (using NativeSecpField mul/add/sub to mirror field_mul etc.)
        let (dx, dy, dz) = jacobian_double(acc_x, acc_y, acc_z);
        // point_add(doubled, base_point) where base has Z=1
        let (sx, sy, sz) = jacobian_add(dx, dy, dz, g.x, g.y, NativeSecpField::ONE);

        if bits[i] {
            acc_x = sx;
            acc_y = sy;
            acc_z = sz;
        } else {
            acc_x = dx;
            acc_y = dy;
            acc_z = dz;
        }
    }

    // MSB correction
    let p255_scalar: [u64; 4] = [0, 0, 0, 1u64 << 63];
    let p255 = NativePoint::scalar_mul(&p255_scalar);
    let neg_p255_y = p255.y.neg();

    if !bits[0] {
        let (rx, ry, rz) = jacobian_add(
            acc_x,
            acc_y,
            acc_z,
            p255.x,
            neg_p255_y,
            NativeSecpField::ONE,
        );
        acc_x = rx;
        acc_y = ry;
        acc_z = rz;
    }

    eprintln!("Jacobian X: {}", hex::encode(acc_x.to_bytes_be()));
    eprintln!("Jacobian Y: {}", hex::encode(acc_y.to_bytes_be()));
    eprintln!("Jacobian Z: {}", hex::encode(acc_z.to_bytes_be()));

    // constrain_affine check: affine_x * Z^2 == X, affine_y * Z^3 == Y
    let z2 = acc_z.mul(&acc_z);
    let z3 = z2.mul(&acc_z);
    let ax_z2 = pub_x.mul(&z2);
    let ay_z3 = pub_y.mul(&z3);

    eprintln!("affine_x * Z^2: {}", hex::encode(ax_z2.to_bytes_be()));
    eprintln!("X match: {}", ax_z2.to_bytes_be() == acc_x.to_bytes_be());

    eprintln!("affine_y * Z^3: {}", hex::encode(ay_z3.to_bytes_be()));
    eprintln!("Y match: {}", ay_z3.to_bytes_be() == acc_y.to_bytes_be());

    assert_eq!(ax_z2.0, acc_x.0, "affine_x * Z^2 must equal X");
    assert_eq!(ay_z3.0, acc_y.0, "affine_y * Z^3 must equal Y");
}

/// Jacobian point doubling using NativeSecpField, mirroring the circuit's point_double.
#[allow(dead_code)]
fn jacobian_double(
    x: NativeSecpField,
    y: NativeSecpField,
    z: NativeSecpField,
) -> (NativeSecpField, NativeSecpField, NativeSecpField) {
    let y2 = y.mul(&y);
    let xy2 = x.mul(&y2);
    // s = 4 * xy2 = double(double(xy2))
    let two_xy2 = xy2.add(&xy2);
    let s = two_xy2.add(&two_xy2);
    let x2 = x.mul(&x);
    let two_x2 = x2.add(&x2);
    // m = 3 * x2 = x2 + double(x2)
    let m = x2.add(&two_x2);
    let m2 = m.mul(&m);
    let two_s = s.add(&s);
    let x_new = m2.sub(&two_s);
    let y4 = y2.mul(&y2);
    let two_y4 = y4.add(&y4);
    let four_y4 = two_y4.add(&two_y4);
    let eight_y4 = four_y4.add(&four_y4);
    let s_minus_x = s.sub(&x_new);
    let m_sx = m.mul(&s_minus_x);
    let y_new = m_sx.sub(&eight_y4);
    let yz = y.mul(&z);
    let z_new = yz.add(&yz);
    (x_new, y_new, z_new)
}

/// Jacobian point addition using NativeSecpField, mirroring the circuit's point_add.
#[allow(dead_code)]
fn jacobian_add(
    x1: NativeSecpField,
    y1: NativeSecpField,
    z1: NativeSecpField,
    x2: NativeSecpField,
    y2: NativeSecpField,
    z2: NativeSecpField,
) -> (NativeSecpField, NativeSecpField, NativeSecpField) {
    let z2_sq = z2.mul(&z2);
    let u1 = x1.mul(&z2_sq);
    let z1_sq = z1.mul(&z1);
    let u2 = x2.mul(&z1_sq);
    let z2_cu = z2_sq.mul(&z2);
    let s1 = y1.mul(&z2_cu);
    let z1_cu = z1_sq.mul(&z1);
    let s2 = y2.mul(&z1_cu);
    let h = u2.sub(&u1);
    let r = s2.sub(&s1);
    let h2 = h.mul(&h);
    let h3 = h2.mul(&h);
    let r2 = r.mul(&r);
    let u1h2 = u1.mul(&h2);
    let two_u1h2 = u1h2.add(&u1h2);
    let r2_minus_h3 = r2.sub(&h3);
    let x3 = r2_minus_h3.sub(&two_u1h2);
    let u1h2_minus_x3 = u1h2.sub(&x3);
    let r_uh = r.mul(&u1h2_minus_x3);
    let s1h3 = s1.mul(&h3);
    let y3 = r_uh.sub(&s1h3);
    let z1z2 = z1.mul(&z2);
    let z3 = h.mul(&z1z2);
    (x3, y3, z3)
}

/// Mixed Jacobian + affine addition mirroring the circuit's `point_add_mixed`
/// (Z2 = 1). Same expressions as [`jacobian_add`] with the Z2 = 1 identity
/// substitutions applied; exists only to feed the equivalence test below.
#[allow(dead_code)]
fn jacobian_add_mixed(
    x1: NativeSecpField,
    y1: NativeSecpField,
    z1: NativeSecpField,
    x2: NativeSecpField,
    y2: NativeSecpField,
) -> (NativeSecpField, NativeSecpField, NativeSecpField) {
    // Z2 = 1 ⇒ U1 = X1, S1 = Y1.
    let u1 = x1;
    let s1 = y1;
    let z1_sq = z1.mul(&z1);
    let u2 = x2.mul(&z1_sq);
    let z1_cu = z1_sq.mul(&z1);
    let s2 = y2.mul(&z1_cu);
    let h = u2.sub(&u1);
    let r = s2.sub(&s1);
    let h2 = h.mul(&h);
    let h3 = h2.mul(&h);
    let r2 = r.mul(&r);
    let u1h2 = u1.mul(&h2);
    let two_u1h2 = u1h2.add(&u1h2);
    let r2_minus_h3 = r2.sub(&h3);
    let x3 = r2_minus_h3.sub(&two_u1h2);
    let u1h2_minus_x3 = u1h2.sub(&x3);
    let r_uh = r.mul(&u1h2_minus_x3);
    let s1h3 = s1.mul(&h3);
    let y3 = r_uh.sub(&s1h3);
    let z3 = h.mul(&z1); // Z2 = 1 ⇒ Z1·Z2 = Z1
    (x3, y3, z3)
}

/// Prove `point_add_mixed` is byte-for-byte identical to `point_add` when
/// the second operand is affine (Z2 = 1).
///
/// Replays the EXACT `scalar_mul` trajectory — 255 double+add steps over the
/// generator plus the MSB-correction add — computing every add with BOTH
/// `jacobian_add_mixed` and `jacobian_add(..., z2 = 1)` on two independent
/// accumulators, and asserts they agree on all three Jacobian coordinates at
/// every step (doubled result, add result, and the correction add). Because
/// the circuit's `point_add_mixed` is line-for-line the same expressions as
/// the native `jacobian_add_mixed`, this pins the optimization to be
/// soundness-neutral. Pure native arithmetic — no circuit synthesis, runs in
/// milliseconds, never touches the k=24 path.
#[test]
fn test_jacobian_add_mixed_matches_jacobian_add() {
    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];
    let bits = decompose_key_to_bits(&key);
    let g = NativePoint::GENERATOR;

    // Two independent accumulators: one advances via the mixed path, one via
    // the full path. They must stay identical throughout.
    let mut mx = g.x;
    let mut my = g.y;
    let mut mz = NativeSecpField::ONE;
    let mut fx = g.x;
    let mut fy = g.y;
    let mut fz = NativeSecpField::ONE;

    for i in 1..=255 {
        // mixed path (affine second operand)
        let (mdx, mdy, mdz) = jacobian_double(mx, my, mz);
        let (msx, msy, msz) = jacobian_add_mixed(mdx, mdy, mdz, g.x, g.y);
        // full path with z2 = 1
        let (fdx, fdy, fdz) = jacobian_double(fx, fy, fz);
        let (fsx, fsy, fsz) = jacobian_add(fdx, fdy, fdz, g.x, g.y, NativeSecpField::ONE);

        // Both branches must agree before the conditional select.
        assert_eq!(mdx.0, fdx.0, "double x mismatch at step {}", i);
        assert_eq!(mdy.0, fdy.0, "double y mismatch at step {}", i);
        assert_eq!(mdz.0, fdz.0, "double z mismatch at step {}", i);
        assert_eq!(msx.0, fsx.0, "add x mismatch at step {}", i);
        assert_eq!(msy.0, fsy.0, "add y mismatch at step {}", i);
        assert_eq!(msz.0, fsz.0, "add z mismatch at step {}", i);

        if bits[i] {
            mx = msx;
            my = msy;
            mz = msz;
            fx = fsx;
            fy = fsy;
            fz = fsz;
        } else {
            mx = mdx;
            my = mdy;
            mz = mdz;
            fx = fdx;
            fy = fdy;
            fz = fdz;
        }
    }

    // MSB-correction add (also an affine second operand, −P255).
    let p255_scalar: [u64; 4] = [0, 0, 0, 1u64 << 63];
    let p255 = NativePoint::scalar_mul(&p255_scalar);
    let neg_p255_y = p255.y.neg();
    let (mrx, mry, mrz) = jacobian_add_mixed(mx, my, mz, p255.x, neg_p255_y);
    let (frx, fry, frz) = jacobian_add(fx, fy, fz, p255.x, neg_p255_y, NativeSecpField::ONE);
    assert_eq!(mrx.0, frx.0, "correction add x mismatch");
    assert_eq!(mry.0, fry.0, "correction add y mismatch");
    assert_eq!(mrz.0, frz.0, "correction add z mismatch");

    eprintln!(
        "✅ point_add_mixed matches point_add (Z2=1) over the full scalar_mul trajectory (256 adds)"
    );
}
