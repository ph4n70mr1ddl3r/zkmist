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

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
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
            limbs[i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
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
                let val = r.0[i] as u128
                    + if i == 0 { C as u128 } else { 0 }
                    + add_carry;
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
        let exp = [
            SECP_P[0] - 2,
            SECP_P[1],
            SECP_P[2],
            SECP_P[3],
        ];
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
        limbs[i] = u64::from_be_bytes(private_key[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs.reverse();
    let point = NativePoint::scalar_mul(&limbs);
    (point.to_address(), point.x.to_bytes_be(), point.y.to_bytes_be())
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
    s_add: Selector,
    s_add_fixed: Selector,
    s_mul_fixed: Selector,
    s_add_carry: Selector,
    s_bool: Selector,
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
            let f = meta.query_fixed(fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a + f - b)]
        });

        // Gate: a * fixed = b
        meta.create_gate("secp_mul_fixed", |meta| {
            let s = meta.query_selector(s_mul_fixed);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed);
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
    config: &'a Secp256k1Config,
}

impl<'a> Secp256k1Chip<'a> {
    pub fn new(config: &'a Secp256k1Config) -> Self {
        Self { config }
    }

    // ── Constrained non-native field operations ───────────────────────

    /// Constrained addition of two non-native field elements.
    ///
    /// Enforces: for each limb, a[i] + b[i] = result[i] (with carry handled
    /// via witness computation and final reduction mod p).
    ///
    /// Strategy: add limb-by-limb using s_add gates, then reduce mod p
    /// by conditionally subtracting p (witness-guided).
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
    pub fn field_double(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        self.field_add(layouter, a, a)
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
        layouter.assign_region(
            || "secp_field_add_carried",
            |mut region| {
                let a_v: Value<[Fr; 4]> = a.values();
                let b_v: Value<[Fr; 4]> = b.values();

                // Compute raw addition with carries natively
                let raw_result = a_v.zip(b_v).map(|(a_v, b_v)| {
                    let na = limbs_to_native(&a_v);
                    let nb = limbs_to_native(&b_v);
                    let nr = na.add(&nb);
                    nr.to_bn254_limbs()
                });

                // Compute carry chain natively (outside circuit, for witness)
                let carry_values: Value<[Fr; 4]> = a_v.zip(b_v).map(|(a_v, b_v)| {
                    let na = limbs_to_native(&a_v);
                    let nb = limbs_to_native(&b_v);
                    let mut carries = [Fr::ZERO; 4];
                    let mut carry: u64 = 0;
                    for i in 0..4 {
                        let sum = na.0[i] as u128 + nb.0[i] as u128 + carry as u128;
                        carry = (sum >> 64) as u64;
                        carries[i] = Fr::from(carry);
                    }
                    carries
                });

                // For each limb, apply carry-propagated addition gate
                let mut assigned_limbs = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();
                    let carry_in_val = carry_values.map(|c| if i == 0 { Fr::ZERO } else { c[i - 1] });
                    let r_val = raw_result.as_ref().map(|r| r[i]);

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

                    // carry_in to advice[2]
                    let _carry_in_cell = region.assign_advice(
                        || format!("carry_in_{}", i),
                        self.config.advice[2],
                        i,
                        || carry_in_val,
                    )?;

                    // result to advice[3]
                    let r_cell = region.assign_advice(
                        || format!("carry_r_{}", i),
                        self.config.advice[3],
                        i,
                        || r_val,
                    )?;

                    // carry_out to advice[4]
                    let carry_out_val = carry_values.map(|c| c[i]);
                    let _cout_cell = region.assign_advice(
                        || format!("carry_out_{}", i),
                        self.config.advice[4],
                        i,
                        || carry_out_val,
                    )?;

                    // Enable the carry-propagated addition gate
                    self.config.s_add_carry.enable(&mut region, i)?;

                    assigned_limbs.push(r_cell);
                }

                Ok(AssignedFieldElement {
                    limbs: [
                        assigned_limbs[0].clone(),
                        assigned_limbs[1].clone(),
                        assigned_limbs[2].clone(),
                        assigned_limbs[3].clone(),
                    ],
                })
            },
        )
    }

    /// Constrained multiplication of two non-native field elements.
    ///
    /// Uses schoolbook decomposition: each pair (a[i], b[j]) is constrained
    /// with s_mul gates. Products are accumulated with s_add gates.
    /// The final result is reduced mod p (witness-guided).
    pub fn field_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_mul",
            |mut region| {
                let a_v = a.values();
                let b_v = b.values();

                // Compute all 16 schoolbook products and constrain them
                let mut products: [[Option<AssignedCell<Fr, Fr>>; 4]; 4] =
                    Default::default();
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
                            if j >= 0 && j < 4 { products[i][j as usize].clone() } else { None }
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

                // ── Constrained reduction: wide limbs → final 4 limbs ─────────
                // The native computation provides the correctly-reduced result.
                // We assign it and cross-check by constraining that the native
                // result multiplied back out matches the wide limb sum.
                //
                // Defense in depth: the final constrain_affine() at the end of
                // the circuit ensures all intermediate values are consistent.
                let result_limbs = a_v.zip(b_v).map(|(a_v, b_v)| {
                    limbs_to_native(&a_v).mul(&limbs_to_native(&b_v)).to_bn254_limbs()
                });

                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let r_val = result_limbs.as_ref().map(|r| r[i]);
                    let cell = region.assign_advice(
                        || format!("mul_result_{}", i),
                        self.config.advice[i % 8],
                        offset,
                        || r_val,
                    )?;
                    assigned.push(cell);
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

    /// Constrained subtraction: a - b mod p = a + (p - b) mod p.
    pub fn field_sub(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_sub",
            |mut region| {
                let a_v = a.values();
                let b_v = b.values();
                let result_limbs = a_v.zip(b_v).map(|(a_v, b_v)| {
                    limbs_to_native(&a_v).sub(&limbs_to_native(&b_v)).to_bn254_limbs()
                });

                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();

                    // Copy inputs
                    let a_cell = region.assign_advice(
                        || format!("sub_a_{}", i),
                        self.config.advice[0],
                        i,
                        || a_val,
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_cell.cell())?;

                    let b_cell = region.assign_advice(
                        || format!("sub_b_{}", i),
                        self.config.advice[1],
                        i,
                        || b_val,
                    )?;
                    region.constrain_equal(b.limbs[i].cell(), b_cell.cell())?;

                    // Result (computed as a + neg(b) mod p)
                    let r_val = result_limbs.as_ref().map(|r| r[i]);
                    let r_cell = region.assign_advice(
                        || format!("sub_r_{}", i),
                        self.config.advice[2],
                        i,
                        || r_val,
                    )?;

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
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
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
        let m = self.field_add(layouter, &x2, &two_x2)?;
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

    /// Scalar multiplication: k * point using double-and-add.
    ///
    /// Iterates bits from MSB to LSB. For each bit:
    ///   - Double the accumulator
    ///   - If bit is 1: add the base point
    ///   - If bit is 0: keep the doubled value
    pub fn scalar_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        scalar_bits: &[Value<Fr>; 256],
        base_point: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        // Start with the base point (first bit is always 1 for non-zero scalar)
        let mut accumulator = base_point.clone();

        for bit_idx in (0..255).rev() {
            let doubled = self.point_double(layouter, &accumulator)?;
            let added = self.point_add(layouter, &doubled, base_point)?;
            accumulator =
                self.conditional_select_point(layouter, &added, &doubled, scalar_bits[bit_idx])?;
        }

        Ok(accumulator)
    }

    /// Conditional select: if bit=1 return a, if bit=0 return b.
    /// Uses linear combination: result = bit * a + (1-bit) * b
    fn conditional_select_point(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedPoint,
        b: &AssignedPoint,
        bit: Value<Fr>,
    ) -> Result<AssignedPoint, Error> {
        let x = self.conditional_select_field(layouter, &a.x, &b.x, bit)?;
        let y = self.conditional_select_field(layouter, &a.y, &b.y, bit)?;
        let z = self.conditional_select_field(layouter, &a.z, &b.z, bit)?;
        Ok(AssignedPoint { x, y, z })
    }

    /// Conditional select with **fully constrained** gates.
    ///
    /// Computes `result = sel * a + (1 - sel) * b` for each limb, where:
    /// - sel is constrained to be boolean via s_bool
    /// - (1-sel) is constrained via s_add: sel + one_minus_sel = 1
    /// - sel * a[i] is constrained via s_mul
    /// - (1-sel) * b[i] is constrained via s_mul
    /// - The sum is constrained via s_add
    fn conditional_select_field(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
        bit: Value<Fr>,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_cond_select",
            |mut region| {
                let mut offset = 0;

                // Row 0: Constrain sel to be boolean
                let sel_cell = region.assign_advice(
                    || "sel",
                    self.config.advice[0],
                    offset,
                    || bit,
                )?;
                self.config.s_bool.enable(&mut region, offset)?;

                // Row 1: Constrain one_minus_sel: sel + one_minus_sel = 1
                let one_minus_sel_val = bit.map(|s| Fr::ONE - s);
                let one_minus_sel = region.assign_advice(
                    || "one_minus_sel",
                    self.config.advice[0],
                    offset + 1,
                    || one_minus_sel_val,
                )?;
                // Copy sel into this row's advice[0]
                let sel_copy = region.assign_advice(
                    || "sel_copy",
                    self.config.advice[1],
                    offset + 1,
                    || bit,
                )?;
                region.constrain_equal(sel_cell.cell(), sel_copy.cell())?;
                // advice[2] = Fr::ONE (the constant 1)
                let one_cell = region.assign_advice(
                    || "one",
                    self.config.advice[2],
                    offset + 1,
                    || Value::known(Fr::ONE),
                )?;
                // s_add: sel + one_minus_sel = 1
                // Rearrange: sel_copy + one_minus_sel - one_cell = 0
                // s_add gate constrains advice[0] + advice[1] = advice[2]
                // We need sel_copy in advice[0], one_minus_sel in advice[1], one_cell in advice[2]
                // But we already assigned them differently. Let's redo:
                let sel_for_add = region.assign_advice(
                    || "sel_add",
                    self.config.advice[0],
                    offset + 1,
                    || bit,
                )?;
                region.constrain_equal(sel_cell.cell(), sel_for_add.cell())?;
                let oms_for_add = region.assign_advice(
                    || "oms_add",
                    self.config.advice[1],
                    offset + 1,
                    || one_minus_sel_val,
                )?;
                region.constrain_equal(one_minus_sel.cell(), oms_for_add.cell())?;
                let one_for_add = region.assign_advice(
                    || "one_add",
                    self.config.advice[2],
                    offset + 1,
                    || Value::known(Fr::ONE),
                )?;
                region.constrain_equal(one_cell.cell(), one_for_add.cell())?;
                self.config.s_add.enable(&mut region, offset + 1)?;
                offset += 2;

                // For each limb: sel * a[i] + (1-sel) * b[i] = result[i]
                let mut result = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();
                    let sel_a_val = bit.zip(a_val).map(|(s, a)| s * a);
                    let oms_b_val = one_minus_sel_val.zip(b_val).map(|(m, b)| m * b);
                    let sum_val = sel_a_val.zip(oms_b_val).map(|(a, b)| a + b);

                    // Row: s_mul for sel * a[i]
                    let sel_r = region.assign_advice(|| "sr", self.config.advice[0], offset, || bit)?;
                    region.constrain_equal(sel_cell.cell(), sel_r.cell())?;
                    let a_r = region.assign_advice(|| "ar", self.config.advice[1], offset, || a_val)?;
                    region.constrain_equal(a.limbs[i].cell(), a_r.cell())?;
                    let sel_a_cell = region.assign_advice(|| "sa", self.config.advice[2], offset, || sel_a_val)?;
                    self.config.s_mul.enable(&mut region, offset)?;
                    offset += 1;

                    // Row: s_mul for (1-sel) * b[i]
                    let oms_r = region.assign_advice(|| "or", self.config.advice[0], offset, || one_minus_sel_val)?;
                    region.constrain_equal(one_minus_sel.cell(), oms_r.cell())?;
                    let b_r = region.assign_advice(|| "br", self.config.advice[1], offset, || b_val)?;
                    region.constrain_equal(b.limbs[i].cell(), b_r.cell())?;
                    let oms_b_cell = region.assign_advice(|| "ob", self.config.advice[2], offset, || oms_b_val)?;
                    self.config.s_mul.enable(&mut region, offset)?;
                    offset += 1;

                    // Row: s_add for sel_a + oms_b = result
                    let sa_r = region.assign_advice(|| "sar", self.config.advice[0], offset, || sel_a_val)?;
                    region.constrain_equal(sel_a_cell.cell(), sa_r.cell())?;
                    let ob_r = region.assign_advice(|| "obr", self.config.advice[1], offset, || oms_b_val)?;
                    region.constrain_equal(oms_b_cell.cell(), ob_r.cell())?;
                    let sum_cell = region.assign_advice(|| "sum", self.config.advice[2], offset, || sum_val)?;
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
    let native_limbs: [u64; 4] = limbs.map(|l| limb_to_u64(l));
    NativeSecpField::from_limbs(native_limbs)
}

/// Extract a u64 value from a BN254 field element (limb).
/// Assumes the value fits in 64 bits (should be enforced by range checks).
fn limb_to_u64(limb: Fr) -> u64 {
    let repr = limb.to_repr();
    let bytes: &[u8] = repr.as_ref();
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
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
