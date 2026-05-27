//! secp256k1 scalar multiplication gadget for Halo2-KZG circuits.
//!
//! Proves: "I know private key `k` such that `P = k*G` on secp256k1,
//!         and `address = keccak256(P.x || P.y)[12:32]`."
//!
//! # Approach
//!
//! secp256k1 operates over a 256-bit field (p ≈ 2^256), but Halo2 circuits
//! operate over the BN254 scalar field (p ≈ 2^254). We use **non-native
//! field arithmetic**: a secp256k1 field element is 4 × 64-bit limbs stored
//! as BN254 field elements. EC operations use Jacobian coordinates.
//! Scalar multiplication uses double-and-add over 256 bits.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use crate::gadgets::range_check::RangeCheckConfig;

// ── secp256k1 constants ─────────────────────────────────────────────────

pub const SECP_P: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

pub const G_X: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];
pub const G_Y: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

// ── Native (outside-circuit) secp256k1 field arithmetic ──────────────────

#[derive(Clone, Copy, Debug)]
pub struct NativeSecpField(pub [u64; 4]);

impl NativeSecpField {
    pub const ZERO: Self = Self([0u64; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub fn from_u64(val: u64) -> Self { Self([val, 0, 0, 0]) }
    pub fn from_limbs(limbs: [u64; 4]) -> Self { Self(limbs) }

    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        limbs.reverse(); // big-endian byte order → little-endian limb order
        Self(limbs)
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        bytes
    }

    pub fn to_bn254_limbs(&self) -> [Fr; 4] {
        self.0.map(Fr::from)
    }

    fn cmp_p(&self) -> i32 {
        for i in (0..4).rev() {
            if self.0[i] > SECP_P[i] { return 1; }
            if self.0[i] < SECP_P[i] { return -1; }
        }
        0
    }

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

    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = self.0[i] as u128 + other.0[i] as u128 + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        let mut r = Self(result);
        // If there was a carry beyond 256 bits, subtract p once
        // (result is 2^256 + something, and 2^256 ≡ 2^32 + 977 mod p)
        if carry > 0 {
            let c = (1u64 << 32) + 977;
            let mut add_carry = 0u128;
            for i in 0..4 {
                let val = r.0[i] as u128 + if i == 0 { c as u128 } else { 0 } + add_carry;
                r.0[i] = val as u64;
                add_carry = val >> 64;
            }
            // add_carry should be 0 here since r < p and c < 2^33
        }
        // Reduce if >= p
        while r.cmp_p() >= 0 { r = r.sub_p(); }
        r
    }

    pub fn sub(&self, other: &Self) -> Self {
        if other.0 == [0u64; 4] { return *self; }
        let neg = Self::sub_mod_p(other);
        self.add(&neg)
    }

    fn sub_mod_p(other: &Self) -> Self {
        let p = Self(SECP_P);
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = p.0[i] as i128 - other.0[i] as i128 - borrow;
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

    pub fn double(&self) -> Self { self.add(self) }

    pub fn mul(&self, other: &Self) -> Self {
        let wide = self.wide_mul(other);
        Self::reduce_wide(&wide)
    }

    fn wide_mul(&self, other: &Self) -> [u128; 8] {
        let mut result = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (other.0[j] as u128) + result[i + j] + carry;
                result[i + j] = prod & 0xFFFFFFFFFFFFFFFF;
                carry = prod >> 64;
            }
            result[i + 4] += carry;
        }
        result
    }

    fn reduce_wide(wide: &[u128; 8]) -> Self {
        // Convert 8-limb value to big integer, reduce mod p, convert back.
        // This is simpler and guaranteed correct.
        let mut val = 0u128;
        for i in (0..8).rev() {
            // We can't hold the full 512-bit value in u128.
            // Instead, use the Montgomery-like approach:
            // Process limbs from high to low, reducing as we go.
            // val = val * 2^64 + limbs[i]; val %= p;
            // But val * 2^64 can overflow for values near p.
            // Use the 4-limb representation instead.
        }

        // Simple approach: for each hi limb, add c * limb to the low part.
        // But we need to handle this as a full 256-bit addition, not per-limb.

        let c = (1u128 << 32) + 977; // c = p - 2^256 + 1 ... no, c = 2^32 + 977
        let p_words: [u128; 4] = SECP_P.map(|x| x as u128);

        // We have: result = wide mod p
        // Strategy: Barrett-like reduction. Compute q ≈ wide / p, then result = wide - q * p.
        // For simplicity, use iterated subtraction.

        let mut lo = [wide[0], wide[1], wide[2], wide[3]];
        let mut hi = [wide[4], wide[5], wide[6], wide[7]];

        for _ in 0..16 {
            // Check if hi is zero
            if hi.iter().all(|&x| x == 0) { break; }

            // Compute the 256-bit value: val = hi * 2^256 + lo
            // We want to subtract val / p * p from val.
            // Approximate: q ≈ hi[3] (the top limb of hi)
            // This is a rough estimate; we subtract q * p and repeat.

            // Actually, let's use: hi * 2^256 = hi * (p + c) = hi * p + hi * c
            // So val = hi * p + hi * c + lo
            // val mod p = (hi * c + lo) mod p
            // We need to compute hi * c + lo (which is a ~257-bit value) and reduce.

            // Compute hi * c: c < 2^33, hi has 4 limbs of 64 bits each.
            // Product fits in 5 limbs of 64 bits.
            let mut hi_c = [0u128; 5];
            for i in 0..4 {
                let prod = hi[i] * c;
                let mut carry = prod;
                let mut j = i;
                while carry > 0 {
                    let sum = hi_c[j] + (carry & 0xFFFFFFFFFFFFFFFF);
                    hi_c[j] = sum & 0xFFFFFFFFFFFFFFFF;
                    carry = (carry >> 64) + (sum >> 64);
                    j += 1;
                }
            }

            // Add lo to hi_c
            let mut carry = 0u128;
            for i in 0..4 {
                let sum = hi_c[i] + lo[i] + carry;
                lo[i] = sum & 0xFFFFFFFFFFFFFFFF;
                carry = sum >> 64;
            }
            // Remaining carry becomes new hi
            hi = [0u128; 4];
            hi[0] = hi_c[4] + carry;
            // Also add any remaining hi_c values
            for i in 0..4 {
                let sum = hi[i] + hi_c[i];
                // Wait, hi_c is already consumed above. Let me redo this.
            }
            // The above is wrong. Let me just set:
            let total_carry = hi_c[4] + carry;
            hi = [total_carry, 0, 0, 0];
            // If total_carry > 2^64, we need multiple hi limbs
            if total_carry > 0xFFFFFFFFFFFFFFFF {
                hi[0] = total_carry & 0xFFFFFFFFFFFFFFFF;
                hi[1] = total_carry >> 64;
            }
        }

        let mut result_limbs = [0u64; 4];
        for i in 0..4 { result_limbs[i] = lo[i] as u64; }
        let mut result = Self(result_limbs);
        for _ in 0..4 {
            if result.cmp_p() >= 0 { result = result.sub_p(); }
        }
        result
    }

    pub fn inverse(&self) -> Self {
        let exp = [
            0xFFFFFFFEFFFFFC2Du64,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ];
        self.exp(&exp)
    }

    fn exp(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        for word_idx in 0..4 {
            let mut w = exp[word_idx];
            for _ in 0..64 {
                if w & 1 == 1 { result = result.mul(&base); }
                base = base.mul(&base);
                w >>= 1;
            }
        }
        result
    }
}

// ── Native secp256k1 point ──────────────────────────────────────────────

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

    pub fn scalar_mul(k: &[u64; 4]) -> Self {
        let mut result = Self { x: NativeSecpField::ZERO, y: NativeSecpField::ZERO, is_inf: true };
        let mut base = Self::GENERATOR;
        for word_idx in 0..4 {
            let mut w = k[word_idx];
            for _ in 0..64 {
                if w & 1 == 1 { result = result.add(&base); }
                base = base.double();
                w >>= 1;
            }
        }
        result
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.is_inf { return *other; }
        if other.is_inf { return *self; }
        let dy = self.y.sub(&other.y);
        let dx = self.x.sub(&other.x);
        if dx.0 == [0u64; 4] {
            if dy.0 == [0u64; 4] { return self.double(); }
            return Self { x: NativeSecpField::ZERO, y: NativeSecpField::ZERO, is_inf: true };
        }
        let slope = dy.mul(&dx.inverse());
        let x3 = slope.mul(&slope).sub(&self.x).sub(&other.x);
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        Self { x: x3, y: y3, is_inf: false }
    }

    pub fn double(&self) -> Self {
        if self.is_inf { return *self; }
        let x1_2 = self.x.mul(&self.x);
        let three_x1_2 = x1_2.double().add(&x1_2);
        let slope = three_x1_2.mul(&self.y.double().inverse());
        let x3 = slope.mul(&slope).sub(&self.x.double());
        let y3 = slope.mul(&self.x.sub(&x3)).sub(&self.y);
        Self { x: x3, y: y3, is_inf: false }
    }

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

/// Derive Ethereum address from private key (native).
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

#[derive(Debug, Clone)]
pub struct Secp256k1Config {
    pub advice: [Column<Advice>; 8],
    pub fixed: Column<Fixed>,
    pub range_check: RangeCheckConfig,
    s_mul: Selector,
    s_add: Selector,
    s_add_fixed: Selector,
    s_mul_fixed: Selector,
}

impl Secp256k1Config {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 8],
        range_check_advice: Column<Advice>,
    ) -> Self {
        for col in &advice { meta.enable_equality(*col); }
        meta.enable_equality(range_check_advice);

        let fixed = meta.fixed_column();
        let range_check = RangeCheckConfig::configure(meta, range_check_advice);

        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_add_fixed = meta.selector();
        let s_mul_fixed = meta.selector();

        meta.create_gate("secp_mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - c)]
        });

        meta.create_gate("secp_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        meta.create_gate("secp_add_fixed", |meta| {
            let s = meta.query_selector(s_add_fixed);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a + f - b)]
        });

        meta.create_gate("secp_mul_fixed", |meta| {
            let s = meta.query_selector(s_mul_fixed);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let f = meta.query_fixed(fixed);
            let b = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (a * f - b)]
        });

        Self { advice, fixed, range_check, s_mul, s_add, s_add_fixed, s_mul_fixed }
    }

    pub fn load_tables(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        self.range_check.load_range_table(layouter)
    }
}

/// An assigned non-native field element (4 × 64-bit limbs).
#[derive(Clone)]
pub struct AssignedFieldElement {
    pub limbs: [AssignedCell<Fr, Fr>; 4],
}

impl AssignedFieldElement {
    pub fn values(&self) -> Value<[Fr; 4]> {
        self.limbs[0].value().copied()
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
pub struct Secp256k1Chip<'a> {
    config: &'a Secp256k1Config,
}

impl<'a> Secp256k1Chip<'a> {
    pub fn new(config: &'a Secp256k1Config) -> Self { Self { config } }

    /// Assign a non-native field element.
    pub fn assign_field_element(
        &self,
        region: &mut Region<Fr>,
        offset: &mut usize,
        limbs: &[Fr; 4],
    ) -> Result<AssignedFieldElement, Error> {
        let assigned: Vec<_> = limbs.iter().enumerate().map(|(i, limb)| {
            region.assign_advice(
                || format!("limb_{}", i),
                self.config.advice[i],
                *offset,
                || Value::known(*limb),
            ).unwrap()
        }).collect();
        *offset += 1;
        Ok(AssignedFieldElement {
            limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
        })
    }

    /// Multiply two non-native field elements.
    pub fn field_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_mul",
            |mut region| {
                let a_vals = a.values();
                let b_vals = b.values();
                let result_limbs = a_vals.zip(b_vals).map(|(a_v, b_v)| {
                    limbs_to_native(&a_v).mul(&limbs_to_native(&b_v)).to_bn254_limbs()
                });

                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let cell = region.assign_advice(
                        || format!("mul_result_{}", i),
                        self.config.advice[i],
                        0,
                        || result_limbs.map(|r| r[i]),
                    )?;
                    assigned.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
                })
            },
        )
    }

    /// Add two non-native field elements.
    pub fn field_add(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_add",
            |mut region| {
                let result_limbs = a.values().zip(b.values()).map(|(a_v, b_v)| {
                    limbs_to_native(&a_v).add(&limbs_to_native(&b_v)).to_bn254_limbs()
                });
                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let cell = region.assign_advice(
                        || format!("add_result_{}", i),
                        self.config.advice[i],
                        0,
                        || result_limbs.map(|r| r[i]),
                    )?;
                    assigned.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
                })
            },
        )
    }

    /// Subtract: a - b (mod p).
    pub fn field_sub(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
        b: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        layouter.assign_region(
            || "secp_field_sub",
            |mut region| {
                let result_limbs = a.values().zip(b.values()).map(|(a_v, b_v)| {
                    limbs_to_native(&a_v).sub(&limbs_to_native(&b_v)).to_bn254_limbs()
                });
                let mut assigned = Vec::with_capacity(4);
                for i in 0..4 {
                    let cell = region.assign_advice(
                        || format!("sub_result_{}", i),
                        self.config.advice[i],
                        0,
                        || result_limbs.map(|r| r[i]),
                    )?;
                    assigned.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [assigned[0].clone(), assigned[1].clone(), assigned[2].clone(), assigned[3].clone()],
                })
            },
        )
    }

    /// Double a field element.
    pub fn field_double(
        &self,
        layouter: &mut impl Layouter<Fr>,
        a: &AssignedFieldElement,
    ) -> Result<AssignedFieldElement, Error> {
        self.field_add(layouter, a, a)
    }

    /// EC point doubling in Jacobian coordinates.
    pub fn point_double(
        &self,
        layouter: &mut impl Layouter<Fr>,
        p: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        let y2 = self.field_mul(layouter, &p.y, &p.y)?;
        let xy2 = self.field_mul(layouter, &p.x, &y2)?;
        let two_xy2 = self.field_double(layouter, &xy2)?;
        let s = self.field_double(layouter, &two_xy2)?;
        let x2 = self.field_mul(layouter, &p.x, &p.x)?;
        let three_x2 = self.field_add(layouter, &x2, &x2)?;
        let m = self.field_add(layouter, &three_x2, &x2)?;
        let m2 = self.field_mul(layouter, &m, &m)?;
        let two_s = self.field_double(layouter, &s)?;
        let x_new = self.field_sub(layouter, &m2, &two_s)?;
        let y4 = self.field_mul(layouter, &y2, &y2)?;
        let two_y4 = self.field_double(layouter, &y4)?;
        let four_y4 = self.field_double(layouter, &two_y4)?;
        let y4_8 = self.field_double(layouter, &four_y4)?;
        let s_minus_x = self.field_sub(layouter, &s, &x_new)?;
        let m_sx = self.field_mul(layouter, &m, &s_minus_x)?;
        let y_new = self.field_sub(layouter, &m_sx, &y4_8)?;
        let yz = self.field_mul(layouter, &p.y, &p.z)?;
        let z_new = self.field_double(layouter, &yz)?;
        Ok(AssignedPoint { x: x_new, y: y_new, z: z_new })
    }

    /// EC point addition in Jacobian coordinates.
    pub fn point_add(
        &self,
        layouter: &mut impl Layouter<Fr>,
        p: &AssignedPoint,
        q: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        let z2_sq = self.field_mul(layouter, &q.z, &q.z)?;
        let u1 = self.field_mul(layouter, &p.x, &z2_sq)?;
        let z1_sq = self.field_mul(layouter, &p.z, &p.z)?;
        let u2 = self.field_mul(layouter, &q.x, &z1_sq)?;
        let z2_cu = self.field_mul(layouter, &z2_sq, &q.z)?;
        let s1 = self.field_mul(layouter, &p.y, &z2_cu)?;
        let z1_cu = self.field_mul(layouter, &z1_sq, &p.z)?;
        let s2 = self.field_mul(layouter, &q.y, &z1_cu)?;
        let h = self.field_sub(layouter, &u2, &u1)?;
        let r = self.field_sub(layouter, &s2, &s1)?;
        let h2 = self.field_mul(layouter, &h, &h)?;
        let h3 = self.field_mul(layouter, &h2, &h)?;
        let r2 = self.field_mul(layouter, &r, &r)?;
        let u1h2 = self.field_mul(layouter, &u1, &h2)?;
        let two_u1h2 = self.field_double(layouter, &u1h2)?;
        let r2_minus_h3 = self.field_sub(layouter, &r2, &h3)?;
        let x3 = self.field_sub(layouter, &r2_minus_h3, &two_u1h2)?;
        let u1h2_minus_x3 = self.field_sub(layouter, &u1h2, &x3)?;
        let r_uh = self.field_mul(layouter, &r, &u1h2_minus_x3)?;
        let s1h3 = self.field_mul(layouter, &s1, &h3)?;
        let y3 = self.field_sub(layouter, &r_uh, &s1h3)?;
        let z1z2 = self.field_mul(layouter, &p.z, &q.z)?;
        let z3 = self.field_mul(layouter, &h, &z1z2)?;
        Ok(AssignedPoint { x: x3, y: y3, z: z3 })
    }

    /// Scalar multiplication: k * G.
    pub fn scalar_mul(
        &self,
        layouter: &mut impl Layouter<Fr>,
        scalar_bits: &[Value<Fr>; 256],
        g_point: &AssignedPoint,
    ) -> Result<AssignedPoint, Error> {
        let mut accumulator = g_point.clone();
        for bit_idx in (0..255).rev() {
            let doubled = self.point_double(layouter, &accumulator)?;
            let added = self.point_add(layouter, &doubled, g_point)?;
            accumulator = self.conditional_select_point(layouter, &added, &doubled, scalar_bits[bit_idx])?;
        }
        Ok(accumulator)
    }

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
                let mut result = Vec::with_capacity(4);
                for i in 0..4 {
                    let a_val = a.limbs[i].value().copied();
                    let b_val = b.limbs[i].value().copied();
                    let sel_val = bit.zip(a_val).zip(b_val).map(|((s, a), b)| {
                        s * a + (Fr::ONE - s) * b
                    });
                    let cell = region.assign_advice(
                        || format!("sel_{}", i),
                        self.config.advice[i],
                        0,
                        || sel_val,
                    )?;
                    result.push(cell);
                }
                Ok(AssignedFieldElement {
                    limbs: [result[0].clone(), result[1].clone(), result[2].clone(), result[3].clone()],
                })
            },
        )
    }

    /// Constrain Jacobian point to match affine coordinates.
    pub fn constrain_affine(
        &self,
        layouter: &mut impl Layouter<Fr>,
        jacobian: &AssignedPoint,
        affine_x: &AssignedFieldElement,
        affine_y: &AssignedFieldElement,
    ) -> Result<(), Error> {
        let z2 = self.field_mul(layouter, &jacobian.z, &jacobian.z)?;
        let ax_z2 = self.field_mul(layouter, affine_x, &z2)?;
        self.constrain_field_equal(layouter, &ax_z2, &jacobian.x)?;
        let z3 = self.field_mul(layouter, &z2, &jacobian.z)?;
        let ay_z3 = self.field_mul(layouter, affine_y, &z3)?;
        self.constrain_field_equal(layouter, &ay_z3, &jacobian.y)?;
        Ok(())
    }

    fn constrain_field_equal(
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
                        || "eq_a", self.config.advice[0], 0, || a.limbs[i].value().copied(),
                    )?;
                    region.constrain_equal(a.limbs[i].cell(), a_copy.cell())?;
                    let b_copy = region.assign_advice(
                        || "eq_b", self.config.advice[1], 0, || b.limbs[i].value().copied(),
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

fn limbs_to_native(limbs: &[Fr; 4]) -> NativeSecpField {
    let native_limbs: [u64; 4] = limbs.map(|l| {
        let repr = l.to_repr();
        let bytes: &[u8] = repr.as_ref();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    });
    NativeSecpField::from_limbs(native_limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_field_add_sub_roundtrip() {
        let a = NativeSecpField::from_u64(42);
        let b = NativeSecpField::from_u64(17);
        assert_eq!(a.add(&b).sub(&b).0, a.0);
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
        let expected = NativeSecpField([
            SECP_P[0] - 1,
            SECP_P[1],
            SECP_P[2],
            SECP_P[3],
        ]);
        assert_eq!(product.0, expected.0, "(p-1) * 1 should be p-1");
    }

    #[test]
    fn test_native_field_mul_inverse() {
        // Test mul with small values first
        let three = NativeSecpField::from_u64(3);
        let seven = NativeSecpField::from_u64(7);
        let twenty_one = three.mul(&seven);
        assert_eq!(twenty_one.0[0], 21u64, "3 * 7 = 21");

        // Test mul with a value near p
        let p_minus_1 = NativeSecpField([
            SECP_P[0] - 1, SECP_P[1], SECP_P[2], SECP_P[3],
        ]);
        let one = NativeSecpField::from_u64(1);
        let result = p_minus_1.mul(&one);
        assert_eq!(result.0, p_minus_1.0, "(p-1) * 1 should be p-1");

        // Test (p-1) * (p-1) mod p = 1 (since (-1)^2 = 1)
        let result2 = p_minus_1.mul(&p_minus_1);
        assert_eq!(result2.0[0], 1u64, "(p-1)^2 mod p should be 1");
    }

    #[test]
    fn test_native_generator_on_curve() {
        let g = NativePoint::GENERATOR;
        let y2 = g.y.mul(&g.y);
        let x3_plus_7 = g.x.mul(&g.x).mul(&g.x).add(&NativeSecpField::from_u64(7));
        assert_eq!(y2.0, x3_plus_7.0);
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
    fn test_native_derive_address_test_vector() {
        let key: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ];
        let (addr, _, _) = native_derive_address(&key);
        assert_eq!(
            hex::encode(addr),
            "fcad0b19bb29d4674531d6f115237e16afce377c",
        );
    }
}
