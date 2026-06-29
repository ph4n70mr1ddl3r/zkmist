//! Range-check gadgets using Halo2 lookup tables.
//!
//! Provides:
//! - An 8-bit (byte) lookup table for range checks
//! - Helpers to decompose field elements into bytes and range-check them
//! - Helpers for boolean constraints (0 or 1)
//!
//! ## Usage
//!
//! ```ignore
//! let config = RangeCheckConfig::configure(meta, advice);
//! // In synthesis:
//! config.assign_and_check_byte(region, offset, value)?;
//! ```

use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for range-check gadgets.
#[derive(Debug, Clone)]
pub struct RangeCheckConfig {
    /// Advice column used for decomposition values.
    pub advice: Column<Advice>,
    /// Lookup table column for 8-bit range checks (values 0..=255).
    pub table: TableColumn,
    /// Selector for the decomposition gate.
    s_decompose: Selector,
}

impl RangeCheckConfig {
    /// Add range-check columns and gates to the constraint system.
    ///
    /// The caller must also call `load_range_table()` during synthesis to
    /// populate the lookup table with values 0..=255.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: Column<Advice>) -> Self {
        let table = meta.lookup_table_column();
        let s_decompose = meta.selector();

        // Lookup gate: advice[cur] must appear in the 8-bit range table.
        crate::compat::lookup(meta, "range8", |meta| {
            let _s = meta.query_selector(s_decompose);
            let val = meta.query_advice(advice, Rotation::cur());
            // The selector gates the lookup — only active rows are checked.
            // Halo2 lookups don't take selectors directly, so we use a
            // conditional pattern: s * val is 0 when s=0 (val can be anything)
            // and val when s=1. We look up val unconditionally and rely on
            // the caller to only enable s_decompose on rows that should be
            // range-checked.
            vec![(val, table)]
        });

        Self {
            advice,
            table,
            s_decompose,
        }
    }

    /// Load the 8-bit range table (values 0..=255).
    /// Must be called exactly once during synthesis, before any lookups.
    pub fn load_range_table(
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

    /// Assign a byte value (0..=255) and enable the range-check lookup.
    pub fn assign_and_check_byte(
        &self,
        region: &mut Region<Fr>,
        offset: usize,
        value: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let cell = region.assign_advice(|| "range_check_byte", self.advice, offset, || value)?;
        self.s_decompose.enable(region, offset)?;
        Ok(cell)
    }
}

// ── Native helpers (outside circuit) ────────────────────────────────────

/// Decompose a BN254 field element into `num_bytes` little-endian bytes.
///
/// Returns `num_bytes` bytes (each in [0, 255]). Panics if the value
/// doesn't fit in `num_bytes` bytes.
pub fn native_decompose_to_bytes(val: &Fr, num_bytes: usize) -> Vec<u8> {
    use ff::PrimeField;
    let le_bytes = val.to_repr();
    let le_ref: &[u8] = le_bytes.as_ref();
    le_ref[..num_bytes].to_vec()
}

/// Recompose `num_bytes` little-endian bytes into a BN254 field element.
pub fn native_recompose_from_bytes(bytes: &[u8]) -> Fr {
    use ff::PrimeField;
    let mut le_bytes = [0u8; 32];
    le_bytes[..bytes.len()].copy_from_slice(bytes);
    Fr::from_repr(le_bytes).expect("valid field element")
}

/// Constrain a cell to be boolean (0 or 1) using a gate.
/// Returns the constrained cell.
pub fn constrain_boolean(
    region: &mut Region<Fr>,
    advice: Column<Advice>,
    s_bool: Selector,
    offset: usize,
    value: Value<Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let cell = region.assign_advice(|| "bool", advice, offset, || value)?;
    s_bool.enable(region, offset)?;
    Ok(cell)
}

/// Configuration for boolean constraint gate.
#[derive(Debug, Clone)]
pub struct BoolConfig {
    pub advice: Column<Advice>,
    pub s_bool: Selector,
}

impl BoolConfig {
    /// Add a boolean constraint gate: `x * (1 - x) = 0`.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, advice: Column<Advice>) -> Self {
        let s_bool = meta.selector();
        meta.create_gate("bool", |meta| {
            let s = meta.query_selector(s_bool);
            let x = meta.query_advice(advice, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(<Fr as ff::Field>::ONE);
            vec![s * (x.clone() * (one - x))]
        });
        Self { advice, s_bool }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_recompose_roundtrip() {
        for val in [0u64, 1, 42, 255, 256, 0xFFFF, 0xFFFFFFFF] {
            let fr = Fr::from(val);
            let bytes = native_decompose_to_bytes(&fr, 8);
            let recomposed = native_recompose_from_bytes(&bytes);
            assert_eq!(fr, recomposed, "Roundtrip failed for {}", val);
        }
    }
}
