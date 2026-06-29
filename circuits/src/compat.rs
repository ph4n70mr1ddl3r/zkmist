//! Halo2 fork-API compatibility shim.
//!
//! `zkmist-circuits` is consumed by two workspaces with DIFFERENT halo2 forks:
//!   - the **main zkmist workspace**: crates.io `halo2_proofs` 0.3.x — 1-arg
//!     `query_fixed(col)` and unnamed `lookup(closure)`.
//!   - **`gen-production-verifier`'s separate workspace**: the PSE git fork
//!     `halo2_proofs` v0.3.0 — 2-arg `query_fixed(col, Rotation)` and named
//!     `lookup(name, closure)`. This fork is required because the vendored
//!     `halo2-solidity-verifier` is implemented against it, and the two forks
//!     are API-incompatible at the call site (crate types do not unify, so a
//!     circuit compiled under one cannot be passed to `keygen_vk` under the
//!     other).
//!
//! These wrappers route to the correct call signature via the `git-fork-api`
//! cargo feature (enabled ONLY by `gen-production-verifier`). They are
//! provably semantically identical across both branches:
//!   - `query_fixed`: crates.io hard-codes `Rotation::cur()` internally, so
//!     passing it explicitly under the git fork yields the SAME `FixedQuery`.
//!   - `lookup`: the name string is a debug label that does NOT appear in the
//!     constraint system's pinned representation (the git fork's `Argument`
//!     Debug impl emits only `input_expressions`/`table_expressions`), so the
//!     CS digest is byte-identical.
//!
//! Both invariants are guarded: `test_circuit_constraint_system_digest`
//! (crates.io side) and `gen-production-verifier`'s runtime parity assert
//! (git-fork side) must agree on `EXPECTED_CS_DIGEST`. If you change this
//! module, re-run both.

use halo2_proofs::plonk::{Column, ConstraintSystem, Expression, Fixed, TableColumn, VirtualCells};
use halo2curves::bn256::Fr;

#[cfg(feature = "git-fork-api")]
use halo2_proofs::poly::Rotation;

/// Query a fixed column at the current rotation, fork-agnostically.
///
/// Equivalent to `meta.query_fixed(column)` on crates.io (which internally
/// uses `Rotation::cur()`) and `meta.query_fixed(column, Rotation::cur())` on
/// the git fork.
pub fn query_fixed(meta: &mut VirtualCells<Fr>, column: Column<Fixed>) -> Expression<Fr> {
    #[cfg(feature = "git-fork-api")]
    {
        meta.query_fixed(column, Rotation::cur())
    }
    #[cfg(not(feature = "git-fork-api"))]
    {
        meta.query_fixed(column)
    }
}

/// Register a lookup argument, fork-agnostically.
///
/// `name` is a debug label used only by the git fork; it does not affect the
/// constraint system or its pinned digest. The lookup's input/table
/// expressions (the only thing that affects soundness and the digest) are
/// identical under both forks.
pub fn lookup<S: AsRef<str>>(
    meta: &mut ConstraintSystem<Fr>,
    name: S,
    table_map: impl FnOnce(&mut VirtualCells<Fr>) -> Vec<(Expression<Fr>, TableColumn)>,
) {
    #[cfg(feature = "git-fork-api")]
    {
        meta.lookup(name, table_map);
    }
    #[cfg(not(feature = "git-fork-api"))]
    {
        // crates.io `lookup` takes only the closure; the name is unused.
        let _ = name;
        meta.lookup(table_map);
    }
}
