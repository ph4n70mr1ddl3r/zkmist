//! ZKMist V2 Circuits — axiom-backend Halo2-KZG anonymous airdrop claim proofs.
//!
//! The axiom claim circuit (`claim_axiom`) enforces:
//! 1. **Key → Address**: secp256k1 scalar multiplication (halo2-ecc) + Keccak-256
//! 2. **Leaf hash**: `poseidon(address)` — t=2 (halo2-base)
//! 3. **Merkle proof**: 26-level Poseidon Merkle path verification (halo2-base)
//! 4. **Nullifier**: `poseidon(Fr(key), Fr(domain))` with V2 domain separator
//! 5. **Non-zero recipient**: Rejects address(0)
//! 6. **K < n_secp256k1**: range proof (§5a TRAP)
//!
//! All gadgets run on audited axiom libraries (halo2-ecc, halo2-base). See
//! `docs/axiom-backend-migration.md` for the migration history + findings.

pub mod claim_axiom;
pub mod keccak_axiom;
pub mod merkle_axiom;
pub mod nullifier_axiom;
pub mod poseidon_axiom;
pub mod secp_axiom;
