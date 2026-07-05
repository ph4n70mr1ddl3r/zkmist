// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Production axiom SHPLONK proof byte length at k=21 (the depth-26 claim
///      circuit). Mirrors `PROOF_LENGTH_EXPECTED` in `cli/src/constants.rs`;
///      the CLI `submit` gate accepts proofs in `[500, 4000]`. Mock-verifier
///      tests build fixtures of this size so they reflect the REAL proof shape
///      rather than the stale `5888`-byte pre-migration estimate (which the
///      real CLI gate would REJECT as > 4000). The mock only requires calldata
///      >= 0x60 (3 instance words), so any in-range length verifies; the value
///      is chosen for realism, not correctness.
uint256 constant PROOF_LENGTH = 1376;

/// @dev Mock Halo2 verifier for testing — mirrors the production axiom
///      `Halo2Verifier` (snark-verifier-generated) `fallback` interface.
///      The contract calls `staticcall(encode_calldata(instances, proof))` where
///      calldata = instances (32-byte big-endian each) ++ proof. This mock
///      accepts any structurally valid calldata (non-zero recipient at
///      instance[2]) so airdrop-logic tests run without real Halo2 proofs.
contract MockHalo2Verifier {
    fallback(bytes calldata data) external returns (bytes memory) {
        require(data.length >= 0x60, "bad calldata");
        // instance[2] = recipient, at byte offset 0x40 (3rd 32-byte word).
        uint256 recipient;
        assembly {
            recipient := calldataload(0x40)
        }
        require(recipient != 0, "zero recipient");
        return "";
    }
}
