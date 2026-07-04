// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

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
