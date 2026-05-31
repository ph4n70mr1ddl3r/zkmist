// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Mock Halo2 verifier for testing.
///      Matches the production Halo2Verifier interface:
///      verifyProof(address vk, bytes calldata proof, uint256[] calldata instances)
///      Accepts any structurally valid proof (non-zero recipient).
///      Used for testing airdrop logic without needing real Halo2 proofs.
contract MockHalo2Verifier {
    function verifyProof(
        address, /* vk */
        bytes calldata, /* proof */
        uint256[] calldata publicInputs
    )
        external
        pure
        returns (bool)
    {
        // Reject zero recipient (publicInputs[2])
        if (publicInputs.length < 3) return false;
        return publicInputs[2] != 0;
    }
}
