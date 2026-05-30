// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHalo2Verifier} from "../src/Halo2Verifier.sol";

/// @dev Mock Halo2 verifier for testing.
///      Returns IS_PRODUCTION_VERIFIER = true so the airdrop constructor
///      accepts it. Accepts any structurally valid proof (non-zero recipient).
///      Used for testing airdrop logic without needing real Halo2 proofs.
contract MockHalo2Verifier is IHalo2Verifier {
    function verify(bytes calldata, uint256[3] memory publicInputs) external pure returns (bool) {
        return publicInputs[2] != 0;
    }

    function IS_PRODUCTION_VERIFIER() external pure returns (bool) {
        return true;
    }
}
