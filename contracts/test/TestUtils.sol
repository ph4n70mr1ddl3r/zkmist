// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IRiscZeroVerifier} from "../src/IRiscZeroVerifier.sol";

/// @dev A noop verifier that accepts any proof. Shared across test files.
///      Used for testing airdrop logic without needing real RISC Zero proofs.
contract NoopVerifier is IRiscZeroVerifier {
    function verify(
        bytes calldata,
        bytes32,
        bytes32
    ) external pure override {}
}
