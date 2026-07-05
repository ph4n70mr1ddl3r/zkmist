// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {MockHalo2Verifier, PROOF_LENGTH} from "./TestUtils.sol";

contract MalleabilityTest is Test {
    ZKMToken token;
    MockHalo2Verifier verifier;
    ZKMAirdrop airdrop;

    uint256 constant F_Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        verifier = new MockHalo2Verifier();
        
        address airdropAddr = computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        token = new ZKMToken(airdropAddr);
        
        airdrop = new ZKMAirdrop(address(token), address(verifier), bytes32(0));
    }

    function test_malleability_rejected() public {
        bytes memory fakeProof = new bytes(PROOF_LENGTH);
        bytes32 nullifier = bytes32(uint256(1));
        address recipient = address(0xB0B);

        // First claim
        airdrop.claim(fakeProof, nullifier, recipient);

        // Malleable claim
        bytes32 malleableNullifier = bytes32(uint256(nullifier) + F_Q);
        
        vm.expectRevert("Nullifier out of field");
        airdrop.claim(fakeProof, malleableNullifier, recipient);
    }
}
