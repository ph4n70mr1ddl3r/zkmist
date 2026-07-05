// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.axiom.sol";

contract BugHuntTest is Test {
    ZKMToken token;
    Halo2Verifier verifier;
    ZKMAirdrop airdrop;

    function setUp() public {
        verifier = new Halo2Verifier();

        address airdropAddr = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        token = new ZKMToken(airdropAddr);
        
        airdrop = new ZKMAirdrop(address(token), address(verifier), bytes32(0));
    }

    function test_emptyProof() public {
        vm.expectRevert();
        airdrop.claim("", bytes32(uint256(1)), address(0x123));
    }
}
