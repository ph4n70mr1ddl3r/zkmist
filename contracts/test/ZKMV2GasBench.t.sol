// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZKMTokenV2} from "../src/ZKMTokenV2.sol";
import {ZKMAirdropV2} from "../src/ZKMAirdropV2.sol";
import {MockHalo2Verifier} from "./TestUtils.sol";

/// @title ZKM V2 Gas Benchmarks
/// @notice Gas snapshot tests for V2 contract operations.
///         Run with: forge test --match-contract ZKMV2GasBench -vvv --gas-report
///         Or:      forge snapshot --match-contract ZKMV2GasBench
contract ZKMV2GasBench is Test {
    ZKMTokenV2 public token;
    ZKMAirdropV2 public airdrop;
    MockHalo2Verifier public verifier;

    address constant MINTER = address(0x1);
    bytes32 constant MERKLE_ROOT =
        0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844;

    function setUp() public {
        verifier = new MockHalo2Verifier();
        token = new ZKMTokenV2(MINTER);
        airdrop = new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
    }

    // ── Token gas benchmarks ────────────────────────────────────────────

    function testGas_token_deploy() public {
        new ZKMTokenV2(address(this));
    }

    function testGas_token_mint() public {
        vm.prank(MINTER);
        token.mint(address(0xB0B), 10_000e18);
    }

    function testGas_token_burn() public {
        vm.prank(MINTER);
        token.mint(address(this), 10_000e18);
        token.burn(5_000e18);
    }

    function testGas_token_burnFrom() public {
        vm.prank(MINTER);
        token.mint(address(0xB0B), 10_000e18);

        vm.prank(address(0xB0B));
        token.approve(address(this), 5_000e18);

        token.burnFrom(address(0xB0B), 5_000e18);
    }

    function testGas_token_transfer() public {
        vm.prank(MINTER);
        token.mint(address(this), 10_000e18);
        token.transfer(address(0xB0B), 1_000e18);
    }

    function testGas_token_approve() public {
        vm.prank(MINTER);
        token.mint(address(this), 10_000e18);
        token.approve(address(0xB0B), type(uint256).max);
    }

    // ── Airdrop gas benchmarks ──────────────────────────────────────────

    function testGas_airdrop_deploy() public {
        new ZKMAirdropV2(address(token), address(verifier), MERKLE_ROOT);
    }

    function testGas_airdrop_isClaimWindowOpen() public view {
        airdrop.isClaimWindowOpen();
    }

    function testGas_airdrop_claimsRemaining() public view {
        airdrop.claimsRemaining();
    }

    function testGas_airdrop_isClaimed() public view {
        airdrop.isClaimed(bytes32(uint256(42)));
    }

    // ── Full deployment (3 contracts) gas benchmark ─────────────────────

    function testGas_full_deploy() public {
        MockHalo2Verifier v = new MockHalo2Verifier();
        address predictedAirdrop = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        ZKMTokenV2 t = new ZKMTokenV2(predictedAirdrop);
        ZKMAirdropV2 a = new ZKMAirdropV2(address(t), address(v), MERKLE_ROOT);
        assert(t.minter() == address(a));
    }

    receive() external payable {}
}
