// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ZKMToken} from "../src/ZKMToken.sol";
import {ZKMAirdrop} from "../src/ZKMAirdrop.sol";
import {Halo2Verifier} from "../src/Halo2Verifier.axiom.sol";

/// @title ProofVerifier — off-chain verification of a CLI `proof.json` via revm
/// @notice Reimplements `zkmist verify`: runs the REAL on-chain Halo2Verifier
///         (the committed `Halo2Verifier.axiom.sol` — the exact bytecode deployed
///         on Base) against a claimant's `proof.json` inside `forge test`'s local
///         EVM (revm). A proof can thus be checked cryptographically WITHOUT
///         broadcasting a transaction or spending gas.
///
/// ## Why this exists
///
/// The PSE Rust-side verifier was removed when the project moved to the axiom
/// Halo2-KZG stack, so the on-chain `Halo2Verifier` (Solidity) is the ONLY
/// verifier. `zkmist verify <file>` therefore shells out to this test: it
/// deploys the real verifier + airdrop in revm and runs
/// `claim(proof, nullifier, recipient)`, which builds
/// `instances = [merkleRoot, nullifier, recipient, chainId] ++ proof` and
/// `staticcall`s the verifier with real BN254 pairings. A pass here means the
/// proof WILL be accepted on-chain by `zkmist submit` (same calldata, same VK).
///
/// ## Gating
///
///   • Default (`PROOF_FILE` unset): the test SKIPS — keeps `forge test` green.
///   • Opted in (`PROOF_FILE=<path>`): HARD GATE — a missing file or a failed
///     verify REVERTS (no silent pass).
///
/// Run directly:
///
///     PROOF_FILE=fixtures/real_roundtrip.json \
///       forge test --match-contract ProofVerifier -vvv
///
/// `zkmist verify` drives this. It stages the proof under `contracts/fixtures/`
/// because foundry's `fs_permissions` only grants read access to the project
/// root, and a claimant's proof normally lives in `~/.zkmist/proofs/`.
contract ProofVerifier is Test {
    ZKMToken internal token;
    ZKMAirdrop internal airdrop;
    Halo2Verifier internal verifier;

    /// Production Merkle root (mirrors `constants.rs` `KNOWN_MERKLE_ROOT` — the
    /// single source of truth on the CLI side). Mirrored here so a default
    /// `verify` needs no extra env. Override with `MERKLE_ROOT=0x...` to verify
    /// a proof generated against a non-production tree (dev/test).
    string internal constant KNOWN_MERKLE_ROOT =
        "0x00cf0fa589ba3f949eec2774dca17df0c00a99497b31d70b76767d4dba38c0ba";

    bool internal _armed;
    string internal _json;

    function setUp() public {
        // ── Default path: skip (keep `forge test` green) ───────────────
        string memory proofFile = vm.envOr("PROOF_FILE", string(""));
        if (bytes(proofFile).length == 0) {
            console.log("ProofVerifier: skipped (set PROOF_FILE=<path> to verify a proof).");
            return;
        }

        // ── Opted in: HARD GATE — a missing file MUST fail, not skip ────
        if (!vm.exists(proofFile)) {
            revert("ProofVerifier: PROOF_FILE does not exist");
        }
        _json = vm.readFile(proofFile);

        // `chain_id` is a public instance / Fiat-Shamir transcript input, so the
        // local EVM chain id MUST equal the one baked into the proof. Foundry
        // defaults to 31337; the production proof is for Base (8453).
        // Accept both spellings: CLI `proof.json` uses `chainId` (camelCase);
        // the `gen-roundtrip-fixture` fixture uses `chain_id` (snake_case).
        uint256 chainId = vm.keyExistsJson(_json, ".chainId")
            ? vm.parseJsonUint(_json, ".chainId")
            : vm.parseJsonUint(_json, ".chain_id");
        vm.chainId(uint64(chainId));

        // Deterministic, pre-deadline timestamp (`claim` requires
        // block.timestamp < CLAIM_DEADLINE = 2027-01-01). Not a public input,
        // so it never affects the proof's cryptographic validity.
        vm.warp(1_700_000_000);

        bytes32 merkleRoot = vm.parseBytes32(_normHex(vm.envOr("MERKLE_ROOT", KNOWN_MERKLE_ROOT)));

        // ── Deploy the REAL contracts (mirrors script/Deploy.s.sol) ─────
        // Token minter is immutable, so predict the airdrop address from the
        // deployer nonce and pass it into the token constructor (nonce+2:
        // verifier, then token, then airdrop).
        address deployer = address(this);
        uint256 nonce = vm.getNonce(deployer);
        address predictedAirdrop = vm.computeCreateAddress(deployer, nonce + 2);

        verifier = new Halo2Verifier();
        token = new ZKMToken(predictedAirdrop);
        airdrop = new ZKMAirdrop(address(token), address(verifier), merkleRoot);

        require(token.minter() == address(airdrop), "minter prediction failed");
        require(airdrop.merkleRoot() == merkleRoot, "root mismatch");

        _armed = true;
        console.log("ProofVerifier: armed. Running real KZG verify + claim() in revm.");
        console.log("  If it reverts with 'Invalid proof', the prover and the on-chain");
        console.log("  Halo2Verifier/VK disagree (wrong root, chain, SRS, or tampered bytes).");
    }

    /// @dev The single real verify: `claim()` builds the instance calldata and
    ///      `staticcall`s the verifier with real BN254 pairings. No early return
    ///      when armed — any verifier failure surfaces as a revert here.
    function test_verifyProof() public {
        if (!_armed) {
            console.log("ProofVerifier: not armed -- nothing to run. See test header.");
            return;
        }

        bytes memory proof = vm.parseBytes(_normHex(vm.parseJsonString(_json, ".proof")));
        bytes32 nullifier = vm.parseBytes32(_normHex(vm.parseJsonString(_json, ".nullifier")));
        address recipient = vm.parseAddress(_normHex(vm.parseJsonString(_json, ".recipient")));

        require(recipient != address(0), "recipient is zero");

        // `claim` reverts with "Invalid proof" if the verifier rejects the
        // pairing/transcript (wrong root, tampered bytes, mismatched VK/SRS).
        uint256 balBefore = token.balanceOf(recipient);
        airdrop.claim(proof, nullifier, recipient);
        uint256 balAfter = token.balanceOf(recipient);

        require(balAfter - balBefore == 10_000e18, "mint amount mismatch");
        require(airdrop.usedNullifiers(nullifier), "nullifier not marked used");

        console.log("ProofVerifier: OK -- real KZG proof verified; 10,000 ZKM would mint.");
        console.log("  This proof will be accepted by `zkmist submit` on Base.");
    }

    /// @dev Prepend `0x` if missing. The CLI `proof.json` serializes `proof` /
    ///      `nullifier` / `recipient` as bare hex (no `0x`); `vm.parseBytes*`
    ///      and `vm.parseAddress` require the prefix. (The `gen-roundtrip-fixture`
    ///      fixture, by contrast, is already `0x`-prefixed.)
    function _normHex(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= 2 && b[0] == 0x30 && (b[1] == 0x78 || b[1] == 0x58)) {
            return s; // already 0x / 0X prefixed
        }
        return string.concat("0x", s);
    }
}
