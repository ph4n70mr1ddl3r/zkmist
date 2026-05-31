# ZKMist — Architecture Document

**Version:** 2.0  
**Date:** 2026-05-30  
**Status:** Implementation (beta — circuit soundness hardened, production verifier generation remaining)  
**Author:** ZKMist Community  

> **NOTE:** This document describes the current ZKMist architecture using Halo2-KZG custom circuits.  
> The prior RISC Zero ("V1") approach has been fully removed. All references to "V1", "V2", and  
> "prior approach" below are preserved for historical context but the codebase now contains only  
> the Halo2-KZG implementation. Contract names no longer carry "V2" suffixes.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Motivation](#2-motivation)
3. [Design Goals](#3-design-goals)
4. [Architecture Overview](#4-architecture-overview)
5. [Proof System Selection](#5-proof-system-selection)
6. [Circuit Design](#6-circuit-design)
7. [Smart Contracts](#7-smart-contracts)
8. [CLI & Prover Tool](#8-cli--prover-tool)
9. [Prior Approach & Why It Changed](#9-prior-approach--why-it-changed)
10. [What Is Reused](#10-what-is-reused)
11. [Project Structure](#11-project-structure)
12. [Dependencies](#12-dependencies)
13. [Test Vectors](#13-test-vectors)
14. [Development Timeline](#14-development-timeline)
15. [Deployment Plan](#15-deployment-plan)
16. [Security Considerations](#16-security-considerations)
17. [Risks & Mitigations](#17-risks--mitigations)
18. [Gas & Cost Analysis](#18-gas--cost-analysis)
19. [Appendix A: Prior Approach Comparison](#19-appendix-a-prior-approach-comparison)
20. [Appendix B: Halo2-KZG Primer](#20-appendix-b-halo2-kzg-primer)
21. [Appendix C: Ethereum KZG Ceremony](#21-appendix-c-ethereum-kzg-ceremony)
22. [Appendix D: Circuit Constraint Breakdown](#22-appendix-d-circuit-constraint-breakdown)

---

## 1. Executive Summary

ZKMist V2 replaces the RISC Zero zkVM proving pipeline with **Halo2-KZG custom circuits**, reducing proof generation from **~50 minutes to ~10-30 seconds** while preserving all privacy guarantees, the same eligibility list, and the same Merkle tree.

**Key changes:**
- **Proof system:** RISC Zero (STARK → Groth16 wrap) → **Halo2-KZG** (direct proof)
- **Proving time:** ~50 min → **~10-30 sec** (~100-300x faster)
- **Prerequisites:** RISC Zero toolchain (~2 GB) → **Rust only** (~50 MB)
- **On-chain gas:** ~510K → **~350-400K** (~$0.10-0.12 per claim)
- **Trusted setup:** None → **Universal** (Ethereum KZG ceremony, 140K+ participants)
- **Contracts:** New deployment on Base

**What is preserved from the existing data pipeline:**
- Eligibility list (64,116,228 addresses)
- Poseidon Merkle tree (same parameters, root `0x1eaf...7844`)
- Nullifier scheme: `poseidon(Fr(key), Fr("ZKMist_V2_NULLIFIER"))`
- Privacy model (qualified address never revealed on-chain)
- Token economics (10,000 ZKM/claim, 1M cap, 2027-01-01 deadline)
- Contract design philosophy (immutable, no admin, no owner, no pause)

**Note on the prior approach:** An earlier prototype used RISC Zero (STARK → Groth16 wrap) for proving. That approach has been **fully abandoned** — no migration, no coexistence. The prior contracts were never used (zero claims) and are irrelevant. ZKMist V2 is a clean implementation built on Halo2-KZG.

---

## 2. Motivation

### 2.1 The Problem

The prior approach used the RISC Zero zkVM — a general-purpose zero-knowledge virtual machine that proves arbitrary RISC-V programs. While powerful and developer-friendly, the generic CPU emulation layer creates massive proving overhead:

| Operation | Native CPU | Halo2 Circuit | RISC Zero zkVM |
|-----------|-----------|---------------|----------------|
| secp256k1 scalar mult | ~50 μs | ~250K constraints | ~80M RISC-V instructions |
| Keccak-256 hash | ~1 μs | ~200K constraints | ~10M RISC-V instructions |
| Poseidon hash | ~10 μs | ~276 constraints | ~200K RISC-V instructions |

The zkVM is **~10,000x slower** than direct circuits because every operation is emulated instruction-by-instruction, and each instruction becomes hundreds of STARK constraints.

### 2.2 Measured Performance

On a 32-core machine with cached Merkle proof:

| Metric | Prior Approach (measured) |
|--------|--------------|
| zkVM proving (STARK + Groth16) | ~50-60 minutes |
| Segments | 49 |
| Total RISC-V cycles | ~205.5M |
| User experience | Unacceptable for most users |

### 2.3 Why Not GPU Acceleration

GPU acceleration (RISC Zero's `cuda` feature) reduces proving to ~3-5 minutes but requires:
- NVIDIA GPU with compute capability ≥ 7.0 (Volta or newer)
- ≥ 8 GB VRAM (16GB+ recommended)
- Most users do not have such hardware

A custom circuit approach provides 10-30 second proving on **any modern CPU** — no special hardware needed.

### 2.4 Why Now

- The prior RISC Zero prototype proved impractical for users (~50 min proving time)
- No claims were ever submitted using the prior approach
- Rebuilding before any adoption minimizes confusion
- The eligibility data pipeline is already built and reusable

---

## 3. Design Goals

| # | Goal | Priority |
|---|------|----------|
| DG1 | **Proving time < 60 seconds** on commodity hardware | Critical |
| DG2 | **No special hardware required** (no GPU, no RISC Zero toolchain) | Critical |
| DG3 | **Preserve full privacy guarantees** | Critical |
| DG4 | **Preserve eligibility list and Merkle tree** | Critical |
| DG5 | **Minimize on-chain gas** (target < 400K) | High |
| DG6 | **No per-circuit trusted setup ceremony** | High |
| DG7 | **Reuse existing Merkle tree library** | High |
| DG8 | **Rust-native development** (no new languages) | Medium |
| DG9 | **Simpler on-chain verification** | Medium |
| DG10 | **Compatible test vectors** | Medium |

---

## 4. Architecture Overview

### 4.1 Proving Pipeline

```
  User's Machine
  ────────────────────────────────────────────────────────────
  
  Private key ──────────────┐
                            │
  Merkle proof (cached) ────┤
                            ├──> Halo2 prover (10-30 sec)
  Recipient address ────────┘         │
                                      │  Circuit enforces:
                                      │  1. secp256k1: key → address
                                      │  2. Poseidon: address → leaf
                                      │  3. Merkle: leaf → root (26 levels)
                                      │  4. Nullifier: poseidon(key, domain)
                                      │  5. recipient ≠ 0x0
                                      │
                                      ▼
                               Halo2-KZG proof
                             (~500-800 bytes)
                                      │
                            proof.json ─┘
                                      
  ────────────────────────────────────────────────────────────
                              │
                              ▼
  
  Base (on-chain)
  ────────────────────────────────────────────────────────────
  
  ZKMAirdropV2.claim(proof, nullifier, recipient)
     │
     ├── Halo2Verifier.verify(proof, [merkleRoot, nullifier, recipient])
     │       Single KZG pairing check (~300K gas)
     │
     ├── require(!usedNullifiers[nullifier])
     ├── require(totalClaims < MAX_CLAIMS)
     ├── require(block.timestamp < CLAIM_DEADLINE)
     ├── require(recipient != address(0))
     │
     ├── usedNullifiers[nullifier] = true
     ├── totalClaims++
     └── ZKMTokenV2.mint(recipient, 10_000e18)
```

### 4.2 Comparison with Prior Pipeline

```
Prior approach:
  key + proof data → ExecutorEnv → RISC Zero zkVM → STARK proof (49 segments)
                  → Groth16 compression → Groth16 seal → on-chain verify

ZKMist (Halo2):
  key + proof data → Halo2 circuit → KZG proof → on-chain verify

  Fewer steps. No CPU emulation. No STARK. No Groth16 wrapping.
```

---

## 5. Proof System Selection

### 5.1 Decision: Halo2-KZG

| Property | Value |
|----------|-------|
| **Proof system** | Halo2 (PLONKish, ZCash/PSE) |
| **Commitment scheme** | KZG (Kate-Zaverucha-Goldberg) |
| **Curve** | BN254 (native precompile on Ethereum/Base) |
| **Setup** | Universal — reuses Ethereum KZG ceremony (140K+ participants) |
| **Proof size** | ~500-800 bytes |
| **Proving time** | ~10-30 seconds on commodity CPU |
| **Verification** | Single pairing check (~300K gas on-chain) |

### 5.2 Why Halo2-KZG over Alternatives

| Factor | Halo2-KZG | Groth16 (circom) | PLONK | Halo2-IPA |
|--------|-----------|-------------------|-------|-----------|
| Proving time | 10-40s | 5-30s | 10-40s | 30-120s |
| On-chain gas | ~350-400K | ~300K | ~350K | ~700K+ |
| Trusted setup | Universal (140K+) | Per-circuit ceremony | Universal | **None** |
| Language | **Rust** (fits codebase) | circom (new DSL) | circom/Rust | Rust |
| Lookup tables | **Yes** (secp256k1 optimization) | No | No | Yes |
| Production use | Scroll, Taiko, Polygon zkEVM | Tornado Cash, Semaphore | Filecoin, Celo | ZCash |

**Selection rationale:**

1. **Rust-native**: Halo2 circuits are written in Rust — fits the existing codebase. No new language (circom) to learn.
2. **Lookup tables**: Halo2's lookup argument dramatically reduces the cost of secp256k1 bit decomposition, the circuit's most expensive operation.
3. **Universal setup**: Reuses the Ethereum KZG ceremony (140K+ participants). No per-circuit ceremony needed. No toxic waste risk unique to ZKMist.
4. **Production-proven**: Scroll processes millions of transactions daily using Halo2-KZG. The Solidity verifier has been battle-tested.
5. **Same curve**: BN254 is the native precompile curve on Ethereum/Base. KZG pairing checks use the `ecPairing()` precompile.

### 5.3 Trusted Setup Details

ZKMist V2 does **not** require its own trusted setup ceremony. It reuses the **Ethereum KZG Ceremony** (EIP-4844):

| Property | Value |
|----------|-------|
| Ceremony name | EIP-4844 KZG Ceremony |
| Participants | ~140,000+ |
| Notable participants | Vitalik Buterin, Ethereum Foundation members, protocol teams |
| Security assumption | At least 1 of 140,000+ participants was honest |
| SRS size | 2¹² BN254 G1 points + 256 G2 points |
| SRS location | Hardcoded in `halo2curves` crate |

**Trusted setup comparison:**

The prior approach (STARK) had zero setup dependencies. Halo2-KZG depends on the Ethereum ceremony. The practical security difference is negligible — compromising the Ethereum ceremony requires subverting 140,000+ independent participants across different organizations, countries, and hardware. This is widely considered at least as secure as any individual project's ceremony, and practically equivalent to no setup.

---

## 6. Circuit Design

### 6.1 Circuit Interface

**Public inputs** (revealed on-chain, encoded in the proof):

| Index | Name | Type | Description |
|-------|------|------|-------------|
| 0 | `merkle_root` | `Fr` (32 bytes) | Known merkle root of eligibility tree |
| 1 | `nullifier` | `Fr` (32 bytes) | `poseidon(Fr(key), Fr(domain))` |
| 2 | `recipient` | `Fr` (20 bytes) | Address to receive tokens (padded to 32 bytes) |

**Private inputs** (never leave the user's machine):

| Name | Type | Description |
|------|------|-------------|
| `private_key` | `[u8; 32]` | secp256k1 private key |
| `siblings` | `[[u8; 32]; 26]` | Merkle proof sibling hashes |
| `path_indices` | `[bool; 26]` | Merkle proof direction flags |

### 6.2 Circuit Logic

The circuit enforces the following constraints:

```
Circuit ZKMistV2Claim {

    // === 1. Address Derivation ===
    // Proves: "I know a private key that derives this Ethereum address"
    
    // 1a. secp256k1 scalar multiplication: private_key → public_key
    pub_key_x, pub_key_y = secp256k1_scalar_mul(private_key, G)
    
    // 1b. Encode public key (uncompressed, 65 bytes: 0x04 || x || y)
    pub_key_bytes = encode_uncompressed(pub_key_x, pub_key_y)
    
    // 1c. Keccak-256 hash: take hash of pub_key_bytes[1..65], extract last 20 bytes
    keccak_hash = keccak256(pub_key_bytes[1..65])
    address = keccak_hash[12..32]   // last 20 bytes
    
    // === 2. Leaf Hash ===
    // Proves: "The address hashes to this leaf in the Merkle tree"
    
    address_padded = 0x00...00 || address    // left-pad to 32 bytes
    address_field = Fr::from_be_bytes(address_padded)
    leaf = poseidon_1(address_field)         // t=2, 1 input, R_F=8, R_P=56
    
    // === 3. Merkle Proof ===
    // Proves: "This leaf is in the eligibility tree with the given root"
    
    current = leaf
    for i in 0..26:
        if path_indices[i] == 0:    // current is LEFT child
            current = poseidon_2(current, siblings[i])   // t=3, 2 inputs
        else:                        // current is RIGHT child
            current = poseidon_2(siblings[i], current)
    
    assert(current == merkle_root)   // PUBLIC INPUT constraint
    
    // === 4. Nullifier ===
    // Proves: "The nullifier was computed from the same private key"
    
    key_field = Fr::from_be_bytes(private_key)
    domain_field = Fr::from_be_bytes("ZKMist_V2_NULLIFIER" || 0x00...00)
    expected_nullifier = poseidon_2(key_field, domain_field)
    
    assert(expected_nullifier == nullifier)   // PUBLIC INPUT constraint
    
    // === 5. Non-zero Recipient ===
    
    assert(recipient != 0)   // PUBLIC INPUT constraint
}
```

### 6.3 Gadget Breakdown

#### 6.3.1 secp256k1 Scalar Multiplication Gadget

The most complex gadget. Proves `P = k * G` on the secp256k1 curve.

**Approach:** Use a windowed scalar multiplication with lookup tables for range checks.

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 (a=0, b=7, p=2²⁵⁶ - 2³² - 977) |
| Field | 256-bit prime |
| Window size | 4 bits (64 windows for 256-bit scalar) |
| Lookup tables | Range checks for 4-bit windows, addition/doubling formulas |
| Constraints | ~50-100K (with lookup optimization) |
| Reference implementation | `scroll-tech/halo2-secp256k1`, `summa-dev/summa-solvency` |

**Implementation notes:**
- secp256k1 field arithmetic is done modulo `p_secp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
- This is NOT the same as the BN254 scalar field (`p_bn254 ≈ 2²⁵⁴`). The circuit must handle non-native field arithmetic.
- Use Halo2 lookup tables for efficient bit decomposition and range checks.
- The gadget must handle the special case of the point at infinity.

#### 6.3.2 Keccak-256 Gadget

Hashes the uncompressed public key (64 bytes, excluding 0x04 prefix) to derive the Ethereum address.

| Parameter | Value |
|-----------|-------|
| Input | 64 bytes (pub_key_x || pub_key_y) |
| Output | 32 bytes (take bytes[12..32] as address) |
| Rounds | 24 Keccak-f permutations |
| Constraints | ~150-200K |
| Reference implementation | `privacy-scaling-explorations/halo2wrong` |

#### 6.3.3 Poseidon Hash Gadget

Two variants, both using BN254 scalar field:

| Variant | t | Inputs | R_F | R_P | Usage |
|---------|---|--------|-----|-----|-------|
| Leaf hash | 2 | 1 | 8 | 56 | `poseidon(address)` → leaf |
| Interior hash | 3 | 2 | 8 | 57 | `poseidon(left, right)` → parent |
| Nullifier | 3 | 2 | 8 | 57 | `poseidon(key_field, domain_field)` |

**Implementation:** Port the round constants and MDS matrix from `light-poseidon` (already in the codebase) into Halo2 gadgets.

**Poseidon gadget constraints per hash:** ~276 (R_F full rounds + R_P partial rounds × t)

**Total Poseidon constraints:** 27 hashes × ~276 = ~7,500 constraints

The Poseidon parameters (round constants, MDS matrix) MUST match the existing Merkle tree exactly to produce the correct root.

#### 6.3.4 Merkle Proof Gadget

Verifies a 26-level Poseidon Merkle proof.

```rust
// Pseudocode for the Merkle gadget
fn merkle_gadget(
    leaf: AssignedCell<Fr>,           // Poseidon hash of address
    siblings: [AssignedCell<Fr>; 26], // Sibling hashes
    path_indices: [AssignedCell<Fr>; 26], // 0 or 1
    root: AssignedCell<Fr>,           // Expected root (public input)
    poseidon_gadget: &mut PoseidonGadget,
) {
    let mut current = leaf;
    for i in 0..26 {
        // Conditional swap based on path_index
        let (left, right) = cond_swap(
            current.clone(),
            siblings[i].clone(),
            path_indices[i].clone(),
        );
        current = poseidon_gadget.hash_two(left, right);
    }
    // Constrain computed root equals expected root
    constrain_equal(current, root);
}
```

#### 6.3.5 Nullifier Gadget

```rust
fn nullifier_gadget(
    private_key: AssignedCell<Fr>,
    expected_nullifier: AssignedCell<Fr>,  // Public input
    poseidon_gadget: &mut PoseidonGadget,
) {
    let domain = Fr::from_be_bytes_mod_order(b"ZKMist_V2_NULLIFIER___\0\0\0\0\0\0\0\0\0\0\0\0\0");
    let computed = poseidon_gadget.hash_two(private_key, domain);
    constrain_equal(computed, expected_nullifier);
}
```

**IMPORTANT:** The domain separator is `"ZKMist_V2_NULLIFIER"`. This provides protocol version separation for future-proofing.

### 6.4 Estimated Circuit Size

| Gadget | Constraints (cells) | Notes |
|--------|-------------------|-------|
| secp256k1 scalar mul | ~50-100K | Non-native field arithmetic |
| Keccak-256 | ~200-300K | 24 rounds, 1600-bit state |
| Poseidon (27 hashes) | ~7.5K | t=2 and t=3 variants |
| Merkle proof wiring | ~2K | Conditional swaps, equality constraints |
| Nullifier wiring | ~0.3K | Single Poseidon hash + equality |
| Range checks & misc | ~5K | Bool checks, non-zero checks |
| **Total (estimated)** | **~265-415K** | |

The circuit is relatively small by Halo2 standards. For reference, Scroll's zkEVM circuit has millions of cells. If the total exceeds ~500K, k=20 will be needed (increasing proof size and gas). The Phase 2 benchmarking task (T2.11) will confirm the actual size.

---

## 7. Smart Contracts

### 7.1 Overview

V2 deploys 3 contracts on Base:

| Contract | Description |
|----------|-------------|
| `Halo2Verifier` | Auto-generated KZG verifier |
| `ZKMTokenV2` | ERC-20 token (10B max supply) |
| `ZKMAirdropV2` | Immutable claim contract |

### 7.2 ZKMAirdropV2.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZKMTokenV2} from "./ZKMTokenV2.sol";
import {Halo2Verifier} from "./Halo2Verifier.sol";

/// @title ZKMAirdropV2 — Privacy-preserving ZKM token claim contract (Halo2)
/// @notice Fully immutable. No admin, no owner, no pause, no upgrade.
contract ZKMAirdropV2 {
    ZKMTokenV2 public immutable token;
    Halo2Verifier public immutable verifier;
    bytes32 public immutable merkleRoot;

    uint256 public constant CLAIM_AMOUNT = 10_000e18;
    uint256 public constant MAX_CLAIMS = 1_000_000;
    uint256 public constant CLAIM_DEADLINE = 1_798_761_600; // 2027-01-01 00:00:00 UTC
    uint256 public constant MIN_PROOF_LENGTH = 4000;
    uint256 public constant MAX_PROOF_LENGTH = 8000;

    uint256 public totalClaims;
    mapping(bytes32 => bool) public usedNullifiers;

    event Claimed(
        bytes32 indexed nullifier,
        uint256 amount,
        address indexed recipient,
        uint256 totalClaims
    );

    constructor(
        address _token,
        address _verifier,
        bytes32 _merkleRoot
    ) {
        token = ZKMTokenV2(_token);
        verifier = Halo2Verifier(_verifier);
        merkleRoot = _merkleRoot;
    }

    /// @notice Claim ZKM tokens with a valid Halo2 proof.
    /// @param proof The Halo2 KZG proof bytes.
    /// @param nullifier The claim's nullifier.
    /// @param recipient Address to receive 10,000 ZKM.
    function claim(
        bytes calldata proof,
        bytes32 nullifier,
        address recipient
    ) external {
        // Validate proof length
        require(proof.length >= MIN_PROOF_LENGTH && proof.length <= MAX_PROOF_LENGTH, "Invalid proof length");

        // Check claim window
        require(block.timestamp < CLAIM_DEADLINE, "Claim period ended");
        require(totalClaims < MAX_CLAIMS, "Claim cap reached");
        require(!usedNullifiers[nullifier], "Already claimed");
        require(recipient != address(0), "Recipient cannot be zero");

        // Construct public inputs: [merkleRoot, nullifier, recipient]
        uint256[3] memory publicInputs = [
            uint256(merkleRoot),
            uint256(nullifier),
            uint256(uint160(recipient))
        ];

        // Verify Halo2 proof
        require(verifier.verify(proof, publicInputs), "Invalid proof");

        // Mark claimed and mint
        usedNullifiers[nullifier] = true;
        totalClaims++;
        token.mint(recipient, CLAIM_AMOUNT);

        emit Claimed(nullifier, CLAIM_AMOUNT, recipient, totalClaims);
    }

    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function claimsRemaining() external view returns (uint256) {
        return totalClaims >= MAX_CLAIMS ? 0 : MAX_CLAIMS - totalClaims;
    }

    function isClaimWindowOpen() external view returns (bool) {
        return block.timestamp < CLAIM_DEADLINE && totalClaims < MAX_CLAIMS;
    }
}
```

### 7.3 Key Design Properties

| Aspect | Implementation |
|--------|----------------|
| Verifier | `Halo2Verifier` contract (auto-generated from VK) |
| Claim parameters | `proof + nullifier + recipient` |
| Public input binding | Public inputs are direct calldata — no journal parsing |
| Verification key | Baked into verifier contract at deploy time |
| Proof validation | 2-step: `require(verifier.verify(...))` + claim checks |
| Proof length | Validated on-chain (`MIN_PROOF_LENGTH` to `MAX_PROOF_LENGTH`) |

### 7.4 Halo2Verifier.sol

Auto-generated from the verification key using `halo2-solidity-verifier` tool. The verifier contract:
- Is ~2000-3000 lines of Solidity (auto-generated, not hand-written)
- Contains the verification key as immutable constants
- Exposes `verify(bytes calldata proof, uint256[N] memory publicInputs) returns (bool)`
- Uses the `ecPairing()` BN254 precompile (address `0x08`) for pairing checks
- Is immutable after deployment (no proxy, no upgrade)

### 7.5 ZKMTokenV2.sol

ERC-20 token with immutable minter:

```solidity
contract ZKMTokenV2 is ERC20 {
    uint256 public constant MAX_SUPPLY = 10_000_000_000e18;
    address public immutable minter;

    constructor(address _minter) ERC20("ZKMist", "ZKM") {
        minter = _minter;
    }

    function mint(address to, uint256 amount) external { /* only minter */ }
    function burn(uint256 amount) external { /* holder burns */ }
    function burnFrom(address account, uint256 amount) external { /* approved burns */ }
}
```

Token name: "ZKMist", symbol: "ZKM". This is the sole ZKM token contract.

### 7.6 Deployment

Deployed via CREATE nonce prediction:

```
Transaction 1: Deploy Halo2Verifier (auto-generated Solidity)
Transaction 2: Deploy ZKMTokenV2 (minter = predicted airdrop address)
Transaction 3: Deploy ZKMAirdropV2 (token, verifier, merkleRoot)
```

All 3 contracts are deployed in one transaction via CREATE nonce prediction, or in 3 separate transactions.

**Constructor parameters:**
- `merkleRoot`: `0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844`
- `CLAIM_DEADLINE`: `1798761600` (2027-01-01 00:00:00 UTC)
- `CLAIM_AMOUNT`: `10_000e18`
- `MAX_CLAIMS`: `1_000_000`

---

## 8. CLI & Prover Tool

### 8.1 Commands

The CLI provides the following commands:

| Command | Description |
|---------|-------------|
| `zkmist fetch` | Download eligibility list |
| `zkmist check <address>` | Check eligibility |
| `zkmist prove` | Generate Halo2 ZK proof (~10-30 sec) |
| `zkmist submit <proof.json>` | Submit proof on-chain |
| `zkmist verify <proof.json>` | Verify proof locally |
| `zkmist status` | Show claim window status |

### 8.2 Prove Command Flow

1. Load private key and derive address
2. Build/load cached Merkle proof (~2 min first time, instant after)
3. Create Halo2 circuit instance with private inputs
4. Generate KZG proof (~10-30 seconds)
5. Save proof.json

**No special toolchain needed** — standard Rust only.

### 8.3 Proof File Format

```json
{
    "version": 2,
    "proofFormatVersion": "halo2-kzg-v1",
    "proof": "0x...halo2_proof_hex",
    "publicInputs": {
        "merkleRoot": "0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844",
        "nullifier": "0x...nullifier_hex",
        "recipient": "0x...recipient_hex"
    },
    "claimAmount": "10000000000000000000000",
    "contractAddress": "0x...airdropV2_address",
    "chainId": 8453
}
```

Note: `nullifier` and `recipient` are embedded in `publicInputs` only. The proof natively binds to these values.

### 8.4 Submit Command

`claim()` ABI:
```solidity
function claim(bytes calldata proof, bytes32 nullifier, address recipient)
```

The proof natively binds to the public inputs (merkleRoot, nullifier, recipient).

### 8.5 Prerequisites (User-Facing)

- Rust (stable) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- ~3 GB disk (eligibility list)
- ~2 GB RAM (Merkle tree build, cached after first run)

---

## 9. Prior Approach & Why It Changed

An earlier prototype used RISC Zero (a general-purpose zkVM) for proving. That approach has been **fully abandoned** in favor of Halo2-KZG custom circuits. Here's why:

| Factor | RISC Zero (abandoned) | Halo2-KZG (chosen) |
|--------|----------------------|-------------------|
| **Proving time** | ~50 min (CPU) / ~3-5 min (GPU) | ~10-30 sec (any CPU) |
| **Toolchain** | RISC Zero (`rzup`, `cargo-risczero`, ~2 GB) | Standard Rust (`cargo`, ~50 MB) |
| **Architecture** | Rust → RISC-V ELF → zkVM → STARK → Groth16 | Direct Rust circuits → KZG proof |
| **RAM to prove** | ~4 GB | ~1-2 GB |
| **On-chain gas** | ~510K | ~350-400K |
| **Trusted setup** | None (STARK) | Universal KZG (140K+ participants) |
| **Dependencies** | `risc0-zkvm`, `risc0-circuit-*`, `bonsai-sdk` | `halo2_proofs`, `halo2curves`, `snark-verifier` |

The core problem: the RISC Zero zkVM emulates a full RISC-V CPU, making every operation ~10,000x slower than a direct circuit. For a fixed-computation circuit (key → address → Merkle proof → nullifier), a custom Halo2 circuit is the right tool for the job.

---

## 10. What Is Reused

The following components from the existing codebase and data pipeline are reused directly:

| Component | Notes |
|-----------|-------|
| **Eligibility list** | 64,116,228 addresses, same CSV files |
| **Merkle tree parameters** | 26 levels, Poseidon, BN254, same R_F/R_P |
| **Merkle root** | `0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844` |
| **Tree library** | `zkmist-merkle-tree` crate (unchanged) |
| **Poseidon parameters** | Same round constants, MDS matrix, S-box |
| **Poseidon crate** | `light-poseidon` v0.4 with `ark-bn254` |
| **Nullifier scheme** | `poseidon(Fr(key), Fr(domain))` |
| **Leaf encoding** | Left-padded to 32 bytes, `Fr::from_be_bytes_mod_order` |
| **Padding sentinel** | `0xFF..FF` (exceeds field modulus) |
| **Privacy model** | Qualified address never on-chain |
| **Token economics** | 10,000 ZKM/claim, 1M cap, 2027-01-01 deadline |
| **Claim deadline** | `1798761600` (2027-01-01 00:00:00 UTC) |
| **Contract philosophy** | Immutable, no admin, no owner, no pause |
| **Burnable** | `burn()` / `burnFrom()` |
| **Permissionless relayers** | Anyone can submit proofs |
| **Data pipeline** | `fetch`, `check` commands (unchanged) |
| **Test vectors** | Same key→address, leaf hash, nullifier |
| **Eligibility SQL** | Same BigQuery query |

---

## 11. Project Structure

```
zkmist/
├── circuits/                      # NEW — Halo2 circuit definitions
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                 # Top-level ZKMistV2Claim circuit
│       ├── secp256k1.rs           # EC scalar multiplication gadget
│       ├── keccak.rs              # Keccak-256 hash gadget
│       ├── poseidon.rs            # Poseidon hash gadget (BN254)
│       ├── merkle.rs              # Merkle proof verification gadget
│       ├── nullifier.rs           # Nullifier computation gadget
│       └── gadgets/               # Shared low-level gadgets
│           ├── mod.rs
│           ├── range_check.rs     # Lookup-based range checks
│           ├── cond_swap.rs       # Conditional value swap
│           └── field_arith.rs     # Non-native field arithmetic helpers
│
├── merkle-tree/                   # Merkle tree library (reused)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
│
├── cli/                           # Halo2 proving backend
│   ├── Cargo.toml                 # Updated dependencies
│   └── src/
│       ├── main.rs                # CLI entry
│       ├── commands.rs            # prove/submit/verify commands
│       ├── constants.rs           # Contract addresses, nullifier domain
│       ├── helpers.rs             # Utility functions
│       ├── download.rs            # Eligibility data download
│       ├── types.rs               # Proof file format
│       ├── abi.rs                 # Claim ABI
│       └── halo2_prover.rs        # Halo2 proving integration
│
├── contracts/                     # V2 contracts
│   ├── src/
│   │   ├── ZKMTokenV2.sol         # ERC-20 token
│   │   ├── ZKMAirdropV2.sol       # New claim logic (Halo2 verifier)
│   │   └── Halo2Verifier.sol      # Auto-generated
│   ├── test/
│   │   ├── ZKMAirdropV2.t.sol     # V2 airdrop tests
│   │   └── ZKME2EV2.t.sol         # V2 end-to-end tests
│   └── script/
│       └── DeployV2.s.sol         # V2 deployment script
│
├── tools/                         # Codegen tools
│   └── src/
│       ├── compute_root.rs         # Merkle root computation
│       └── gen_verifier.rs         # Generate Halo2Verifier.sol from VK
│           # Workflow: load VK → snark-verifier CLI → Solidity output
│           # Command: cargo run --bin gen-verifier -- --vk <vk> --output Halo2Verifier.sol
│           # Verify: forge test (Rust proof must pass Solidity verifier)
│
├── tests/                         # Circuit integration tests
│   └── e2e_circuit.rs             # End-to-end: circuit + prove + verify
│
├── Cargo.toml                     # Updated workspace
├── PRD.md                         # Product requirements
├── README.md                      # Project documentation
├── CLAIMING_GUIDE.md              # User claiming guide
├── V2_PLAN.md                     # This document
└── CONTRIBUTING.md                # Contribution guidelines
```

---

## 12. Dependencies

### 12.1 New Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `halo2_proofs` | 0.3.0 | Halo2 proof system (PSE fork, KZG backend) |
| `halo2curves` | 0.6.0 | BN254 curve primitives for Halo2 |
| `ff` | 0.13 | Field trait (halo2curves backend) |
| `group` | 0.13 | Group trait (halo2curves backend) |
| `snark-verifier` | 0.1.0 | Solidity proof encoding for on-chain verification |
| `halo2-solidity-verifier` | (tool) | Auto-generates `Halo2Verifier.sol` from verification key |

### 12.2 Reused Dependencies

| Crate | Purpose | Change |
|-------|---------|--------|
| `ark-bn254` | BN254 field arithmetic | None |
| `ark-ff` | Field trait implementations | None |
| `light-poseidon` | Poseidon hash (host-side, tree building) | None |
| `zkmist-merkle-tree` | Merkle tree library | None |
| `clap` | CLI framework | None |
| `alloy` | Ethereum interaction | None |
| `tokio` | Async runtime | None |
| `serde` / `serde_json` | Serialization | None |
| `k256` | secp256k1 (host-side key derivation) | None |
| `tiny-keccak` | Keccak-256 (host-side) | None |

### 12.3 Not Applicable (Prior Approach)

These crates were used in the abandoned RISC Zero prototype and are not part of ZKMist V2:

| Crate | Reason |
|-------|--------|
| `risc0-zkvm` | Not using RISC Zero |
| `risc0-circuit-*` | Not using RISC Zero |
| `bonsai-sdk` | Not using Bonsai |
| `risc0-groth16` | No Groth16 wrapping needed |

### 12.4 circuits/Cargo.toml (new)

```toml
[package]
name = "zkmist-circuits"
version = "0.1.0"
edition = "2021"

[dependencies]
halo2_proofs = "0.3.0"
halo2curves = "0.6.0"
ff = "0.13"
group = "0.13"
ark-bn254 = "0.5"
ark-ff = "0.5"
num-bigint = "0.4"
num-traits = "0.2"
sha3 = "0.10"
hex = "0.4"

[dev-dependencies]
rand = "0.8"
```

### 12.5 cli/Cargo.toml (updated)

```toml
[package]
name = "zkmist-cli"
version = "2.0.0"
edition = "2021"

[[bin]]
name = "zkmist"
path = "src/main.rs"

[dependencies]
clap = { version = "4", features = ["derive"] }
alloy = { version = "1", features = ["providers", "signer-local", "contract", "transport-http"] }
zkmist-circuits = { path = "../circuits" }
zkmist-merkle-tree = { path = "../merkle-tree" }
halo2_proofs = "0.3.0"
halo2curves = "0.6.0"
ark-bn254 = "0.5"
light-poseidon = "0.4"
k256 = { version = "0.13", features = ["ecdsa", "arithmetic"] }
tiny-keccak = { version = "2.0", features = ["keccak"] }
rpassword = "7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
sha2 = "0.10"
indicatif = "0.17"
dirs = "5"

# REMOVED: risc0-zkvm, bonsai-sdk

[dev-dependencies]
tempfile = "3"
```

---

## 13. Test Vectors

Test vectors verify that the circuit produces identical results to native computation.

### 13.1 Core Test Vectors

| Component | Input | Expected Output |
|-----------|-------|-----------------|
| Address derivation | Private key `0x0123...cdef` | `0xfcad0b19bb29d4674531d6f115237e16afce377c` |
| Leaf hash | Address above | `0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9` |
| Nullifier | Key `0x0123...cdef` + `"ZKMist_V2_NULLIFIER"` | To be computed during implementation |
| Interior hash | `poseidon(Fr(1), Fr(2))` | `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` |

### 13.2 Merkle Root Verification

The circuit computes the same Poseidon hashes over the same Merkle tree, so the root must be `0x1eafd6f3b8f30af949ff5493e9102853a7c22f8cffdcf018daa31d4245797844`. Any discrepancy indicates a circuit bug.

### 13.3 Circuit Test Strategy

| Test Type | Description | Count |
|-----------|-------------|-------|
| **Unit tests** | Each gadget tested independently with known inputs/outputs | ~20 |
| **Integration test** | Full circuit: valid proof generation and verification | ~5 |
| **Negative tests** | Wrong key, wrong root, wrong nullifier, zero recipient | ~10 |
| **Property tests** | Random keys, verify circuit output == native computation | ~5 |
| **Gas benchmark** | Forge gas snapshot for claim transaction | 1 |
| **E2E on testnet** | Full claim flow on Base Sepolia | 1 |

---

## 14. Development Timeline

### Phase 1: Foundation (Weeks 1-2)

**Goal:** Circuit scaffolding, Poseidon and Merkle gadgets working.

| Task | Description | Est. |
|------|-------------|------|
| T1.1 | Create `circuits/` crate with Halo2 project structure | 0.5 day |
| T1.2 | Implement Poseidon gadget (t=2 and t=3) with existing parameters | 3 days |
| T1.3 | Verify Poseidon gadget output matches `light-poseidon` for test vectors | 1 day |
| T1.4 | Implement conditional swap gadget | 0.5 day |
| T1.5 | Implement Merkle proof gadget (26 levels) | 2 days |
| T1.6 | Test Merkle gadget with tree data | 1 day |
| T1.7 | Implement nullifier gadget (V2 domain) | 1 day |
| T1.8 | Integration test: Poseidon + Merkle + nullifier produce correct root/nullifier | 1 day |
| T1.9 | **Spike:** Research and prototype secp256k1 gadget (parallel with T1.2-T1.8) | 2 days |

**Deliverable:** Poseidon, Merkle, and nullifier gadgets passing all test vectors.

### Phase 2: Hard Part (Weeks 3-5)

**Goal:** secp256k1 and Keccak gadgets, full circuit wired.

> **Note:** Phase 2 can start earlier if T1.9 spike completes successfully. The secp256k1 gadget is the critical path and likely harder than estimated — allow buffer.

| Task | Description | Est. |
|------|-------------|------|
| T2.1 | Finalize secp256k1 gadget approach based on T1.9 spike results | 1 day |
| T2.2 | Implement/adapt secp256k1 scalar multiplication gadget | 7 days |
| T2.3 | Implement Keccak-256 gadget | 3 days |
| T2.4 | Implement non-native field arithmetic helpers (secp256k1 over BN254) | 3 days |
| T2.5 | Wire key → pubkey → address derivation in circuit | 2 days |
| T2.6 | Verify address derivation matches test vectors | 1 day |
| T2.7 | Wire all gadgets into top-level `ZKMistV2Claim` circuit | 2 days |
| T2.8 | Generate proving key and verification key | 0.5 day |
| T2.9 | Full circuit test: generate proof, verify locally | 2 days |
| T2.10 | Property tests: random keys, circuit output == native | 2 days |
| T2.11 | **Benchmark:** Measure proving time and peak memory on 4-core/8GB machine | 1 day |

**Deliverable:** Complete circuit generating valid Halo2-KZG proofs.

### Phase 3: Contracts (Week 6)

**Goal:** V2 smart contracts deployed on testnet.

| Task | Description | Est. |
|------|-------------|------|
| T3.1 | Auto-generate `Halo2Verifier.sol` from verification key | 1 day |
| T3.2 | Write `ZKMTokenV2.sol` | 0.5 day |
| T3.3 | Write `ZKMAirdropV2.sol` | 1 day |
| T3.4 | Foundry unit tests (claim, double-claim, cap, deadline, zero recipient) | 2 days |
| T3.5 | Gas benchmark with `forge snapshot` | 0.5 day |
| T3.6 | Deploy to Base Sepolia testnet | 0.5 day |

**Deliverable:** Contracts deployed on Base Sepolia, passing all tests.

### Phase 4: CLI Integration (Weeks 7-8)

**Goal:** CLI generates V2 proofs and submits to testnet.

| Task | Description | Est. |
|------|-------------|------|
| T4.1 | Implement `halo2_prover.rs` module in CLI | 2 days |
| T4.2 | Update `cmd_prove` to use Halo2 backend | 2 days |
| T4.3 | Update `cmd_submit` for V2 ABI (no journal) | 1 day |
| T4.4 | Update `cmd_verify` for Halo2 proof verification | 1 day |
| T4.5 | Update proof file format (v2) | 1 day |
| T4.6 | Update constants (contract addresses, nullifier domain) | 0.5 day |
| T4.7 | End-to-end test: prove + submit on Base Sepolia | 1 day |
| T4.8 | Error handling and edge cases | 2 days |

**Deliverable:** Full CLI working with V2 contracts on testnet.

### Phase 5: Testing & Hardening (Weeks 9-10)

**Goal:** Production-ready.

| Task | Description | Est. |
|------|-------------|------|
| T5.1 | Comprehensive negative testing (invalid proofs, wrong keys, etc.) | 2 days |
| T5.2 | Fuzz testing on circuit inputs | 2 days |
| T5.3 | Gas optimization on verifier contract | 1 day |
| T5.4 | Security review of critical constraints | 2 days |
| T5.5 | Cross-verify Merkle roots against tree builder | 1 day |
| T5.6 | Update documentation (README, CLAIMING_GUIDE, PRD) | 2 days |
| T5.7 | Community testnet testing period | 3 days |

**Deliverable:** Production-ready codebase with passing test suite.

### Phase 6: Deployment (Weeks 11-12)

**Goal:** Mainnet deployment.

| Task | Description | Est. |
|------|-------------|------|
| T6.1 | Final audit of verifier contract | 2 days |
| T6.2 | Dry-run deployment on Base Sepolia | 1 day |
| T6.3 | Deploy to Base mainnet | 0.5 day |
| T6.4 | Verify contracts on BaseScan | 0.5 day |
| T6.5 | Publish release, update GitHub, announce | 1 day |
| T6.6 | Monitor first claims | Ongoing |

**Deliverable:** V2 live on Base mainnet.

### Timeline Summary

| Phase | Weeks | Description |
|-------|-------|-------------|
| Phase 1 | 1-2 | Circuit scaffolding (Poseidon, Merkle, nullifier) |
| Phase 2 | 3-5 | secp256k1 + Keccak (the hard part) |
| Phase 3 | 6 | Smart contracts |
| Phase 4 | 7-8 | CLI integration |
| Phase 5 | 9-10 | Testing and hardening |
| Phase 6 | 11-12 | Deployment |
| **Total** | **~12 weeks** | |

With an experienced Halo2 developer, phases 2-3 could be compressed to ~3 weeks. If learning Halo2 during development, add 4-6 weeks.

---

## 15. Deployment Plan

### 15.1 Testnet Deployment (Base Sepolia)

1. Deploy `Halo2Verifier` to Base Sepolia
2. Deploy `ZKMTokenV2` (minter = predicted airdrop address)
3. Deploy `ZKMAirdropV2` (token, verifier, merkleRoot)
4. Generate test proof using CLI
5. Submit test claim on Sepolia
6. Verify claim succeeded, tokens minted, nullifier marked
7. Attempt double-claim (should fail)
8. Attempt zero-recipient claim (should fail)
9. Community testing period (minimum 7 days)

### 15.2 Mainnet Deployment (Base)

1. Verify all testnet tests pass
2. Verify gas costs match expectations
3. Deploy all 3 contracts in a single transaction (CREATE nonce prediction)
4. Verify contract bytecode on BaseScan
5. Publish contract addresses
6. Tag GitHub release (`v2.0.0`)
7. Update README, CLAIMING_GUIDE with new addresses
8. Announce to community

### 15.3 Contract Addresses (TBD)

| Contract | Testnet (Base Sepolia) | Mainnet (Base) |
|----------|----------------------|----------------|
| `Halo2Verifier` | TBD | TBD |
| `ZKMTokenV2` | TBD | TBD |
| `ZKMAirdropV2` | TBD | TBD |

---

## 16. Security Considerations

### 16.1 Threat Model

| Threat | Vector | Mitigation |
|--------|--------|------------|
| **Circuit bug (secp256k1)** | Wrong EC arithmetic produces wrong address | Cross-verify against test vectors; property-based testing with random keys |
| **Circuit bug (Merkle)** | Wrong Poseidon parameters produce wrong root | Reuse exact parameters; verify root matches `0x1eaf...7844` |
| **Verifier contract bug** | Solidity verifier doesn't match Rust VK | Auto-generated from VK; test on testnet with real proofs |
| **SRS compromise** | KZG ceremony toxic waste leaked | 140K+ participants; would also compromise Ethereum blob verification |
| **Nullifier collision** | Two different keys produce same nullifier | Poseidon hash collision resistance (~2¹²⁸ security level) |
| **Proof malleability** | Attacker modifies proof without detection | KZG binding property; public inputs are part of proof verification |
| **Front-running** | Attacker submits proof before original claimant | Recipient is bound in proof; attacker cannot change it |
| **Nullifier collision** | Two different keys produce same nullifier | Poseidon hash collision resistance (~2¹²⁸ security level) |

### 16.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| No admin keys | Contracts are fully immutable |
| No double-claim | Nullifier stored in on-chain mapping |
| Front-running protected | Recipient committed in ZK proof |
| Privacy | Qualified address never on-chain; nullifier is one-way hash |
| Supply cap | 10B ZKM max mint enforced on-chain |
| Burnable | Holders can burn via `burn()` / `burnFrom()` |

### 16.3 Formal Verification Targets

The following circuit constraints should be formally verified or exhaustively tested:

1. **secp256k1 gadget**: For a random key `k`, the circuit's computed address matches `keccak256(secp256k1(k).pubkey[1:])[12:]` computed natively.
2. **Poseidon gadget**: Circuit output matches `light-poseidon` for all test vectors.
3. **Merkle gadget**: Circuit-computed root matches `build_tree_streaming` output.
4. **Nullifier gadget**: Circuit nullifier matches `compute_nullifier` with V2 domain.
5. **Non-native field arithmetic**: secp256k1 operations over BN254 field are correct for boundary values.

---

## 17. Risks & Mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|------------|--------|------------|
| R1 | secp256k1 gadget too slow or too large | Medium | High | Use proven Scroll/Summa implementations; start spike in Phase 1 to detect issues early |
| R2 | Proving time > 60 seconds | Low | Medium | Profile and optimize; reduce redundant constraints; benchmark early (T2.11) |
| R3 | Verifier gas > 500K | Low | Medium | Optimize verification key layout; use Halo2-KZG→Groth16 wrap if needed |
| R4 | Circuit correctness bug | Medium | Critical | Exhaustive testing, property-based tests, cross-verification against native computation |
| R5 | SRS size insufficient | Very Low | High | Ethereum KZG SRS provides 2¹² points; our circuit needs far fewer |
| R6 | Halo2 version incompatibility | Low | Medium | Pin exact crate versions (0.3.0, 0.1.0); test against pinned versions |
| R7 | Schedule overrun | Medium | Low | Phases 1 and 3-4 are low-risk; Phase 2 is the critical path |

### R1 Mitigation: secp256k1 Gadget Alternatives

If a full secp256k1 scalar multiplication gadget proves impractical, alternatives include:

1. **ECDSA verify gadget**: Instead of computing `P = k*G`, verify a signature `(r, s)` against the public key derived from the address. This shifts some complexity but still requires non-native field arithmetic.

2. **Precompiled table approach**: Precompute scalar multiplication tables at circuit setup time, reducing the online proving cost.

3. **Circuit layout optimization**: Use Halo2 lookup tables aggressively for bit decomposition and range checks in the scalar multiplication.

**⚠️ What NOT to do:** Do NOT accept the address as an unconstrained private input. Without in-circuit verification of key→address derivation, the nullifier (derived from key) would be unbound from the leaf (derived from address), allowing a malicious prover to claim against any eligible address with an arbitrary key. The key↔address binding is essential for the one-claim-per-person guarantee.

---

## 18. Gas & Cost Analysis

### 18.1 Gas Breakdown

| Component | Gas |
|-----------|-----|
| Proof verification (KZG pairing + transcript) | ~300K |
| Airdrop logic (SSTORE, _mint, event) | ~100K |
| **Total** | **~400K** |

### 18.2 Cost per Claim

| Network | Cost |
|---------|------|
| Base (0.1 Gwei, $3K ETH) | ~$0.12 |

### 18.3 At Scale (1M Claims)

| Metric | Value |
|--------|-------|
| Total gas | ~400B gas |
| Total cost | ~$117,000 |

### 18.4 Proving Cost

| Metric | Value |
|--------|-------|
| Hardware | Any modern CPU |
| Electricity | ~$0.001 (30 sec CPU) |
| **Total per proof** | **~$0.001** |

---

## 19. Appendix A: Prior Approach Comparison

| Aspect | RISC Zero (abandoned) | Halo2-KZG (chosen) |
|--------|----------------------|-------------------|
| Proof system | STARK → Groth16 wrap | Direct KZG |
| Trusted setup | None | Universal (140K+ participants) |
| Proving time | 50 min (CPU) / 3-5 min (GPU) | 10-30 sec (any CPU) |
| Proof size | ~400 bytes | ~500-800 bytes |
| On-chain gas | ~510K | ~350-400K |
| Toolchain | RISC Zero (`rzup`, `cargo-risczero`, ~2 GB) | Standard Rust (`cargo`, ~50 MB) |
| RAM to prove | ~4 GB | ~1-2 GB |
| Guest program | Rust → RISC-V ELF | Native Rust circuits |
| Journal | 84 bytes (root + nullifier + recipient) | None (public inputs are direct) |
| Verifier contract | RiscZeroGroth16Verifier (3rd party) | Halo2Verifier (auto-generated) |
| Claim ABI | `claim(proof, journal, nullifier, recipient)` | `claim(proof, nullifier, recipient)` |
| Nullifier domain | `"ZKMist_V1_NULLIFIER"` | `"ZKMist_V2_NULLIFIER"` |
| Dependencies | risc0-zkvm, risc0-circuit-*, bonsai-sdk | halo2_proofs, halo2curves |

---

## 20. Appendix B: Halo2-KZG Primer

### What is Halo2?

Halo2 is a zero-knowledge proof system developed by ZCash/Electric Coin Company. It uses:
- **PLONKish arithmetization**: Circuits are expressed as tables with advice (private), instance (public), fixed, and selector columns.
- **KZG polynomial commitments**: Proves that a polynomial evaluates to a specific value at a specific point.
- **Lookup arguments**: Efficiently proves that a value appears in a predefined table.

### What is KZG?

KZG (Kate-Zaverucha-Goldberg) is a polynomial commitment scheme:
1. **Setup**: Generate structured reference string (SRS) from Powers of Tau ceremony
2. **Commit**: `C = f(s) * G` (elliptic curve point)
3. **Prove**: Prove `f(z) = y` using the SRS
4. **Verify**: Check pairing equation `e(C - y*G, z*H) == e(π, H - s*H2)`

The verification is a single pairing check — constant time regardless of circuit size.

### Key Halo2 Concepts

| Concept | Description |
|---------|-------------|
| **Region** | A rectangular area of the trace table assigned to a gadget |
| **Advice column** | Columns holding private witness values |
| **Instance column** | Columns holding public inputs |
| **Fixed column** | Columns holding precomputed constants |
| **Selector column** | Boolean columns enabling/disabling gates |
| **Gate** | A polynomial constraint enforced on active rows |
| **Lookup table** | Precomputed table of valid values (e.g., 8-bit range check) |
| **Circuit** | The full set of gates, lookups, and column assignments |

---

## 21. Appendix C: Ethereum KZG Ceremony

### Overview

The Ethereum KZG Ceremony was conducted as part of EIP-4844 (Proto-Danksharding, March 2023). It is the largest multi-party computation ceremony in history.

### Statistics

| Metric | Value |
|--------|-------|
| Participants | ~140,000+ |
| Contribution method | Browser, CLI, GitHub Actions |
| Final SRS size | 2¹² G1 points + 256 G2 points |
| Ceremony duration | ~6 months |
| Security assumption | At least 1 participant honestly destroyed their secret |
| SRS custodian | Ethereum Foundation (public, auditable) |

### How ZKMist Uses It

ZKMist V2 loads the Ethereum KZG SRS from the `halo2curves` crate, which embeds the ceremony output as compile-time constants. No additional ceremony is needed.

### Security Analysis

| Attack scenario | Feasibility |
|----------------|-------------|
| All 140K participants colluded | ~0 — they are anonymous, distributed globally |
| Ceremony coordinator cheated | Not possible — contributions are independently verifiable |
| Future breakthrough breaks KZG | Would also break Ethereum blob verification — systemic, not ZKMist-specific |

---

## 22. Appendix D: Circuit Constraint Breakdown

### Estimated Constraint Count

| Gadget | Constraints | Advice Cells | Lookup Tables |
|--------|------------|-------------|---------------|
| secp256k1 scalar mul | ~50-100K | ~80K | 4-bit windows, carry rules |
| Keccak-256 | ~200-300K | ~250K | 8-bit S-box, round constants |
| Poseidon t=2 (×1) | ~300 | ~250 | None (algebraic) |
| Poseidon t=3 (×26) | ~7,200 | ~6,500 | None (algebraic) |
| Conditional swap (×26) | ~780 | ~500 | None |
| Non-zero check (×1) | ~10 | ~10 | None |
| Range checks & bool (×26) | ~1,000 | ~800 | 1-bit boolean |
| **Total (estimated)** | **~265-415K** | **~340K** | | |

### K (Circuit Size Parameter)

Halo2 uses `k` (the power of 2) to define the circuit's row capacity:

| k | Rows | Usable after blinding |
|---|------|-----------------------|
| 18 | 262,144 | ~260,000 |
| 19 | 524,288 | ~522,000 |
| 20 | 1,048,576 | ~1,046,000 |

With ~340K advice cells, **k=19** should be sufficient (524K rows available). If Keccak pushes beyond 300K, k=20 may be needed. This should be confirmed during the Phase 2 benchmarking task (T2.11).

### Performance Estimates

| Metric | k=18 | k=19 | k=20 |
|--------|------|------|------|
| Proving time | ~5-15s | ~10-30s | ~20-60s |
| Proof size | ~400 bytes | ~500-800 bytes | ~800-1200 bytes |
| Verify gas | ~250K | ~300K | ~400K |

Target: **k=19** (good balance of proving time and gas cost).

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-05-27 | Initial V2 plan |
| 1.2 | 2026-05-27 | Spike results: validated halo2_proofs 0.3.0 + halo2curves 0.6.0, corrected API differences, added circuits/ crate with passing tests |
| 1.3 | 2026-05-28 | Critical blocker fixes: Keccak iota cell conflict fixed, secp256k1 limb range checks + carry boolean constraints + on-curve check added, Halo2Verifier.sol improved with structural validation, CLI verification enhanced |
| 1.4 | 2026-05-29 | Implementation review: constrained field_sub via negation+add, on-curve + limb range checks wired into main circuit, Keccak MockProver test, E2E test hard-fail on verification errors, Halo2Verifier.sol production guard, compiler warnings fixed |
| 1.5 | 2026-05-29 | Deployment readiness: removed IS_PRODUCTION_VERIFIER guard from airdrop contract (cheap checks first), added gas benchmark tests (11 tests), added fuzz tests (8 tests), added E2E testnet tests (14 tests), rewrote gen-verifier with VK hash from pinned(), rewrote CLI halo2_prover with timing instrumentation and full local verification, fixed deploy script with safety checks, added 6 circuit property tests (nullifier 10K, leaf hash uniqueness/determinism, V1/V2 separation, address derivation consistency, merkle proof soundness), total 55 circuit + 124 contract tests passing |

---

## Appendix E: Halo2 API Spike Results (2026-05-27)

The `circuits/` crate contains a validated spike that exercises the full Halo2-KZG pipeline.
All 7 tests pass, including real KZG proof generation and verification on BN254.

### Validated Dependencies

| Crate | Version | Status |
|-------|---------|--------|
| `halo2_proofs` | 0.3.0 | ✅ Compiles and works |
| `halo2curves` | 0.6.0 | ✅ Compiles and works |
| `ark-bn254` | 0.5 | ✅ Interop with halo2curves confirmed |
| `ff` | 0.13 | Required for field trait |
| `group` | 0.13 | Required for group trait |

### API Differences from Tutorials

The PSE Halo2 v0.3.0 has several API differences from the tutorials and examples
found online (which often target the ZCash Halo2 or newer PSE versions):

| Feature | Expected | Actual |
|---------|----------|--------|
| `Circuit::Params` associated type | Present | **Not in trait** |
| `circuit-params` feature | Exists | **Does not exist** |
| `meta.lookup()` args | `(name, closure)` | `(closure)` only |
| `meta.lookup_table()` | `lookup_table(name)` | **`lookup_table_column()`** |
| `query_fixed()` args | `(col, rotation)` | **`(col)` only** — per-region |
| `region.instance_cell()` | Method | **Not available**; use `assign_advice_from_instance` |
| `TranscriptReadBuffer` | Type | Use **`Blake2bRead::init()`** |
| Curve type param | `Bn256` | **`G1Affine`** |
| `region.constrain_equal` with instance | `instance.cur()` | **`assign_advice_from_instance`** then constrain |

### Field Element Interoperability

`halo2curves::bn256::Fr` and `ark_bn254::Fr` are the **same field** (BN254 scalar field).
- `halo2curves` uses **little-endian** representation (`to_repr()`)
- `ark-bn254` uses **big-endian** representation (`into_bigint().to_bytes_be()`)
- Conversion: reverse bytes from one to the other
- **This is critical for Poseidon interop** — the V2 circuit will use halo2curves Fr
  internally but must match the existing merkle-tree crate's ark-bn254 Fr outputs.

### Proof Size

Trivial circuit (k=9, 512 rows): **1,600 bytes** proof.
Full ZKMist V2 circuit (k=19, ~500K rows) is estimated at **500-800 bytes**.

### Spike Test Results

```
test trivial::tests::test_api_surface_documentation ... ok
test trivial::tests::test_field_interop ... ok
test trivial::tests::test_trivial_mock_valid ... ok
test trivial::tests::test_trivial_mock_wrong_input ... ok
test trivial::tests::test_multiply_mock_valid ... ok
test trivial::tests::test_multiply_mock_wrong_result ... ok
test trivial::tests::test_real_kzg_proof_and_verify ... ok

test result: ok. 7 passed; 0 failed
```

### Risks Updated After Spike

| Risk | Before Spike | After Spike |
|------|-------------|-------------|
| halo2_proofs API compatibility | Unknown | ✅ Resolved — API mapped, tests pass |
| halo2curves/ark-bn254 interop | Unknown | ✅ Resolved — same field, different endianness |
| KZG proof generation works | Unknown | ✅ Resolved — 1.6KB proof in 2.5s |
| Dependency version conflicts | Unknown | ✅ Resolved — pinned 0.3.0/0.6.0 |
| secp256k1 gadget feasibility | High risk | ⚠️ Still high — needs dedicated implementation spike |
