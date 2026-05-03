# ZKMist (ZKM) — Product Requirements Document

**Version:** 4.0  
**Date:** 2026-05-03  
**Status:** Draft  
**Author:** ZKMist Team  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is an ERC-20 token deployed on **Base Chain** featuring a **privacy-preserving airdrop**. ~65 million Ethereum addresses that paid ≥0.004 ETH in cumulative transaction fees on mainnet before 2026 are eligible to claim ZKM tokens anonymously.

The claimant generates a **zero-knowledge proof** locally using the **RISC Zero zkVM** — a Rust guest program that proves membership in the eligibility Merkle tree without revealing which address is claiming. The proof is submitted directly to the immutable on-chain contract. Anyone can also build relayer services that submit proofs on behalf of claimants and cover gas costs.

**Key properties:**
- **Fully immutable contract** — deployed once, never modified, no admin, no pausability.
- **Permissionless** — anyone can submit a valid claim proof; anyone can build tools or relayers on top.
- **No trusted setup** — RISC Zero is STARK-based. No ceremony, no toxic waste.
- **No web dApp needed** — the contract is the interface. Anyone can build a UI on top.

### 1.2 Problem Statement

Standard airdrops create a permanent, public on-chain link between a user's qualifying address and their claiming address. This exposes portfolios, creates phishing targets, and discourages participation.

### 1.3 Solution

The claimant runs a local CLI tool with three inputs:

1. The **published eligibility list** (from IPFS)
2. The **private key** to their qualified Ethereum address
3. A **recipient address** of their choice

The CLI tool builds the Merkle tree locally, generates a ZK proof via RISC Zero, and outputs the proof data. The proof is then submitted to the immutable `ZKMAirdrop` contract on Base — either directly by the claimant or by any third-party relayer. On-chain, only an opaque nullifier and the recipient address are visible. The qualified address is never revealed.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Deploy ZKM as a standard ERC-20 on Base Chain | Successful deployment & verification |
| G2 | Enable anonymous claiming for all qualified addresses | Zero on-chain link between qualified and recipient address |
| G3 | Prevent double-claiming | Zero double-claims |
| G4 | Gas-efficient claim process | Claim tx cost < $0.50 USD on Base |
| G5 | Fully immutable contract | No admin functions, no upgradeability, no pausability |
| G6 | Auditable & verifiable | Published eligibility list, Merkle root on-chain, Rust guest program source public |
| G7 | Permissionless ecosystem | Anyone can build relayers, UIs, or tools on top of the contract |

### 2.2 Non-Goals

- ZKMist is **not** a governance token (at launch).
- No staking, farming, or DeFi mechanics at launch.
- No web dApp built by the ZKMist team — the contract is the interface.
- No dynamic/incremental eligibility list — the list is **fixed** at deployment.
- No admin recovery of unclaimed tokens — unclaimed tokens remain in the contract permanently.

---

## 3. User Personas

### 3.1 Claimant (Primary User)

- Holds a qualified Ethereum address.
- Runs the CLI tool locally to generate a ZK proof.
- Submits the proof to the contract directly, or via a relayer.
- Values privacy — qualified address must not be linked to recipient address.

### 3.2 Relayer Operator

- Builds a service (web app, bot, API) that accepts ZK proofs from claimants and submits them on-chain.
- Pays gas on behalf of claimants (may charge a fee or offer it free).
- Cannot tamper with claims (proof is bound to recipient).
- Operates permissionlessly — no relationship with the ZKMist team.

### 3.3 Observer / Auditor

- Verifies the airdrop was conducted fairly.
- Reconstructs the Merkle tree from the published eligibility list.
- Reads and audits the Rust guest program source code.
- Verifies on-chain that no double-claims occurred.

---

## 4. Token Economics

### 4.1 Token Specifications

| Property | Value |
|----------|-------|
| **Name** | ZKMist |
| **Symbol** | ZKM |
| **Decimals** | 18 |
| **Total Supply** | 1,000,000,000 ZKM (1B) |
| **Chain** | Base (Ethereum L2) |
| **Standard** | ERC-20 |
| **Mintable** | No |
| **Burnable** | No (at launch) |
| **Owner/Admin** | **None** (fully immutable after deployment) |

### 4.2 Token Allocation

| Allocation | % of Supply | Amount (ZKM) | Notes |
|------------|-------------|--------------|-------|
| Airdrop Claims | 50% | 500,000,000 | Sent to ZKMAirdrop contract at deployment |
| Treasury / DAO | 20% | 200,000,000 | Time-locked; future community allocation |
| Team & Advisors | 15% | 150,000,000 | Vested over 24 months |
| Liquidity Provision | 10% | 100,000,000 | Paired in DEX LP on Base |
| Reserve | 5% | 50,000,000 | Emergency / partnerships |

> The airdrop allocation (500M ZKM) is sent to the `ZKMAirdrop` contract at deployment. Any tokens not claimed remain in the contract permanently. There is no admin function to withdraw them.

### 4.3 Per-Address Claim Amount

- **Uniform allocation:** `CLAIM_AMOUNT = 500,000,000 / exactQualifiedCount`
- With ~65M qualified addresses: **~7.69 ZKM per address**
- All qualified addresses receive the **same amount** (strongest anonymity).
- `CLAIM_AMOUNT` is hardcoded in the airdrop contract at deployment.

---

## 5. Eligibility & Qualification

### 5.1 Eligibility Criteria

> **Any Ethereum mainnet address that has paid a cumulative total of at least 0.004 ETH in transaction fees before 2026-01-01 00:00:00 UTC is qualified.**

| Parameter | Value |
|-----------|-------|
| **Threshold** | ≥ 0.004 ETH cumulative gas fees paid |
| **Cutoff** | `block_timestamp < 2026-01-01 00:00:00 UTC` |
| **Scope** | Ethereum mainnet only (L1) |
| **Qualifying Action** | `from_address` on successful transactions (`receipt_status = 1`) |
| **Qualified Addresses** | **~65,000,000** (estimated from BigQuery) |

**Rationale:** 0.004 ETH (~$8–12 at average prices) filters out dust/spam addresses while capturing virtually all real users. Broad, inclusive, and Sybil-resistant — costly to fake at scale.

### 5.2 Data Source — Google BigQuery

The eligibility data is extracted from **Google BigQuery** (`bigquery-public-data.crypto_ethereum`).

#### BigQuery SQL

```sql
SELECT
  from_address AS qualified_address,
  SAFE_DIVIDE(SUM(gas_price * receipt_gas_used), 1e18) AS total_fees_eth
FROM
  `bigquery-public-data.crypto_ethereum.transactions`
WHERE
  block_timestamp < TIMESTAMP('2026-01-01 00:00:00 UTC')
  AND receipt_status = 1
GROUP BY
  from_address
HAVING
  total_fees_eth >= 0.004
ORDER BY
  total_fees_eth DESC;
```

#### Query Notes

- `receipt_status = 1` — only **successful** transactions (reverts excluded).
- `gas_price × receipt_gas_used` — actual gas fee paid. Accurate for both pre-EIP-1559 and EIP-1559 transactions (BigQuery's `gas_price` is the effective price paid).
- The query processes **~2.5 billion rows**. Expected BigQuery cost: ~$25–50 USD.

#### Export Pipeline

```
BigQuery SQL
    │
    ▼
Export to GCS (Google Cloud Storage)
    │   Format: CSV, partitioned into ~65 files (1M rows each)
    │   gs://zkmist-eligibility/addresses_part_*.csv
    ▼
Deduplicate & Normalize
    │   • Lowercase all addresses
    │   • Sort lexicographically for deterministic Merkle tree
    ▼
Final Eligibility List
        Format: CSV
        Published to: IPFS (CID pinned), GitHub release
```

### 5.3 Claim Amount — Uniform Allocation

```
claimAmount = 500,000,000 / ~65,000,000 ≈ 7.69 ZKM per address
```

| Parameter | Value |
|-----------|-------|
| **Total Airdrop Supply** | 500,000,000 ZKM |
| **Qualified Addresses** | ~65,000,000 |
| **ZKM per Address** | **~7.69 ZKM** (exact amount set at deployment) |
| **Merkle Leaf** | `poseidon(address)` |

> **Why uniform?** Tiered amounts would create a deanonymization vector (observer narrows candidates by tier). Uniform amounts ensure the claim amount reveals nothing.

### 5.4 Eligibility List Format

The list is published as chunked files on IPFS + GitHub mirror:

```
eligibility/
├── manifest.json              # Metadata: count, merkleRoot, hash algorithm
├── addresses_00000001.csv     # address (1M rows each, sorted lexicographically)
├── addresses_00000002.csv
├── ...
└── addresses_00000065.csv
```

**`manifest.json`**
```json
{
  "version": 1,
  "cutoffTimestamp": "2026-01-01T00:00:00Z",
  "feeThresholdEth": "0.004",
  "totalQualified": 65000000,
  "claimAmountWei": "7692307000000000000",
  "merkleRoot": "0x...",
  "merkleTreeDepth": 26,
  "hashAlgorithm": "poseidon",
  "files": [
    { "file": "addresses_00000001.csv", "sha256": "0x..." },
    { "file": "addresses_00000002.csv", "sha256": "0x..." }
  ]
}
```

---

## 6. Anonymous Claim Protocol

### 6.1 Design Principles

1. **Local-only proof generation** — the private key never leaves the claimant's machine.
2. **Immutable contract** — deployed once, no admin, no upgrades, no pause.
3. **Permissionless submission** — anyone can submit a valid proof. Anyone can build a relayer.
4. **No trusted setup** — STARK-based proving. No ceremony, no toxic waste.
5. **Auditable code** — the "circuit" is a Rust program anyone can read.

### 6.2 Why RISC Zero

| Factor | circom + Groth16 | RISC Zero zkVM |
|--------|------------------|----------------|
| **Address derivation** | ~400K constraints (secp256k1 + keccak256) | Native Rust: `k256` crate |
| **Trusted setup** | ❌ Required (ceremony, toxic waste) | ✅ **None** |
| **Code readability** | Constraint signals | Regular Rust code |
| **Front-running protection** | Must manually add constraints | Just hash recipient in code |
| **Audit surface** | Custom circom gadgets | Standard Rust crypto libraries |

### 6.3 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PUBLISHED DATA                         │
│                                                             │
│  Google BigQuery ──► Eligibility List (~65M addresses)      │
│                            │                                │
│                            ▼                                │
│                  Published to IPFS (chunked CSV)            │
│                  Merkle Root hardcoded in contract           │
│                                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  CLAIMANT'S LOCAL MACHINE                    │
│                                                             │
│  CLI Tool:                                                  │
│    ① Download eligibility list from IPFS (~1.3 GB)         │
│    ② Stream-build Merkle tree (O(log n) memory)            │
│    ③ Find address in tree → extract 26-level proof          │
│    ④ Enter private key (hidden prompt)                      │
│    ⑤ RISC Zero zkVM generates STARK proof                   │
│    ⑥ Output: proof + journal + nullifier + recipient        │
│                                                             │
│  Output can be:                                             │
│    • Submitted directly to the contract by the claimant     │
│    • Sent to a relayer who submits on the claimant's behalf │
│    • Saved to file for later submission                     │
│                                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
           ┌───────────────┴───────────────┐
           ▼                               ▼
  ┌─────────────────┐            ┌──────────────────┐
  │  Direct submit   │            │  Relayer          │
  │  (any wallet)    │            │  (anyone)         │
  └────────┬────────┘            └────────┬──────────┘
           │                              │
           └──────────────┬───────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     ON-CHAIN (Base)                          │
│                                                             │
│  ZKMAirdrop Contract (IMMUTABLE):                            │
│                                                             │
│    function claim(proof, journal, nullifier, recipient)      │
│      1. Verify RISC Zero STARK proof                        │
│      2. Validate journal (merkleRoot, nullifier, recipient) │
│      3. Check nullifier not used                            │
│      4. Transfer CLAIM_AMOUNT ZKM to recipient              │
│                                                             │
│    On-chain visibility:                                     │
│      ✗ qualified address — HIDDEN                           │
│      ✗ private key — HIDDEN                                 │
│      ✓ nullifier (opaque, not linkable to address)           │
│      ✓ recipient address                                    │
│      ✓ STARK proof + journal                                │
│                                                             │
│    No admin functions. No pause. No upgrade. No owner.       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.4 Nullifier Design

The nullifier prevents double-claiming without revealing the qualified address.

```
nullifier = sha256(privateKey || "ZKMist_V1_NULLIFIER")
```

| Property | Explanation |
|----------|-------------|
| **Deterministic** | Same private key → same nullifier → double-claim impossible |
| **Not precomputable** | Cannot compute from the published address list — requires the private key |
| **Not reversible** | Cannot recover the private key or address from the nullifier |
| **Unique per address** | Different private keys → different nullifiers (collision-resistant) |

### 6.5 Guest Program (Rust)

The RISC Zero guest program is the zkVM equivalent of a ZK circuit. It is a regular Rust program that proves:

1. "I know a private key whose Ethereum address is in the eligibility Merkle tree."
2. "The nullifier is correctly derived from my private key."
3. "The recipient address is committed to the proof."

```rust
//! ZKMist Airdrop Claim — RISC Zero Guest Program

#![no_main]
risc0_zkvm::guest::entry!(main);

use sha2::{Digest, Sha256};

const TREE_DEPTH: usize = 26;
const DOMAIN_SEPARATOR: &[u8] = b"ZKMist_V1_NULLIFIER";

pub fn main() {
    // === Public inputs (committed to journal, visible on-chain) ===
    let merkle_root: [u8; 32] = env::read();
    let nullifier: [u8; 32] = env::read();
    let recipient: [u8; 20] = env::read();

    // === Private inputs (never leave the claimant's machine) ===
    let private_key: [u8; 32] = env::read();

    // --- Derive Ethereum address from private key ---
    let address = derive_address(&private_key);

    // --- Merkle membership proof ---
    let mut siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices: [bool; TREE_DEPTH] = [false; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        siblings[i] = env::read();
        path_indices[i] = env::read();
    }

    // --- Verify Merkle membership ---
    let leaf = poseidon_hash_address(&address);
    let computed_root = compute_merkle_root(&leaf, &siblings, &path_indices);
    assert_eq!(computed_root, merkle_root, "Not in eligibility tree");

    // --- Verify nullifier ---
    let expected_nullifier = compute_nullifier(&private_key);
    assert_eq!(nullifier, expected_nullifier, "Invalid nullifier");

    // === Commit public outputs to journal ===
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

fn derive_address(key: &[u8; 32]) -> [u8; 20] {
    let signing_key = k256::ecdsa::SigningKey::from_bytes(key)
        .expect("Invalid private key");
    let verifying_key = k256::ecdsa::VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let pub_key_bytes = encoded.as_bytes(); // 65 bytes: 0x04 || x || y
    // Use keccak256 for Ethereum address derivation
    let hash = keccak256(&pub_key_bytes[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn compute_nullifier(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(DOMAIN_SEPARATOR);
    hasher.finalize().into()
}

fn compute_merkle_root(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    indices: &[bool; TREE_DEPTH],
) -> [u8; 32] {
    let mut current = *leaf;
    for i in 0..TREE_DEPTH {
        let mut hasher = Sha256::new();
        if indices[i] {
            hasher.update(&siblings[i]);
            hasher.update(&current);
        } else {
            hasher.update(&current);
            hasher.update(&siblings[i]);
        }
        current = hasher.finalize().into();
    }
    current
}
```

> **Front-running is impossible.** The `recipient` is committed to the journal. The journal hash is part of the STARK proof. Changing the recipient in calldata invalidates the proof.

### 6.6 Claim Flow (Step-by-Step)

1. **Download eligibility list** — `zkmist fetch` downloads the published list from IPFS (~1.3 GB, chunked CSV). Cached locally after first download.

2. **Generate proof** — `zkmist prove` does the following:
   - Prompts for private key (hidden input, never in shell history)
   - Prompts for recipient address
   - Stream-builds the Merkle tree (~1–2 minutes)
   - Finds the address in the tree, extracts 26-level Merkle proof
   - Runs RISC Zero zkVM (~30–90 seconds)
   - Outputs proof data to a file

3. **Submit claim** — One of:
   - **Direct:** `zkmist submit proof.json` — submits via any connected wallet. The claimant pays gas on Base (~$0.01–0.07).
   - **Via relayer:** Send the proof file to any relayer service. The relayer submits on-chain and pays gas. The relayer cannot modify the claim (proof is bound to recipient).
   - **Manual:** Copy the proof data and submit via any Base block explorer (BaseScan) or contract interaction tool.

4. **Completion** — Tokens arrive in the recipient address. On-chain observers see only: a nullifier, a recipient address, and a ZK proof. **Nothing links to the qualified address.**

### 6.7 Privacy Guarantees

| What is public on-chain | What is NOT public on-chain |
|--------------------------|-----------------------------|
| STARK proof | Qualified (original) address |
| Nullifier (opaque hash) | Private key |
| Recipient address | Merkle proof / tree position |
| Claim amount (uniform for all 65M) | Link between qualified ↔ recipient |

### 6.8 Privacy Caveats & Edge Cases

| Risk | Mitigation |
|------|------------|
| **Gas funding correlation** — if claimant sends ETH from qualified address to recipient for gas, addresses are linked. | Tool warns: "Fund your recipient address from an independent source (CEX, bridge)." |
| **Relayer sees proof** — but cannot link it to a qualified address. | Relayer sees {proof, nullifier, recipient} — same as on-chain. No additional info. |
| **Front-running** — observer sees pending tx. | Impossible — recipient is committed to the proof. Changing recipient invalidates the proof. |

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description | Mutability |
|----------|-------------|------------|
| `ZKMToken` | Standard ERC-20 token | Immutable (no owner after deploy) |
| `RiscZeroVerifier` | RISC Zero STARK verifier (auto-generated) | Immutable |
| `ZKMAirdrop` | Claim contract — verify proof + transfer tokens | **Immutable** (no owner, no admin, no pause) |

### 7.2 ZKMToken Contract

```
Standard ERC-20:
  - name: "ZKMist"
  - symbol: "ZKM"
  - decimals: 18
  - totalSupply: 1,000,000,000e18
  - No mint/burn functions
  - No owner after deployment
  - 500,000,000 ZKM transferred to ZKMAirdrop at deployment
  - Remaining allocated per §4.2
```

### 7.3 ZKMAirdrop Contract

**This contract is fully immutable.** No admin functions, no owner, no pausability, no upgradeability. Deployed once and never touched again.

#### State Variables

```solidity
IERC20 public immutable zkmToken;
IRiscZeroVerifier public immutable verifier;
bytes32 public immutable imageId;         // Guest program identity
bytes32 public immutable merkleRoot;
uint256 public immutable claimAmount;
uint256 public immutable claimDeadline;   // Timestamp after which claims are rejected
mapping(bytes32 => bool) public usedNullifiers;
```

#### Functions

The contract has **one public function**:

| Function | Description |
|----------|-------------|
| `claim(bytes proof, bytes journal, bytes32 nullifier, address recipient)` | Verify proof, check nullifier, transfer tokens. Callable by anyone. |

Plus standard view functions:

| Function | Description |
|----------|-------------|
| `usedNullifiers(bytes32)` | Check if a nullifier has been used |
| `isClaimed(bytes32)` | Alias for nullifier check |

#### Claim Function

```solidity
contract ZKMAirdrop {
    IERC20 public immutable zkmToken;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    bytes32 public immutable merkleRoot;
    uint256 public immutable claimAmount;
    uint256 public immutable claimDeadline;

    mapping(bytes32 => bool) public usedNullifiers;

    constructor(
        address _zkmToken,
        address _verifier,
        bytes32 _imageId,
        bytes32 _merkleRoot,
        uint256 _claimAmount,
        uint256 _claimDeadline
    ) {
        zkmToken = IERC20(_zkmToken);
        verifier = IRiscZeroVerifier(_verifier);
        imageId = _imageId;
        merkleRoot = _merkleRoot;
        claimAmount = _claimAmount;
        claimDeadline = _claimDeadline;
    }

    function claim(
        bytes calldata _proof,
        bytes calldata _journal,
        bytes32 _nullifier,
        address _recipient
    ) external {
        require(block.timestamp <= claimDeadline, "Claim period ended");
        require(!usedNullifiers[_nullifier], "Already claimed");

        // Verify the RISC Zero STARK proof
        bytes32 journalRoot = bytes32(sha256(_journal));
        verifier.verify(_proof, imageId, journalRoot);

        // Decode and validate journal
        bytes32 journalMerkleRoot = bytes32(_journal[0:32]);
        bytes32 journalNullifier  = bytes32(_journal[32:64]);
        address journalRecipient  = address(bytes20(_journal[64:84]));

        require(journalMerkleRoot == merkleRoot, "Root mismatch");
        require(journalNullifier == _nullifier, "Nullifier mismatch");
        require(journalRecipient == _recipient, "Recipient mismatch");

        // Mark nullifier and transfer
        usedNullifiers[_nullifier] = true;
        zkmToken.transfer(_recipient, claimAmount);

        emit Claimed(_nullifier, claimAmount, _recipient);
    }

    event Claimed(bytes32 indexed nullifier, uint256 amount, address indexed recipient);
}
```

**Key properties:**
- `msg.sender` is **not used** — anyone can call `claim`.
- No admin, owner, or pause functions.
- The guest program `imageId` is immutable — only proofs from the published Rust program are accepted.
- Unclaimed tokens remain in the contract permanently. No withdrawal function exists.
- `claimDeadline` prevents claims after the deadline. No way to extend.

### 7.4 Published Data Artifacts

All data and artifacts are published on IPFS + GitHub mirror:

```
zkmist-airdrop/
├── manifest.json                      # Metadata (see §5.4)
├── addresses_00000001.csv              # Sorted address list (1M rows each)
├── ...
├── guest_program.elf                  # Compiled RISC Zero guest program (RISC-V)
├── image_id.txt                       # Guest program image ID (also on-chain)
├── guest_program_source.tar.gz        # Full Rust source code (auditable)
├── risc_zero_verifier.sol             # Auto-generated verifier contract
└── CONTRACTS.md                       # Deployed contract addresses on Base
```

> **No proving key or trusted setup artifacts.** RISC Zero doesn't need them.

#### Local Merkle Tree Construction (Streaming)

The CLI tool builds the Merkle tree locally in a streaming pass:

```
1. Download sorted address list from IPFS (stream, don't load all at once)
2. For each address (in sorted order):
   a. Compute leaf = poseidon(address)
   b. Push leaf onto stack
   c. While top 2 elements on stack are at the same level:
      - Pop both, compute parent = sha256(left || right)
      - Push parent
   d. If current address matches claimant's address:
      - Record the sibling at each level (the Merkle proof)
3. After processing all 65M leaves:
   - Stack contains the Merkle root (verify against on-chain value)
   - Proof is extracted

Memory: O(tree_depth) = O(26) hash values = ~832 bytes
Time: ~1–2 minutes on a modern computer
```

---

## 8. CLI Tool

### 8.1 Commands

```
zkmist fetch              Download eligibility list from IPFS (~1.3 GB)
zkmist prove              Generate ZK proof (interactive)
zkmist submit <proof.json> Submit proof to ZKMAirdrop contract on Base
zkmist verify <proof.json> Verify a proof locally (dry run)
zkmist check <address>     Check if an address is in the eligibility list
```

### 8.2 `zkmist prove` — Interactive Flow

```
$ zkmist prove

[1/4] Loading eligibility list...
       Using cached list: ~/.zkmist/eligibility/ (1.3 GB)

[2/4] Building Merkle tree (streaming)...
       Processing 65,000,000 addresses...
       Found your address at index 42,317,891
       Merkle proof extracted (26 levels)
       ✓ Root matches on-chain value: 0xabc123...

[3/4] Enter your private key (hidden):
       ********
       → Derived address: 0x742d...35Cc
       → Nullifier: 0x4a7f...e2c1

       Enter recipient address: 0xRecip...EntAddress

[4/4] Generating RISC Zero proof...
       Guest program: zkmist-claim-v1
       Image ID: 0xdef456...
       zkVM execution: 2,847,331 cycles
       ████████████████████████████████ done  (45s)

       ✓ Proof saved to: ./zkmist_proof_2026-05-03.json

To claim, run:
  zkmist submit ./zkmist_proof_2026-05-03.json

Or submit via any relayer service. The proof file contains everything needed.
Your qualified address (0x742d...35Cc) is NOT visible on-chain.
```

### 8.3 Proof File Format

```json
{
  "version": 1,
  "proof": "0x...stark_proof_hex",
  "journal": "0x...journal_hex",
  "nullifier": "0x4a7f...e2c1",
  "recipient": "0xRecip...EntAddress",
  "claimAmount": "7692307000000000000",
  "contractAddress": "0xAirdrop...Contract",
  "chainId": 8453,
  "claimDeadline": 1767225600
}
```

> The proof file is self-contained. Anyone can submit it to the contract. The relayer cannot modify any field without invalidating the proof.

### 8.4 `zkmist submit` — On-Chain Submission

```
$ zkmist submit ./zkmist_proof_2026-05-03.json

Contract:  0xAirdrop...Contract (Base)
Recipient: 0xRecip...EntAddress
Amount:    7.69 ZKM
Gas cost:  ~$0.01–0.07 (Base)
Nullifier: 0x4a7f...e2c1

Submit? [Y/n] Y

Transaction: 0xabc123...
Block:       12345678
Gas used:    1,520,000
Cost:        $0.07

✓ Claimed! 7.69 ZKM → 0xRecip...EntAddress
```

### 8.5 Relayer Ecosystem

The contract is permissionless. Anyone can build a relayer:

```
Relayer service (built by anyone):

1. User sends proof.json to the relayer (API, Telegram bot, web form, etc.)
2. Relayer validates the proof locally (optional but recommended)
3. Relayer submits the claim on Base, paying gas
4. Relayer may charge a fee (deducted from the claim, or paid separately)

The relayer CANNOT:
  - Modify the recipient (proof would be invalid)
  - Modify the nullifier (proof would be invalid)
  - Claim the tokens for themselves (recipient is bound to the proof)
  - Learn the qualified address (it's a private input to the zkVM)
```

### 8.6 Technology Stack

| Layer | Choice |
|-------|--------|
| **zkVM** | RISC Zero (risc0-zkvm) |
| **Guest Program** | Rust (compiled to RISC-V) |
| **Proof System** | STARK (RISC Zero native) |
| **Crypto Libraries** | `k256` (secp256k1), `sha2`, `tiny-keccak` |
| **CLI Tool** | Rust |
| **Chain** | Base (Chain ID: 8453) |
| **Data Publishing** | IPFS (Pinata) + GitHub mirror |

---

## 9. Claim Timeline

| Phase | Dates | Description |
|-------|-------|-------------|
| **Snapshot** | T-30 days | BigQuery extraction finalized; eligibility list published |
| **Publication** | T-14 days | Eligibility list + Merkle root + guest program source published for audit |
| **Contract Deployment** | T-7 days | ZKM + Verifier + Airdrop contracts deployed on Base; tokens funded |
| **Claim Window Opens** | T+0 | `block.timestamp >= deployment` — claims accepted |
| **Claim Window Closes** | T+90 days | `block.timestamp > claimDeadline` — claims rejected |
| **Post-close** | Indefinite | Contract sits with unclaimed tokens. No admin. Immutable. |

---

## 10. Security Considerations

### 10.1 Smart Contract Security

| Measure | Details |
|---------|---------|
| **Audit** | External audit (Trail of Bits, Spearbit, Cyfrin) before mainnet deployment |
| **Test Coverage** | ≥ 95% line coverage |
| **Guest Program Audit** | Audit the Rust source (readable, ~80 lines of logic) |
| **Immutability** | No admin, no owner, no pause, no upgrade — maximum security through simplicity |
| **No admin keys** | No keys to lose, compromise, or abuse |

### 10.2 Privacy Security

| Measure | Details |
|---------|--------|
| **Private key never leaves machine** | zkVM execution is entirely local |
| **No server dependency** | All data on IPFS. No API, no backend. |
| **No trusted setup** | STARK-based. No ceremony, no toxic waste. |
| **Deterministic nullifier** | Prevents double-claim. No server state needed. |
| **Front-running impossible** | Recipient is committed to the journal. |
| **Relayer learns nothing** | Relayer sees {proof, nullifier, recipient} — same as on-chain. |

### 10.3 Immutability Benefits

| Property | Why it matters |
|----------|----------------|
| **No admin to compromise** | No private keys to steal, no multisig to social-engineer |
| **No pause function** | Claims cannot be stopped, censored, or delayed |
| **No upgrade path** | Logic cannot be changed after deployment |
| **Trustless** | Users don't need to trust the ZKMist team — the code is the contract |
| **Permanent** | The contract exists as long as Base chain exists |

---

## 11. Technical Specifications Summary

| Spec | Value |
|------|-------|
| **Chain** | Base (Chain ID: 8453) |
| **Token** | ZKMist (ZKM), ERC-20, 18 decimals, 1B supply |
| **Proof System** | RISC Zero zkVM (STARK) |
| **Guest Program** | Rust, compiled to RISC-V ELF |
| **Trusted Setup** | **None** |
| **Merkle Tree** | 26 levels, 65M leaves, Poseidon leaf hash, SHA-256 interior |
| **Nullifier** | `sha256(privateKey ∥ "ZKMist_V1_NULLIFIER")` |
| **Claim Amount** | ~7.69 ZKM (uniform, hardcoded at deploy) |
| **Claim Deadline** | 90 days after deployment |
| **On-chain Verification** | RISC Zero STARK verifier + journal validation |
| **Proof Generation** | Local only, ~30–90s |
| **Gas (raw STARK)** | ~1,500,000 (~$0.07) |
| **Gas (Groth16 wrapper)** | ~300,000 (~$0.015) — optional optimization |
| **Solidity Version** | ^0.8.24 |
| **Contract Mutability** | **Fully immutable** — no admin, no owner, no pause |
| **Eligibility** | ≥0.004 ETH gas fees on mainnet before 2026-01-01 |
| **Qualified Addresses** | ~65,000,000 |
| **Data Distribution** | IPFS + GitHub mirror |

---

## 12. Milestones & Deliverables

| # | Milestone | Estimated Duration |
|---|-----------|---------------------|
| 1 | Run final BigQuery extraction & validate ~65M address list | Week 1 |
| 2 | Build Merkle tree, compute root, publish to IPFS | Week 2 |
| 3 | Write RISC Zero guest program (Rust) + test with small tree | Weeks 2–3 |
| 4 | Develop & test immutable contracts (ZKMToken + Verifier + ZKMAirdrop) | Weeks 3–4 |
| 5 | Build CLI tool (fetch → prove → submit) | Weeks 3–4 |
| 6 | Internal security review + testnet deployment | Week 5 |
| 7 | External audit (guest program + contracts) | Weeks 5–7 |
| 8 | Deploy to Base mainnet (immutable, no admin) | Week 8 |
| 9 | Publish all artifacts (IPFS + GitHub) | Week 8 |
| 10 | Claim window runs for 90 days | Weeks 8–21 |
| 11 | Post-close: contract remains with unclaimed tokens | Indefinite |

---

## 13. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | Eligibility criteria / snapshot source? | ✅ **Resolved** — ≥0.004 ETH gas fees on mainnet before 2026-01-01 UTC. |
| 2 | Uniform or tiered amounts? | ✅ **Resolved** — Uniform (~7.69 ZKM). |
| 3 | Proof system? | ✅ **Resolved** — RISC Zero zkVM. |
| 4 | Contract mutability? | ✅ **Resolved** — Fully immutable. No admin, no owner, no pause. |
| 5 | Web dApp? | ✅ **Resolved** — No web dApp from ZKMist team. Contract is the interface. Anyone can build one. |
| 6 | Unclaimed tokens? | ✅ **Resolved** — Remain in the contract permanently. No withdrawal function. |
| 7 | Relayers? | ✅ **Resolved** — Permissionless. Anyone can build one. The proof file is self-contained. |
| 8 | Token listing strategy? | 🔲 Pending |
| 9 | Legal / compliance review? | 🔲 Pending |
| 10 | Exact qualified count (after final BigQuery run)? | 🔲 Pending (determines exact CLAIM_AMOUNT) |
| 11 | Handle contract addresses (multisigs, smart contracts)? | 🔲 Pending (recommend: include all — they're eligible too) |
| 12 | Keccak256 in guest program for Ethereum address derivation? | 🔲 Pending (recommend: yes — must match Ethereum's address scheme) |
| 13 | Gas optimization: raw STARK (~1.5M gas) or Groth16 wrapper (~300K gas)? | 🔲 Pending (recommend: raw STARK for simplicity; Groth16 wrapper if gas is a concern at scale) |
| 14 | Claim deadline: hardcoded timestamp or block number? | 🔲 Pending (recommend: timestamp — simpler, `block.timestamp <= claimDeadline`) |

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **Nullifier** | `sha256(privateKey ∥ "ZKMist_V1_NULLIFIER")`. Prevents double-claiming without revealing the qualified address. |
| **Merkle Tree** | Binary hash tree, 26 levels. Each leaf is `poseidon(address)`. Root stored on-chain. |
| **Merkle Proof** | 26 sibling hashes proving a leaf's membership in the tree. |
| **RISC Zero** | Zero-knowledge virtual machine that proves correct execution of Rust programs. |
| **Guest Program** | The Rust program running inside RISC Zero zkVM. Proves address membership and nullifier validity. |
| **Journal** | Public output of the guest program. Contains `[merkleRoot, nullifier, recipient]`. |
| **Image ID** | Hash identifying the guest program binary. Hardcoded in the contract. |
| **STARK** | Scalable Transparent ARgument of Knowledge. Proof system requiring no trusted setup. |
| **Relayer** | Any third party that submits proofs on behalf of claimants. Operates permissionlessly. |

---

## 15. Appendix

### A. Reference Implementations

- [RISC Zero Documentation](https://dev.risczero.com/)
- [RISC Zero Examples (GitHub)](https://github.com/risc0/risc0/tree/main/examples)
- [k256 Rust crate (secp256k1)](https://crates.io/crates/k256)
- [Tornado Cash — ZK-based private transactions](https://github.com/tornadocash)

### B. Gas Estimation (Base Chain)

| Operation | Estimated Gas | Estimated Cost (Base) |
|-----------|---------------|------------------------|
| Deploy ZKMToken | ~1,200,000 | ~$0.05 |
| Deploy RiscZeroVerifier (STARK) | ~6,000,000 | ~$0.25 |
| Deploy ZKMAirdrop | ~1,000,000 | ~$0.04 |
| Claim (raw STARK) | ~1,500,000 | ~$0.07 |
| Claim (Groth16 wrapper) | ~300,000 | ~$0.015 |

> *Gas estimates based on Base gas price ~0.1 Gwei & ETH at $3,000.*

### C. Architecture Diagram

```
                    ┌──────────────────────────┐
                    │  Google BigQuery          │
                    │  (Ethereum dataset)       │
                    └──────────┬───────────────┘
                               │ ~65M addresses
                               ▼
                    ┌──────────────────────────┐
                    │  Eligibility List         │
                    │  (CSV on IPFS + GitHub)   │
                    └──────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  Claimant's Local Machine  │
                    │                            │
                    │  $ zkmist fetch            │
                    │  $ zkmist prove            │
                    │     → proof.json           │
                    │                            │
                    └──────────┬───────────────┘
                               │ proof.json
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
      ┌──────────────────┐        ┌──────────────────┐
      │  Direct submit    │        │  Any relayer      │
      │  $ zkmist submit  │        │  (permissionless) │
      └──────────┬────────┘        └────────┬──────────┘
                 │                          │
                 └────────────┬─────────────┘
                              ▼
                   ┌────────────────────────┐
                   │  ZKMAirdrop (Base)      │
                   │  IMMUTABLE CONTRACT      │
                   │                          │
                   │  claim(proof, journal,   │
                   │        nullifier, recip) │
                   │                          │
                   │  ✗ qualified addr hidden │
                   │  ✓ nullifier + recipient │
                   │  No admin. No pause.     │
                   └────────────────────────┘
```

---

*End of PRD v4.0*
