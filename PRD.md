# ZKMist (ZKM) — Product Requirements Document

**Version:** 2.0  
**Date:** 2026-05-03  
**Status:** Draft  
**Author:** ZKMist Team  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is an ERC-20 token deployed on **Base Chain** featuring a **privacy-preserving airdrop** mechanism. A predefined list of ~65 million qualified Ethereum addresses are eligible to claim ZKM tokens, but the claiming process is designed so that **the qualified address is never publicly linked to the receiving address**.

The claimant generates a **zero-knowledge proof** entirely on their local machine using only three things: the **published eligibility list**, the **private key** to their qualified address, and a **recipient address** they choose. No server, no API, no third party is involved in proof generation. The resulting proof is submitted on-chain and reveals nothing about which address is claiming — only a deterministic nullifier (preventing double-claims) and the recipient address.

### 1.2 Problem Statement

Standard airdrops create a permanent, public on-chain link between a user's qualifying activity (original address) and their claiming address. This:

- **Exposes user portfolios** — anyone can trace a claim back to the qualifying address and inspect its full history and holdings.
- **Creates targeting risk** — whales or early adopters become visible targets for phishing, social engineering, or legal scrutiny.
- **Discourages participation** — privacy-conscious users may avoid claiming airdrops they are entitled to.

### 1.3 Solution

ZKMist uses a **zero-knowledge proof system** (circom + Groth16) where claimants generate proofs entirely locally. The proof proves:

1. **Membership** — "I know a private key whose derived Ethereum address is in the published eligibility Merkle tree."
2. **Nullifier uniqueness** — a deterministic nullifier derived from the private key prevents double-claiming.
3. **Recipient binding** — the proof specifies a recipient address that receives the tokens.

**No server, API, or third party** is needed to generate the proof. The claimant only needs the published eligibility list, their private key, and a recipient address.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Deploy ZKM as a standard ERC-20 on Base Chain | Successful deployment & verification |
| G2 | Enable anonymous claiming for all qualified addresses | ≥ 90% of claims completed without identity linkage |
| G3 | Prevent double-claiming | Zero double-claims |
| G4 | Gas-efficient claim process | Claim tx cost < $0.50 USD on Base |
| G5 | Simple UX — no ZK expertise required for claimants | Average claim completed in < 3 minutes |
| G6 | Fully auditable & verifiable eligibility list | Merkle root & eligibility list published openly |

### 2.2 Non-Goals

- ZKMist is **not** a governance token (at launch).
- No staking, farming, or DeFi mechanics at launch.
- No dynamic/incremental eligibility list — the list is **fixed** at deployment.
- Not building a custom L1 or L2 — purely Base Chain.

---

## 3. User Personas

### 3.1 Claimant (Primary User)

- Holds a qualified Ethereum address.
- Wants to claim ZKM tokens to a fresh or existing Base address.
- Values privacy — does not want their qualified address linked to their receiving address.
- May or may not be technically sophisticated.

### 3.2 Admin (Operator)

- Manages the eligibility list, Merkle tree, and claim contract.
- Responsible for deployment, monitoring, and any post-launch support.
- May need to handle edge cases (e.g., stuck claims, support).

### 3.3 Observer / Auditor

- Wants to verify that the airdrop was conducted fairly.
- Can independently reconstruct the Merkle tree from the published eligibility list.
- Can verify on-chain that no double-claims occurred.

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
| **Owner/Admin** | Renounceable after claim period |

### 4.2 Token Allocation

| Allocation | % of Supply | Amount (ZKM) | Notes |
|------------|-------------|--------------|-------|
| Airdrop Claims | 50% | 500,000,000 | Distributed to qualified addresses |
| Treasury / DAO | 20% | 200,000,000 | Time-locked; future community allocation |
| Team & Advisors | 15% | 150,000,000 | Vested over 24 months |
| Liquidity Provision | 10% | 100,000,000 | Paired in DEX LP on Base |
| Reserve | 5% | 50,000,000 | Emergency / partnerships |

### 4.3 Per-Address Claim Amount

- **Uniform allocation per qualified address:** `claimAmount = 500,000,000 / ~65,000,000 ≈ 7.69 ZKM`
- All qualified addresses receive the **same amount** to preserve anonymity (see §6.5).
- Exact `claimAmount` is hardcoded in the airdrop contract at deployment.

---

## 5. Eligibility & Qualification

### 5.1 Eligibility Criteria

> **Any Ethereum mainnet address that has paid a cumulative total of at least 0.004 ETH in transaction fees before the end of 2025 (UTC) is qualified.**

| Parameter | Value |
|-----------|-------|
| **Threshold** | ≥ 0.004 ETH cumulative gas fees paid |
| **Cutoff** | `block_timestamp < 2026-01-01 00:00:00 UTC` |
| **Scope** | Ethereum mainnet only (L1) |
| **Qualifying Action** | `from_address` on successful transactions (`receipt_status = 1`) |
| **Qualified Addresses** | **~65,000,000** (estimated from BigQuery) |

**Rationale:** 0.004 ETH (~$8–12 at average prices) represents a meaningful on-chain activity threshold that filters out dust/spam addresses while capturing virtually all real users, DeFi participants, NFT traders, and anyone who has genuinely used Ethereum. It is a broad, inclusive, and Sybil-resistant criterion — costly to fake at scale.

### 5.2 Data Source — Google BigQuery

The eligibility data is extracted from the **Google BigQuery Ethereum dataset** (`bigquery-public-data.crypto_ethereum`).

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

- `receipt_status = 1` — only counts **successful** transactions (reverts excluded).
- `gas_price × receipt_gas_used` — actual gas fee paid per tx (pre-EIP-1559 and post-EIP-1559 compatible since `gas_price` is the effective price paid).
- For **EIP-1559 transactions**, BigQuery's `gas_price` already reflects the effective `baseFeePerGas + maxPriorityFeePerGas` paid, making the query accurate across both transaction types.
- The query processes **~2.5 billion rows** (all Ethereum transactions up to end of 2025). Expected BigQuery cost: ~$25–50 USD.

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
    │   • Remove zero-address, contract-creator-only addresses (optional filter)
    │   • Sort lexicographically for deterministic Merkle tree
    ▼
Final Eligibility List
        Format: JSON + CSV
        Published to: IPFS (CID pinned), GitHub release, website
```

### 5.3 Claim Amount — Uniform Allocation

With **~65M qualified addresses** and **500,000,000 ZKM** allocated to the airdrop:

```
claimAmount = 500,000,000 / 65,000,000 ≈ 7.69 ZKM per address
```

| Parameter | Value |
|-----------|-------|
| **Total Airdrop Supply** | 500,000,000 ZKM |
| **Qualified Addresses** | ~65,000,000 |
| **ZKM per Address** | **~7.69 ZKM** (uniform, exact amount set at deployment) |
| **Merkle Leaf** | `keccak256(abi.encodePacked(address, amount))` |

> **Why uniform?** Uniform amounts provide the strongest privacy guarantee — the claim amount reveals nothing about which address is claiming. Tiered amounts would create a deanonymization vector (an observer could narrow candidates by tier). See §6.5.

### 5.4 Eligibility List Format

The list is published as a set of chunked files for practical distribution:

```
eligibility/
├── manifest.json              # Metadata: count, merkleRoot, hash algorithm
├── addresses_00000001.csv     # address,amount (1M rows each)
├── addresses_00000002.csv
├── ...
└── addresses_00000065.csv
```

**`manifest.json`**
```json
{
  "version": 1,
  "cutoffTimestamp": "2025-12-31T23:59:59Z",
  "feeThresholdEth": "0.004",
  "totalQualified": 65000000,
  "claimAmountWei": "7692307000000000000",
  "merkleRoot": "0x...",
  "merkleTreeDepth": 26,
  "hashAlgorithm": "keccak256",
  "files": [
    { "file": "addresses_00000001.csv", "sha256": "0x..." },
    { "file": "addresses_00000002.csv", "sha256": "0x..." }
  ]
}
```

The list is published on **IPFS** (pinned via Pinata/estuary) and mirrored on GitHub so anyone can audit it.

---

## 6. Anonymous Claim Protocol

### 6.1 Design Principles

1. **Local-only proof generation** — the claimant never sends their private key, qualified address, or any identifying information to any server.
2. **Three inputs suffice** — the published eligibility list + private key + recipient address are all that's needed.
3. **On-chain reveals nothing** — only a nullifier (derived from the private key) and the recipient address appear on-chain.
4. **No trusted third party** — the eligibility list is public, the Merkle root is on-chain, and anyone can verify.

### 6.2 High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        PUBLISHED DATA                            │
│                                                                  │
│  Google BigQuery ──► Eligibility List (~65M addresses)           │
│                            │                                     │
│                            ▼                                     │
│                  Published to IPFS (chunked CSV)                 │
│                  Merkle Root stored on-chain                     │
│                                                                  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   CLAIMANT'S LOCAL MACHINE                        │
│                                                                  │
│  Inputs:                                                         │
│    ① Published eligibility list (downloaded from IPFS)           │
│    ② Private key to qualified Ethereum address                   │
│    ③ Recipient address (not linked to qualified address)         │
│                                                                  │
│  Local proof generation (CLI tool or desktop app):               │
│    a. Load eligibility list, build Merkle tree (streaming)       │
│    b. Derive address from private key                            │
│    c. Find address in tree → extract Merkle proof (26 levels)    │
│    d. Compute nullifier = poseidon(privateKey, domainSeparator)  │
│    e. Generate ZK proof (Groth16) using circom circuit           │
│                                                                  │
│  Output:                                                         │
│    • ZK proof (π)                                                │
│    • Public signals: [merkleRoot, nullifier, recipientAddress]   │
│                                                                  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼  (submit via any wallet or relayer)
┌──────────────────────────────────────────────────────────────────┐
│                       ON-CHAIN (Base)                             │
│                                                                  │
│  ┌───────────────┐      ┌──────────────────────┐                 │
│  │  ZKM Token    │◄─────│  ZKMAirdrop Claim    │                 │
│  │  (ERC-20)     │      │  Contract            │                 │
│  └───────────────┘      └──────────────────────┘                 │
│                              │                                   │
│         Receives:            │                                   │
│          • ZK proof (π)      │                                   │
│          • nullifier         │                                   │
│          • recipientAddress  │                                   │
│                              │                                   │
│         Verifies:            │                                   │
│          • ZK proof is valid │                                   │
│          • nullifier unused  │                                   │
│          • transfers ZKM     │                                   │
│            to recipient      │                                   │
│                                                                  │
│  On-chain visibility:                                            │
│    ✗ qualified address — HIDDEN (private input to ZK circuit)    │
│    ✗ private key — HIDDEN                                        │
│    ✓ nullifier (opaque hash, not linkable to address)            │
│    ✓ recipient address                                           │
│    ✓ ZK proof                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 6.3 Privacy Mechanism — ZK Proof + Deterministic Nullifier

The core of the protocol is a **zero-knowledge circuit** (circom) that takes the claimant's private key as a **private input** and produces a proof that reveals nothing about which address is claiming.

#### Why ZK (not hash-based nullifiers)?

Previous versions considered a simpler hash-based nullifier scheme (`keccak256(address, salt)`). This had a fatal flaw: a user could generate unlimited salts and claim multiple times. A ZK proof with a **deterministic nullifier derived from the private key** solves this — the same private key always produces the same nullifier, making double-claiming impossible regardless of how many proofs are generated.

#### ZK Circuit Design

```
Circuit: ZKMAirdropClaim (treeDepth = 26)

PRIVATE INPUTS (never leave the claimant's machine):
  • privateKey        — the Ethereum private key of the qualified address
  • merkleProof[26]   — 26 sibling hashes for Merkle membership proof
  • pathIndices[26]   — 0/1 direction bits for each level

PUBLIC INPUTS (submitted on-chain):
  • merkleRoot        — the on-chain Merkle root (verified by contract)
  • nullifier         — deterministic hash derived from privateKey
  • recipientAddress  — the address receiving ZKM tokens

CIRCUIT LOGIC:
  1. Derive ethereum address from privateKey
     (secp256k1 scalar multiplication → keccak256(pubKey) → lower 20 bytes)

  2. Compute leaf = poseidon(address)
     (or keccak256(address) — must match the hash used in tree construction)

  3. Verify Merkle proof:
     Verify that `leaf` at `pathIndices` with `merkleProof` produces `merkleRoot`

  4. Compute nullifier = poseidon(privateKey, domainSeparator)
     where domainSeparator is a protocol-specific constant

  5. Enforce nullifier === public input nullifier

  6. Enforce recipientAddress === public input recipientAddress

OUTPUT: ZK proof (π) that all constraints are satisfied
```

#### Nullifier Properties

| Property | Explanation |
|----------|-------------|
| **Deterministic** | `nullifier = poseidon(privateKey, domainSeparator)` — same key always produces the same nullifier |
| **Unique per address** | Different private keys → different nullifiers (collision-resistant) |
| **Not precomputable** | Cannot compute nullifier from the published address list — requires the private key |
| **Prevents double-claim** | Same private key → same nullifier → contract rejects second claim |
| **Not linkable** | Nullifier reveals nothing about the Ethereum address (no known relation between poseidon(privateKey) and keccak256(pubKey)) |

### 6.4 Claim Flow (Step-by-Step)

1. **Download eligibility list** — The claimant downloads the published eligibility list from IPFS (~1.3 GB, chunked CSV). This is a one-time download; subsequent claims reuse the cached data.

2. **Build Merkle tree locally** — The CLI/desktop tool builds the Merkle tree in a **streaming fashion** using O(log n) memory. As it streams through the 65M sorted addresses, it finds the claimant's address and extracts its Merkle proof (26 siblings).

   > **Performance:** Streaming through 65M leaves takes ~1–2 minutes on a modern computer. The tree can be cached locally for future use.

3. **Provide inputs** — The claimant provides:
   - Their Ethereum **private key** (or signs via connected wallet — the key never leaves the machine)
   - A **recipient address** (any Base address they control, preferably fresh and not linked to the qualified address)

4. **Generate ZK proof** — The tool runs the circom circuit via snarkjs:
   - Private inputs: private key, Merkle proof (26 hashes), path indices
   - Public inputs: Merkle root, nullifier, recipient address
   - Output: Groth16 proof (~128 bytes) + public signals

   > **Performance:** ZK proof generation takes ~10–30 seconds on a modern computer (WASM-accelerated).

5. **Submit on-chain** — The claimant submits the proof to the `ZKMAirdrop` contract on Base. This can be done via:
   - **Any wallet** — `msg.sender` is irrelevant (could be anyone, including the recipient address)
   - **A relayer** — for gasless claims (the recipient address doesn't even need ETH on Base)

6. **Contract verification:**
   - Verify the Groth16 proof against the on-chain verifier contract.
   - Verify `merkleRoot` matches the immutable on-chain root.
   - Check `usedNullifiers[nullifier] == false`.
   - Set `usedNullifiers[nullifier] = true`.
   - Transfer `CLAIM_AMOUNT` ZKM to `recipientAddress`.

7. **Completion** — Tokens arrive in the recipient address. On-chain observers see: a ZK proof, a nullifier, and a recipient address. **Nothing links to the original qualified address.**

### 6.5 Privacy Guarantees

| What is public on-chain | What is NOT public on-chain |
|--------------------------|-----------------------------|
| ZK proof (reveals nothing beyond validity) | Qualified (original) address |
| Nullifier (opaque, not precomputable from address) | Private key |
| Recipient address | Merkle proof / tree position |
| Claim amount (uniform — same for all 65M) | Link between qualified ↔ recipient |

**Uniform amount = strongest anonymity set.** With 65M addresses all receiving the same amount, the claim amount reveals nothing. Every claim looks identical on-chain except for the nullifier and recipient address.

**msg.sender is irrelevant.** The transaction submitter can be anyone — the qualified address is never `msg.sender` and is never revealed in any calldata. This is true end-to-end anonymity.

### 6.6 Privacy Caveats & Edge Cases

| Risk | Mitigation |
|------|------------|
| **Time correlation** — if a claimant transfers ETH for gas from their qualified address to their recipient address, the addresses can be linked. | Tool should warn users to fund the recipient address from an independent source (CEX withdrawal, bridge). |
| **Uniform amounts eliminate amount-based deanonymization.** | ✅ All 65M addresses receive the same 7.69 ZKM. |
| **Nullifier cannot be precomputed** — requires private key, which is not in the published list. | ✅ Resolved by `nullifier = poseidon(privateKey, domainSeparator)`. |
| **No double-claim via new salt** — nullifier is deterministic from the private key. | ✅ Resolved. Same key → same nullifier. |
| **Front-running** — observer sees pending tx. | Only nullifier + recipient visible. A front-runner cannot steal the claim (nullifier is bound to the private key). |
| **Relayer sees the proof** — but cannot link it to a qualified address. | Relayer sees {proof, nullifier, recipient} — same as on-chain. No additional info leaked. |

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description |
|----------|-------------|
| `ZKMToken` | Standard ERC-20 token contract for ZKMist |
| `ZKMAirdropVerifier` | Auto-generated Groth16 verifier contract (from snarkjs) |
| `ZKMAirdrop` | Claim contract — verifies ZK proof + nullifier uniqueness |
| (optional) `Timelock` | For treasury/team token vesting |

### 7.2 ZKMToken Contract

```
Standard ERC-20:
  - name: "ZKMist"
  - symbol: "ZKM"
  - decimals: 18
  - totalSupply: 1,000,000,000e18
  - No mint/burn functions after deployment
  - All tokens minted to deployer at construction
```

### 7.3 ZKMAirdrop Contract

#### State Variables

```solidity
IERC20 public immutable zkmToken;
IVerifier public immutable verifier;   // Groth16 verifier contract
bytes32 public immutable merkleRoot;
mapping(bytes32 => bool) public usedNullifiers;
uint256 public claimStart;
uint256 public claimEnd;
address public admin;
bool public paused;
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `claim(uint[2] _proofA, uint[2][2] _proofB, uint[2] _proofC, bytes32 _nullifier, address _recipient)` | Public | Claim tokens. Verifies ZK proof + nullifier uniqueness. |
| `pause()` | Admin | Pause claims (emergency). |
| `unpause()` | Admin | Unpause claims. |
| `withdrawUnclaimed()` | Admin | After claim period ends, withdraw remaining tokens to treasury. |
| `usedNullifiers(bytes32)` | View | Check if a nullifier has been used. |
| `isClaimed(bytes32)` | View | Alias for nullifier check. |

#### Claim Function Pseudocode

```solidity
uint256 public constant CLAIM_AMOUNT = 7_692_307_000_000_000_000; // ~7.69 ZKM

function claim(
    uint256[2] calldata _pA,         // Groth16 proof part A
    uint256[2][2] calldata _pB,       // Groth16 proof part B
    uint256[2] calldata _pC,          // Groth16 proof part C
    bytes32 _nullifier,               // Public signal: nullifier
    address _recipient                // Public signal: recipient address
) external {
    require(!paused, "Claims paused");
    require(block.timestamp >= claimStart, "Not started");
    require(block.timestamp <= claimEnd, "Claim period ended");
    require(!usedNullifiers[_nullifier], "Already claimed");

    // Prepare public signals for ZK verification
    // The circuit outputs: [merkleRoot, nullifier, recipientAddress]
    uint256[3] memory publicSignals = [
        uint256(merkleRoot),
        uint256(_nullifier),
        uint256(uint160(_recipient))
    ];

    // Verify the ZK proof
    require(verifier.verifyProof(_pA, _pB, _pC, publicSignals), "Invalid proof");

    // Mark nullifier as used
    usedNullifiers[_nullifier] = true;

    // Transfer tokens to recipient
    zkmToken.transfer(_recipient, CLAIM_AMOUNT);

    emit Claimed(_nullifier, CLAIM_AMOUNT, _recipient);
}
```

**Key design properties:**
- `msg.sender` is **not used** for verification — anyone can submit the claim.
- The qualified address is **never visible** on-chain — it's a private input to the ZK circuit.
- The nullifier is verified inside the ZK proof (circuit enforces it's correctly derived from the private key).
- The Merkle root is verified inside the ZK proof (circuit enforces the address is in the tree).
- The recipient address is a public signal, bound to the proof.

### 7.4 Events

```solidity
event Claimed(bytes32 indexed nullifier, uint256 amount, address indexed recipient);
event Paused();
event Unpaused();
event Withdrawn(address to, uint256 amount);
```

### 7.5 Published Data Artifacts

All data needed for proof generation is **published and publicly verifiable**. No server interaction is required.

#### Published Files (IPFS + GitHub mirror)

```
zkmist-airdrop/
├── manifest.json                 # Metadata (see §5.4)
├── addresses_00000001.csv         # Sorted address list (1M rows each, ~65 files)
├── addresses_00000002.csv
├── ...
├── merkle_root.txt               # The Merkle root (also on-chain)
├── proving_key.zkey              # Groth16 proving key (for CLI tool)
├── verification_key.json         # Verification key (for contract generation)
├── circuit.wasm                  # Compiled circom circuit (for CLI tool)
└── trusted_setup_attestation.txt # Ceremony attestation for trusted setup
```

#### Local Merkle Tree Construction (Streaming)

The claimant's CLI/desktop tool builds the Merkle tree locally from the published address list using a **streaming algorithm** that requires only O(log n) memory:

```
Streaming Merkle Tree Builder:

1. Download sorted address list from IPFS (stream, don't load all at once)
2. For each address (in sorted order):
   a. Compute leaf = hash(address)
   b. Push leaf onto stack
   c. While top 2 elements on stack are at the same level:
      - Pop both, compute parent = hash(left, right)
      - Push parent
   d. If current address matches claimant's address:
      - Record the sibling at each level (the Merkle proof)
3. After processing all leaves:
   - Stack contains the Merkle root
   - Proof is extracted

Memory: O(tree_depth) = O(26) hash values = ~832 bytes
Time: O(n) where n = 65M → ~1–2 minutes
```

> **No server needed.** The tree is deterministically reconstructed from the published list. Anyone can verify the root matches the on-chain value.

#### ZK Proof Generation (Local)

```
1. Load the compiled circuit (circuit.wasm)
2. Provide inputs:
   - Private: privateKey, merkleProof[26], pathIndices[26]
   - Public: merkleRoot, nullifier (computed), recipientAddress
3. Compute witness via circuit.wasm
4. Generate Groth16 proof via snarkjs + proving_key.zkey
5. Output: proof (π) + public signals
```

> **Performance:** ~10–30 seconds on a modern computer. Purely local computation.

#### Merkle Tree Construction Details

```
1. Sort all 65M addresses lexicographically.
2. Pad to next power of 2 (2^26 = 67,108,864) with zero-value leaves.
3. Leaf = poseidon(address) or keccak256(address)
4. Build binary tree bottom-up:
   node = hash(leftChild, rightChild)
5. Root = top-level hash → hardcoded in smart contract.
6. Claimant extracts proof path for their specific leaf index.
```

> **Estimated resources:** Building the 65M-leaf tree takes ~1–2 minutes streaming on a modern computer with <100MB RAM. Proof generation adds ~10–30 seconds.

---

## 8. Claimant Tool & dApp

### 8.1 Two Claim Modes

| Mode | Description | Target User |
|------|-------------|-------------|
| **CLI / Desktop App** (primary) | Downloads full list, builds tree, generates ZK proof locally. Maximum trustlessness. | Power users, privacy-conscious users |
| **Web dApp** (convenience) | Same ZK proof generation in browser (WASM). Downloads pre-computed Merkle proof from published artifacts (no full list download needed). | Casual users |

### 8.2 CLI / Desktop App — Claim Flow

```
$ zkmist claim --key <PRIVATE_KEY> --recipient 0xRecip...

[1/4] Downloading eligibility list from IPFS...
       ████████████████████████████████ 100%  (1.3 GB)

[2/4] Building Merkle tree (streaming)...
       Processing 65,000,000 addresses...
       Found your address at index 42,317,891
       Merkle proof extracted (26 levels)
       ✓ Root matches on-chain value

[3/4] Generating ZK proof...
       Circuit: ZKMAirdropClaim (depth=26)
       Proof system: Groth16
       ████████████████████████████████ done  (12s)
       Nullifier: 0x4a7f...e2c1

[4/4] Submit claim?
       Recipient: 0xRecip...EntAddress
       Amount:    7.69 ZKM
       Gas cost:  ~$0.01 (Base)

       [Y/n] Y

       Transaction submitted: 0xabc123...
       ✓ Claimed! 7.69 ZKM → 0xRecip...EntAddress

       On-chain: qualified address is NOT visible.
```

### 8.3 Web dApp — Claim Flow

```
Step 1: "Connect Qualified Wallet"
        └─ Connect the wallet holding the eligible Ethereum mainnet address
        └─ dApp checks eligibility via local lookup of published address list
        └─ If not found → "This address is not eligible"

Step 2: "Verify Eligibility" ✓
        └─ Shows: "You are eligible for ~7.69 ZKM tokens"
        └─ Generates deterministic nullifier (computed from private key via wallet sign)

Step 3: "Choose Recipient Address"
        └─ Option A: Connect a different wallet (on Base)
        └─ Option B: Paste any Base address manually
        └─ ⚠️ Warning: "Do not fund this address from your qualified wallet"

Step 4: "Download Merkle Proof"
        └─ Downloads only the relevant proof chunk from IPFS (~few MB)
        └─ Proof is verified against the on-chain Merkle root client-side

Step 5: "Generate ZK Proof" (runs in browser via WASM)
        └─ ~10–30 seconds progress bar
        └─ All computation is local — nothing leaves the browser

Step 6: "Submit Claim"
        └─ Option A: Submit directly (recipient address needs ETH on Base)
        └─ Option B: Submit via relayer (gasless)

Step 7: "Claim Complete!" ✓
        └─ Shows tx hash, link to BaseScan
        └─ "Your qualified address is NOT linked to your recipient address"
```

### 8.4 Technology Stack

| Layer | Choice |
|-------|--------|
| **ZK Circuit** | circom 2.1.x |
| **Proof System** | Groth16 (via snarkjs) |
| **Proof Generation** | snarkjs + WASM (runs locally in CLI or browser) |
| **Tree Hash** | Poseidon (for ZK-friendliness) or keccak256 |
| **CLI Tool** | Node.js / Rust |
| **Web dApp** | Next.js / React + WASM |
| **Wallet Connect** | RainbowKit / wagmi / viem |
| **Chain** | Base (Chain ID: 8453) |
| **Data Publishing** | IPFS (Pinata) + GitHub mirror |
| **Relayer (optional)** | Gelato / custom |
| **Hosting** | Vercel / IPFS |
| **Style** | TailwindCSS |

---

## 9. Claim Timeline

| Phase | Dates | Description |
|-------|-------|-------------|
| **Snapshot** | T-30 days | Snapshot block taken; eligibility list finalized |
| **Publication** | T-14 days | Eligibility list + Merkle root published for audit |
| **Contract Deployment** | T-7 days | ZKM + Airdrop contracts deployed on Base; tokens funded |
| **Claim Window Opens** | T+0 | Claim period begins |
| **Claim Window Closes** | T+90 days | No more claims accepted |
| **Unclaimed Withdrawal** | T+97 days | Admin withdraws unclaimed tokens to treasury |

---

## 10. Security Considerations

### 10.1 Smart Contract Security

| Measure | Details |
|---------|---------|
| **Audit** | Engage a reputable auditor (e.g., Trail of Bits, Spearbit, Cyfrin) before mainnet deployment |
| **Test Coverage** | ≥ 95% line coverage on all contracts |
| **Formal Verification** | Verify Merkle proof logic + nullifier logic |
| **Pause Mechanism** | Admin can pause claims if vulnerability discovered |
| **No Upgradeability** | Immutable contracts (no proxy pattern) — simplicity is security |
| **Renounce Admin** | Admin role can be renounced after claim period |

### 10.2 Privacy Security

| Measure | Details |
|---------|---------|
| **Private key never leaves local machine** | ZK proof generation is entirely local (CLI or browser WASM). No server receives the private key. |
| **No server dependency** | No Proof API, no backend. All data is published on IPFS. |
| **No server-side logging** | Not applicable — there is no server. |
| **Deterministic nullifier** | Derived from private key, not random salt. Prevents double-claim without requiring server-side state. |
| **CORS / CSP Headers** | Strict security headers on web dApp |
| **User Guidance** | Clear warnings about not linking addresses via on-chain transfers |

### 10.3 Operational Security

| Measure | Details |
|---------|---------|
| **Multisig for Admin** | Admin address is a 3-of-5 multisig (e.g., Safe) |
| **Timelock for Withdrawal** | Unclaimed withdrawal has a 7-day delay |
| **Monitoring** | On-chain monitoring for unusual claim patterns |
| **Bug Bounty** | Post-launch bounty program via Immunefi |

---

## 11. Technical Specifications Summary

| Spec | Value |
|------|-------|
| **Chain** | Base (Chain ID: 8453) |
| **Token Standard** | ERC-20 |
| **Token Name** | ZKMist |
| **Token Symbol** | ZKM |
| **Token Decimals** | 18 |
| **Total Supply** | 1,000,000,000 (1B) |
| **Merkle Tree Hash** | Poseidon (ZK-friendly) for tree; keccak256 for leaf pre-image |
| **Merkle Tree Depth** | 26 levels (65M leaves, padded to 2²⁶) |
| **Merkle Proof Size** | 26 × 32 bytes = 832 bytes per claim |
| **Nullifier Scheme** | poseidon(privateKey, domainSeparator) — deterministic, non-precomputable |
| **Claim Amount** | 7.69 ZKM (constant — uniform for all 65M addresses) |
| **Claim Verification** | Groth16 ZK proof verification (on-chain) + nullifier uniqueness |
| **Proof System** | Groth16 (circom + snarkjs) |
| **Proof Generation** | Local (CLI or browser WASM), ~10–30 seconds |
| **Proof Size** | ~128 bytes (Groth16) + 3 public signals |
| **Claim Method** | Anyone submits proof (wallet, relayer, CLI) — msg.sender irrelevant |
| **Claim Period** | 90 days |
| **Gas Target** | < $0.50 per claim (~300K gas for Groth16 verification) |
| **Solidity Version** | ^0.8.24 |
| **Contract Size Target** | < 24KB (deployment limit) |
| **Eligibility Data Source** | Google BigQuery (`bigquery-public-data.crypto_ethereum`) |
| **Qualified Addresses** | ~65,000,000 |
| **Data Distribution** | IPFS (chunked CSV) + GitHub mirror |
| **Trusted Setup** | Groth16 ceremony required (per-circuit) |

---

## 12. Milestones & Deliverables

| # | Milestone | Estimated Duration |
|---|-----------|---------------------|
| 1 | Run final BigQuery extraction & validate ~65M address list | Week 1 |
| 2 | Build Merkle tree (26-level, 65M leaves), publish to IPFS, compute root | Week 2 |
| 3 | Write circom circuit (ZKMAirdropClaim) + test with small tree | Week 2 |
| 4 | Groth16 trusted setup ceremony (per-circuit) | Week 3 |
| 5 | Develop & test smart contracts (ZKMToken + Verifier + ZKMAirdrop) | Weeks 3–4 |
| 6 | Build CLI tool (download list → stream tree → generate proof → submit) | Weeks 3–4 |
| 7 | Build web dApp (WASM-based proof generation in browser) | Weeks 4–5 |
| 8 | Internal security review + testnet deployment | Week 5 |
| 9 | External audit (circuit + contracts) | Weeks 5–7 |
| 10 | Set up relayer service (if applicable) | Week 6 |
| 11 | Deploy to Base mainnet | Week 8 |
| 12 | Open claim window | Week 8 |
| 13 | Close claim window + withdraw unclaimed | Week 21 |
| 14 | Renounce admin / decentralize | Week 22 |

---

## 13. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | What is the exact eligibility criteria / snapshot source? | ✅ **Resolved** — ≥ 0.004 ETH cumulative gas fees on Ethereum mainnet before 2026-01-01 UTC. Data from Google BigQuery. ~65M addresses. |
| 2 | Will claim amounts be uniform or tiered? | ✅ **Resolved** — Uniform (~7.69 ZKM per address). Uniform amounts maximize privacy by eliminating amount-based deanonymization. |
| 3 | Hash-based nullifiers vs ZK proofs? | ✅ **Resolved** — ZK proofs (circom + Groth16). Hash-based nullifiers had a fatal double-claim vulnerability (new salt = new nullifier). ZK + deterministic nullifier from private key is the only design that provides both privacy and double-claim prevention. |
| 4 | Will a relayer service be built or use an existing one (Gelato)? | 🔲 Pending |
| 5 | Should the eligibility list be updatable (e.g., to fix errors)? | 🔲 Pending (recommend no — fixed list) |
| 6 | What happens to unclaimed tokens after the claim window? | 🔲 Pending (recommend → treasury) |
| 7 | Will the admin role be fully renounced post-claim? | 🔲 Pending (recommend yes) |
| 8 | Sybil resistance beyond the 0.004 ETH fee threshold? | ✅ **Resolved** — 0.004 ETH (~$8–12) is a meaningful Sybil filter. |
| 9 | Token listing strategy — DEX liquidity pool at launch or after claim period? | 🔲 Pending |
| 10 | Legal / compliance review needed for the airdrop? | 🔲 Pending |
| 11 | Exact snapshot block number for 2025-12-31 23:59:59 UTC? | 🔲 Pending |
| 12 | How to handle addresses that are contracts (smart contracts / multisigs)? | 🔲 Pending (recommend: include all — contracts are eligible too) |
| 13 | Tree hash: Poseidon (ZK-friendly) or keccak256? | 🔲 Pending (recommend Poseidon for efficient ZK proofs, but keccak256 is more standard. Trade-off: Poseidon requires a Poseidon-based tree build; keccak256 is standard but expensive in circom.) |
| 14 | Groth16 trusted setup: who participates? How is it run? | 🔲 Pending (recommend: use a multi-party ceremony with public attestations, or use a universal setup like KZG) |
| 15 | What if the actual qualified count differs slightly from 65M after final query? | 🔲 Pending (adjust CLAIM_AMOUNT to ensure total = 500M ZKM) |
| 16 | ECDSA in circom: use existing circom-ecdsa library or alternative identity scheme? | 🔲 Pending (circom-ecdsa is well-tested but adds ~10s to proof generation; alternative: use Ethereum address directly as public input with ECDSA verification) |
| 17 | Should the web dApp also support full-list download + streaming tree build (heavy but trustless), or only pre-computed proof download (lighter but requires publishing proof artifacts)? | 🔲 Pending (recommend both options) |

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **Nullifier** | A one-way hash derived from a qualified address + secret salt. Used to prevent double-claiming without revealing the original address. |
| **Merkle Tree** | A binary hash tree where each leaf is a hash of a (qualifiedAddress, amount) pair. The root is stored on-chain. |
| **Merkle Proof** | The sibling hashes needed to prove a specific leaf is part of the tree. |
| **Base Chain** | Coinbase's Ethereum Layer-2 blockchain. |
| **EIP-712** | Ethereum standard for typed structured data signing. Used for off-chain signature + on-chain verification. |
| **Relayer** | A service that submits transactions on behalf of a user. The relayer pays gas; the user only signs a message. |
| **ZK (Zero-Knowledge)** | Cryptographic method to prove knowledge of a value without revealing the value itself. |

---

## 15. Appendix

### A. Reference Implementations

- [circom-ecdsa — ECDSA verification in circom](https://github.com/0xPARC/circom-ecdsa)
- [Semaphore Protocol — Privacy-preserving group proofs](https://semaphore.pse.dev/)
- [Tornado Cash — ZK-based private transactions](https://github.com/tornadocash)
- [Merkle Airdrop — OpenZeppelin](https://docs.openzeppelin.com/contracts/4.x/utilities#merkle-proofs)
- [snarkjs — ZK proof generation and verification](https://github.com/iden3/snarkjs)

### D. ZK Circuit Pseudocode (circom)

```circom
pragma circom 2.1.0;

include "circomlib/poseidon.circom";
include "../node_modules/circom-ecdsa/circuits/ecdsa.circom";

// Verify ECDSA signature and recover Ethereum address,
// then prove Merkle membership and derive nullifier.

template ZKMAirdropClaim(treeDepth) {
    // === PUBLIC INPUTS ===
    signal input merkleRoot;
    signal input nullifier;
    signal input recipientAddress;

    // === PRIVATE INPUTS ===
    signal input privateKey;              // Ethereum private key
    signal input merkleSiblings[treeDepth]; // 26 sibling hashes
    signal input pathIndices[treeDepth];   // 0/1 direction bits

    // 1. Derive nullifier from private key (deterministic)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== privateKey;
    nullifierHasher.inputs[1] <== 7528515253103; // domain separator
    nullifierHasher.out === nullifier; // enforce correct nullifier

    // 2. Derive Ethereum address from private key
    //    (secp256k1 scalar mult → keccak256(pubkey) → address)
    //    Uses circom-ecdsa library for on-circuit ECDSA verification.
    //    Alternative: precompute address off-chain and pass as private input,
    //    then verify a signature inside the circuit.
    component addrDeriver = EthereumAddressDeriver();
    addrDeriver.privateKey <== privateKey;
    signal address;
    address <== addrDeriver.address;

    // 3. Compute Merkle leaf = hash(address)
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== address;
    signal leaf;
    leaf <== leafHasher.out;

    // 4. Verify Merkle membership proof
    component tree = MerkleTreeChecker(treeDepth);
    tree.leaf <== leaf;
    for (var i = 0; i < treeDepth; i++) {
        tree.siblings[i] <== merkleSiblings[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    tree.root === merkleRoot; // enforce correct membership
}

component main { public [merkleRoot, nullifier, recipientAddress] } =
    ZKMAirdropClaim(26);
```

### B. Gas Estimation (Base Chain)

| Operation | Estimated Gas | Estimated Cost (Base) |
|-----------|---------------|------------------------|
| Deploy ZKMToken | ~1,200,000 | ~$0.05 |
| Deploy ZKMAirdropVerifier | ~4,500,000 | ~$0.20 |
| Deploy ZKMAirdrop | ~800,000 | ~$0.03 |
| Claim Transaction (Groth16 verify) | ~300,000 | ~$0.015 |
| Nullifier Storage (SSTORE cold) | ~20,000 | ~$0.001 |

> *Gas estimates based on Base average gas price of ~0.1 Gwei & ETH at $3,000.*
> *Groth16 verification is a fixed-cost operation (~300K gas) regardless of tree depth. This is significantly more expensive than a plain Merkle proof verification (~160K gas) but provides true zero-knowledge privacy.*

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
                    │  CLI / Desktop App:        │
                    │   ① Download list (IPFS)  │
                    │   ② Stream-build tree     │
                    │   ③ Extract Merkle proof   │
                    │   ④ Generate ZK proof      │
                    │      (circom + snarkjs)    │
                    │                            │
                    │  OR Web dApp (WASM):       │
                    │   ① Download proof chunk   │
                    │   ② Generate ZK proof      │
                    │                            │
                    └──────────┬───────────────┘
                               │ ZK proof + nullifier + recipient
                               ▼
                    ┌──────────────────────────┐
                    │  Base Chain               │
                    │                            │
                    │  ZKMAirdrop Contract:      │
                    │   • Verify Groth16 proof   │
                    │   • Check nullifier        │
                    │   • Transfer ZKM tokens    │
                    │                            │
                    │  On-chain:                 │
                    │   ✓ nullifier (opaque)     │
                    │   ✓ recipient address      │
                    │   ✗ qualified address      │
                    └──────────────────────────┘
```

---

*End of PRD v2.0*
