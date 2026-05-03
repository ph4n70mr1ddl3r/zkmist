# ZKMist (ZKM) — Product Requirements Document

**Version:** 5.0  
**Date:** 2026-05-03  
**Status:** Draft  
**Author:** ZKMist Community  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is a **fully community-owned, fairly launched** ERC-20 token on **Base Chain**. There is no team allocation, no treasury, no investor share, and no pre-mine. Every ZKM token in existence was claimed by a member of the Ethereum community through a privacy-preserving airdrop.

~65 million Ethereum addresses that paid ≥0.004 ETH in cumulative transaction fees on mainnet before 2026 are eligible. Each claimant receives **10,000 ZKM** — no more, no less. The token supply is determined entirely by how many people claim: up to **1 billion ZKM** across up to **1 million claimants**. Claims close at end of 2026 or when 1 million claims are reached, whichever comes first.

The claiming process is **anonymous** — the qualified address is never linked to the receiving address. Claimants generate zero-knowledge proofs locally using the RISC Zero zkVM and submit them to a fully immutable, adminless contract.

**ZKMist has no central team. The value of ZKM is built entirely by the community.**

### 1.2 Philosophy

| Principle | Implementation |
|-----------|---------------|
| **Fair** | Every claimant gets exactly 10,000 ZKM. No exceptions. No tiers. No insider allocation. |
| **Community-owned** | 100% of supply goes to claimants. Zero team tokens. Zero investor tokens. |
| **Anonymous** | Qualified address is never linked to receiving address on-chain. |
| **Immutable** | Contract has no admin, no owner, no pause, no upgrade. Deploy once, run forever. |
| **Permissionless** | Anyone can build relayers, UIs, tools, markets on top. No gatekeepers. |
| **Transparent** | Eligibility list, Merkle root, and guest program source are all public and auditable. |

### 1.3 Problem Statement

Standard airdrops are neither fair nor private. They create public links between qualifying and claiming addresses, expose user portfolios, and reserve large token allocations for teams and investors. ZKMist exists to prove that a token launch can be **entirely community-owned and privacy-preserving**.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Deploy ZKM as a fair-launch ERC-20 on Base | 100% of supply claimable by community |
| G2 | Enable anonymous claiming | Zero on-chain link between qualified and recipient address |
| G3 | Prevent double-claiming | Zero double-claims |
| G4 | Gas-efficient claim | < $0.50 per claim on Base |
| G5 | Fully immutable contract | No admin, no owner, no pause |
| G6 | Fair distribution | Every claimant receives exactly 10,000 ZKM |
| G7 | Permissionless ecosystem | Anyone can build relayers, UIs, tools |

### 2.2 Non-Goals

- No governance, staking, farming, or DeFi mechanics at launch.
- No web dApp from the project — the contract is the interface.
- No team, treasury, or investor allocation — ever.
- No dynamic eligibility list — fixed at deployment.
- No admin functions of any kind.

---

## 3. User Personas

### 3.1 Claimant (Primary User)

- Holds a qualified Ethereum address.
- Runs the CLI tool locally to generate a ZK proof.
- Submits the proof directly or via a relayer.
- Values privacy — qualified address must not be linked to recipient address.
- Is both a user and an owner of ZKM — there is no team.

### 3.2 Relayer Operator

- Builds a service that submits proofs on behalf of claimants.
- Pays gas for claimants (may charge a fee).
- Cannot tamper with claims (proof is bound to recipient).
- Operates permissionlessly.

### 3.3 Community Builder

- Creates UIs, dashboards, integrations, markets, or tools for ZKM.
- Has no special access — interacts with the same immutable contract as everyone else.
- Builds value for ZKM through ecosystem development.

### 3.4 Observer / Auditor

- Verifies the airdrop was fair and correctly executed.
- Reconstructs the Merkle tree from the published eligibility list.
- Reads and audits the Rust guest program source code.
- Confirms no double-claims occurred and supply matches claims.

---

## 4. Token Economics

### 4.1 Token Specifications

| Property | Value |
|----------|-------|
| **Name** | ZKMist |
| **Symbol** | ZKM |
| **Decimals** | 18 |
| **Max Supply** | 10,000,000,000 ZKM (10 billion) |
| **Initial Supply** | 0 ZKM (minted on claim) |
| **Chain** | Base (Ethereum L2) |
| **Standard** | ERC-20 |
| **Mintable** | Yes — algorithmically, only by the airdrop contract |
| **Burnable** | No |
| **Owner/Admin** | **None** |

### 4.2 Token Allocation

**There is no allocation. 100% of ZKM goes to claimants.**

| Recipient | % of Supply | Amount | Notes |
|-----------|-------------|--------|-------|
| **Claimants** | **100%** | Up to 10B ZKM | 10,000 ZKM × up to 1M claimants |
| Team | 0% | 0 | No team allocation |
| Treasury | 0% | 0 | No treasury |
| Investors | 0% | 0 | No investor allocation |
| Liquidity | 0% | 0 | Community provides liquidity if desired |
| Reserve | 0% | 0 | No reserve |

### 4.3 Per-Address Claim Amount

| Parameter | Value |
|-----------|-------|
| **ZKM per Claim** | **10,000 ZKM** (fixed, non-negotiable) |
| **Max Claimants** | **1,000,000** |
| **Max Total Supply** | 10,000 × 1,000,000 = **10,000,000,000 ZKM** |
| **Actual Supply** | Determined by claims: `supply = claimCount × 10,000` |

### 4.4 Claim Window

The claim window closes when **either** condition is met:

| Condition | Value |
|-----------|-------|
| **Time deadline** | `block.timestamp >= 2027-01-01 00:00:00 UTC` |
| **Claim cap** | `totalClaims >= 1,000,000` |

Whichever comes first.

### 4.5 Supply Scenarios

| Scenario | Claimants | Total Supply | % of Max |
|----------|-----------|-------------|----------|
| Low participation | 100,000 | 1,000,000,000 (1B) | 10% |
| Moderate | 500,000 | 5,000,000,000 (5B) | 50% |
| Full | 1,000,000 | 10,000,000,000 (10B) | 100% |
| Time expires at 750K | 750,000 | 7,500,000,000 (7.5B) | 75% |

> **No more ZKM will ever exist than what is claimed.** If only 300K people claim, the total supply is 3B ZKM — forever. No one can mint the remaining 7B. This is by design.

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

**Rationale:** 0.004 ETH (~$8–12 at average prices) filters out dust/spam while capturing virtually all real Ethereum users. Broad, inclusive, and Sybil-resistant — costly to fake at scale.

> **Note on contract wallets:** Smart contract addresses (multisigs, Safes, etc.) may appear in the eligibility list if they sent transactions meeting the fee threshold. However, they **cannot claim** because the claim protocol requires a private key to (1) derive the Ethereum address and (2) compute the nullifier. Contract wallets do not have a single private key, so they are effectively excluded. This is by design.

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
- `gas_price × receipt_gas_used` — actual gas fee paid. Accurate for both pre-EIP-1559 and EIP-1559 transactions.
- Processes **~2.5 billion rows**. Expected cost: ~$25–50 USD.

#### Export Pipeline

```
BigQuery SQL
    │
    ▼
Export to GCS (Google Cloud Storage)
    │   CSV, partitioned into ~65 files (1M rows each)
    ▼
Deduplicate & Normalize
    │   • Lowercase all addresses
    │   • Sort lexicographically
    ▼
Final Eligibility List
        Published to: IPFS (CID pinned), GitHub release
```

### 5.3 Merkle Tree

| Parameter | Value |
|-----------|-------|
| **Leaf** | `poseidon(address)` |
| **Depth** | 26 levels (65M leaves, padded to 2²⁶ = 67,108,864) |
| **Interior hash** | Poseidon |
| **Root** | Hardcoded in the airdrop contract |

### 5.4 Eligibility List Format

Published as chunked files on IPFS + GitHub mirror:

```
eligibility/
├── manifest.json              # Metadata
├── addresses_00000001.csv     # address (1M rows each, sorted)
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
  "claimAmountWei": "10000000000000000000000",
  "maxClaimants": 1000000,
  "claimDeadline": "2027-01-01T00:00:00Z",
  "merkleRoot": "0x...",
  "merkleTreeDepth": 26,
  "leafHashAlgorithm": "poseidon",
  "interiorHashAlgorithm": "poseidon",
  "files": [
    { "file": "addresses_00000001.csv", "sha256": "0x..." }
  ]
}
```

---

## 6. Anonymous Claim Protocol

### 6.1 Design Principles

1. **Local-only proof generation** — the private key never leaves the claimant's machine.
2. **Immutable contract** — no admin, no upgrades, no pause.
3. **Permissionless submission** — anyone can submit a valid proof or build a relayer.
4. **No trusted setup** — STARK-based proving. No ceremony, no toxic waste.
5. **Fair** — every claimant receives exactly 10,000 ZKM.
6. **Community-owned** — 100% of supply goes to claimants.

### 6.2 Why RISC Zero

| Factor | circom + Groth16 | RISC Zero zkVM |
|--------|------------------|----------------|
| **Address derivation** | ~400K constraints | Native Rust `k256` crate |
| **Trusted setup** | ❌ Required | ✅ **None** |
| **Code readability** | Constraints | Regular Rust |
| **Audit surface** | Custom gadgets | Standard Rust crypto |

### 6.3 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PUBLISHED DATA                         │
│                                                             │
│  Eligibility List (~65M addresses) on IPFS                  │
│  Merkle Root hardcoded in contract                          │
│  Guest program source on GitHub                             │
│                                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  CLAIMANT'S LOCAL MACHINE                    │
│                                                             │
│  $ zkmist prove                                             │
│    ① Download eligibility list (IPFS, ~1.3 GB)             │
│    ② Stream-build Merkle tree (O(log n) memory)            │
│    ③ Enter private key (hidden) + recipient address         │
│    ④ RISC Zero zkVM generates STARK proof                   │
│    ⑤ Save proof.json                                        │
│                                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │ proof.json
           ┌───────────────┴───────────────┐
           ▼                               ▼
  ┌─────────────────┐            ┌──────────────────┐
  │  Direct submit   │            │  Any relayer      │
  │  $ zkmist submit │            │  (permissionless) │
  └────────┬────────┘            └────────┬──────────┘
           │                              │
           └──────────────┬───────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 ZKMAirdrop (Base) — IMMUTABLE                │
│                                                             │
│  claim(proof, journal, nullifier, recipient)                │
│    • Verify STARK proof                                     │
│    • Validate journal (root + nullifier + recipient)        │
│    • Check nullifier unused                                 │
│    • Check claimCount < 1,000,000                           │
│    • Check block.timestamp < CLAIM_DEADLINE                 │
│    • MINT 10,000 ZKM to recipient                           │
│                                                             │
│  On-chain:                                                  │
│    ✗ qualified address — HIDDEN                             │
│    ✓ nullifier (opaque) + recipient                         │
│    ✓ totalClaims counter                                   │
│    No admin. No owner. No pause.                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.4 Nullifier Design

```
nullifier = sha256(privateKey || "ZKMist_V1_NULLIFIER")
```

| Property | Explanation |
|----------|-------------|
| **Deterministic** | Same private key → same nullifier → double-claim impossible |
| **Not precomputable** | Requires the private key, not in the published list |
| **Not reversible** | Cannot recover key or address from nullifier |
| **Unique per address** | Different keys → different nullifiers |

### 6.5 Guest Program (Rust)

```rust
//! ZKMist Airdrop Claim — RISC Zero Guest Program

#![no_main]
risc0_zkvm::guest::entry!(main);

use sha2::{Digest, Sha256};

const TREE_DEPTH: usize = 26;
const DOMAIN_SEPARATOR: &[u8] = b"ZKMist_V1_NULLIFIER";

pub fn main() {
    // === Public inputs (committed to journal) ===
    let merkle_root: [u8; 32] = env::read();
    let nullifier: [u8; 32] = env::read();
    let recipient: [u8; 20] = env::read();

    // === Private inputs ===
    let private_key: [u8; 32] = env::read();

    // Derive Ethereum address
    let address = derive_address(&private_key);

    // Merkle membership proof
    let mut siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices: [bool; TREE_DEPTH] = [false; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        siblings[i] = env::read();
        path_indices[i] = env::read();
    }

    // Verify Merkle membership
    let leaf = poseidon_hash_address(&address);
    let computed_root = compute_merkle_root(&leaf, &siblings, &path_indices);
    assert_eq!(computed_root, merkle_root, "Not in eligibility tree");

    // Verify nullifier
    let expected = compute_nullifier(&private_key);
    assert_eq!(nullifier, expected, "Invalid nullifier");

    // Commit outputs
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

fn derive_address(key: &[u8; 32]) -> [u8; 20] {
    let sk = k256::ecdsa::SigningKey::from_bytes(key).expect("Invalid key");
    let vk = k256::ecdsa::VerifyingKey::from(&sk);
    let point = vk.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn compute_nullifier(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(DOMAIN_SEPARATOR);
    h.finalize().into()
}
```

### 6.6 Claim Flow (Step-by-Step)

1. **Download eligibility list** — `zkmist fetch` downloads from IPFS (~1.3 GB). Cached locally.

2. **Generate proof** — `zkmist prove`:
   - Prompts for private key (hidden input)
   - Prompts for recipient address
   - Stream-builds Merkle tree (~1–2 min)
   - Runs RISC Zero zkVM (~30–90s)
   - Saves `proof.json`

3. **Submit claim** — one of:
   - **Direct:** `zkmist submit proof.json`
   - **Relayer:** send proof.json to any relayer service
   - **Manual:** submit via BaseScan or any contract interaction tool

4. **Contract mints 10,000 ZKM** to the recipient address. On-chain observers see only a nullifier, a recipient, and a ZK proof. **Nothing links to the qualified address.**

### 6.7 Privacy Guarantees

| Public on-chain | Hidden |
|-----------------|--------|
| STARK proof | Qualified address |
| Nullifier (opaque hash) | Private key |
| Recipient address | Merkle proof / tree position |
| Claim amount (10,000 ZKM for all) | Link between qualified ↔ recipient |

### 6.8 Privacy Caveats

| Risk | Mitigation |
|------|------------|
| Gas funding correlation | Tool warns: fund recipient from independent source |
| Relayer sees proof | Sees same data as on-chain — no additional info |
| Front-running | Impossible — recipient bound to proof |

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description | Mutability |
|----------|-------------|------------|
| `ZKMToken` | ERC-20 with max supply, mintable only by airdrop | Immutable owner (no admin functions) |
| `RiscZeroVerifier` | RISC Zero STARK verifier | Immutable |
| `ZKMAirdrop` | Claim contract — verify proof + mint tokens | **Immutable** (no admin, no owner, no pause) |

### 7.2 ZKMToken Contract

```
ERC-20:
  - name: "ZKMist"
  - symbol: "ZKM"
  - decimals: 18
  - maxSupply: 10,000,000,000e18
  - initialSupply: 0 (minted on claim)
  - mint(): only callable by ZKMAirdrop contract
  - No burn, no owner functions
```

```solidity
contract ZKMToken is ERC20 {
    uint256 public constant MAX_SUPPLY = 10_000_000_000e18;
    address public immutable minter;

    constructor(address _minter) ERC20("ZKMist", "ZKM") {
        minter = _minter;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Only airdrop contract");
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }
}
```

### 7.3 ZKMAirdrop Contract

**Fully immutable.** No admin, no owner, no pause, no upgrade.

```solidity
contract ZKMAirdrop {
    ZKMToken public immutable token;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    bytes32 public immutable merkleRoot;
    uint256 public constant CLAIM_AMOUNT = 10_000e18;     // 10,000 ZKM
    uint256 public constant MAX_CLAIMS = 1_000_000;
    uint256 public constant CLAIM_DEADLINE = 1_798_761_600;  // 2027-01-01 00:00:00 UTC

    uint256 public totalClaims;
    mapping(bytes32 => bool) public usedNullifiers;

    constructor(
        address _token,
        address _verifier,
        bytes32 _imageId,
        bytes32 _merkleRoot
    ) {
        token = ZKMToken(_token);
        verifier = IRiscZeroVerifier(_verifier);
        imageId = _imageId;
        merkleRoot = _merkleRoot;
    }

    function claim(
        bytes calldata _proof,
        bytes calldata _journal,
        bytes32 _nullifier,
        address _recipient
    ) external {
        // Check claim window
        require(block.timestamp < CLAIM_DEADLINE, "Claim period ended");
        require(totalClaims < MAX_CLAIMS, "Claim cap reached");
        require(!usedNullifiers[_nullifier], "Already claimed");

        // Verify RISC Zero proof
        bytes32 journalDigest = bytes32(sha256(_journal));
        verifier.verify(_proof, imageId, journalDigest);

        // Validate journal
        require(bytes32(_journal[0:32])  == merkleRoot,  "Root mismatch");
        require(bytes32(_journal[32:64]) == _nullifier,  "Nullifier mismatch");
        require(address(bytes20(_journal[64:84])) == _recipient, "Recipient mismatch");

        // Mark claimed and mint
        usedNullifiers[_nullifier] = true;
        totalClaims++;
        token.mint(_recipient, CLAIM_AMOUNT);

        emit Claimed(_nullifier, CLAIM_AMOUNT, _recipient, totalClaims);
    }

    // View helpers
    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
    function claimsRemaining() external view returns (uint256) {
        return MAX_CLAIMS - totalClaims;
    }
    function isClaimWindowOpen() external view returns (bool) {
        return block.timestamp < CLAIM_DEADLINE && totalClaims < MAX_CLAIMS;
    }

    event Claimed(
        bytes32 indexed nullifier,
        uint256 amount,
        address indexed recipient,
        uint256 totalClaims
    );
}
```

**Key properties:**
- Tokens are **minted on claim** — no pre-mine, no leftover tokens.
- `totalClaims` is public — anyone can see how many have claimed.
- `MAX_CLAIMS = 1,000,000` — enforced on-chain. After 1M claims, no more ZKM can ever exist.
- `CLAIM_DEADLINE` — hardcoded constant. After 2027-01-01, no more ZKM can ever be minted.
- `MAX_SUPPLY = 10,000,000,000 ZKM` on the token contract — hard cap, can never be exceeded.
- `msg.sender` is not used for verification — anyone can submit.
- No admin, owner, pause, or upgrade functions exist.

### 7.4 On-Chain Read Queries

| Query | Function | Returns |
|-------|----------|---------|
| Is claim window open? | `isClaimWindowOpen()` | `bool` |
| Claims remaining? | `claimsRemaining()` | `uint256` |
| Total claims so far? | `totalClaims` | `uint256` |
| Has this nullifier claimed? | `isClaimed(bytes32)` | `bool` |
| Total ZKM supply? | `token.totalSupply()` | `uint256` |
| Max ZKM supply? | `token.MAX_SUPPLY` | `uint256` |

---

## 8. CLI Tool

### 8.1 Commands

```
zkmist fetch                  Download eligibility list from IPFS (~1.3 GB)
zkmist prove                  Generate ZK proof (interactive)
zkmist submit <proof.json>    Submit proof to ZKMAirdrop contract
zkmist verify <proof.json>    Verify proof locally (dry run)
zkmist check <address>        Check if address is eligible
zkmist status                 Show claim window status, claims remaining, total supply
```

### 8.2 `zkmist prove`

```
$ zkmist prove

[1/4] Loading eligibility list...
       Using cached list: ~/.zkmist/eligibility/

[2/4] Building Merkle tree...
       Processing 65,000,000 addresses... done (1m 23s)
       Found your address at index 42,317,891
       ✓ Root matches on-chain: 0xabc123...

[3/4] Enter credentials:
       Private key (hidden): ********
       → Address: 0x742d...35Cc ✓ Eligible
       → Nullifier: 0x4a7f...e2c1

       Recipient address: 0xRecip...EntAddress

[4/4] Generating proof...
       Guest: zkmist-claim-v1 | Cycles: 2,847,331
       ████████████████████████████████ done (45s)

       ✓ Proof saved: ./zkmist_proof_2026-05-03.json

       10,000 ZKM will be minted to 0xRecip...EntAddress on claim.
       Run: zkmist submit ./zkmist_proof_2026-05-03.json
       Or send to any relayer.
```

### 8.3 `zkmist status`

```
$ zkmist status

ZKMist (ZKM) on Base
──────────────────────────────────────
Contract:       0xAirdrop...Contract
Claim amount:   10,000 ZKM per claim
Total claimed:  347,219
Claims left:    652,781 / 1,000,000
Total supply:   3,472,190,000 ZKM (34.7% of max)
Deadline:       2027-01-01 00:00:00 UTC (243 days remaining)
Status:         ✅ OPEN
```

### 8.4 Proof File Format

```json
{
  "version": 1,
  "proof": "0x...stark_proof_hex",
  "journal": "0x...journal_hex",
  "nullifier": "0x4a7f...e2c1",
  "recipient": "0xRecip...EntAddress",
  "claimAmount": "10000000000000000000000",
  "contractAddress": "0xAirdrop...Contract",
  "chainId": 8453
}
```

Self-contained. Anyone can submit it. Relayer cannot modify any field.

### 8.5 Relayer Ecosystem

```
Anyone can build a relayer:
  1. Accept proof.json from claimants (API, bot, web form)
  2. Validate proof locally (optional)
  3. Submit claim on Base, paying gas
  4. May charge a fee

Cannot:
  - Modify recipient (proof invalid)
  - Claim tokens for themselves
  - Learn the qualified address
```

### 8.6 Technology Stack

| Layer | Choice |
|-------|--------|
| zkVM | RISC Zero (risc0-zkvm) |
| Guest Program | Rust (RISC-V) |
| Proof System | STARK (RISC Zero) |
| Crypto | `k256`, `sha2`, `tiny-keccak` |
| CLI | Rust |
| Chain | Base (8453) |
| Data | IPFS + GitHub |

---

## 9. Timeline

| Phase | Description |
|-------|-------------|
| T-30d | BigQuery extraction finalized, list published |
| T-14d | List + Merkle root + guest program source published for audit |
| T-7d | Contracts deployed on Base |
| T+0 | Claims open |
| T+90d or 1M claims | Claims close (whichever comes first) |
| Post-close | Contract remains immutable forever. No more ZKM can be minted. |

---

## 10. Security

### 10.1 Smart Contract Security

| Measure | Details |
|---------|---------|
| **Audit** | External audit before mainnet |
| **Test Coverage** | ≥ 95% |
| **Guest Program Audit** | Rust source (~80 lines of logic) |
| **Immutability** | No admin, no owner, no pause — security through simplicity |
| **No admin keys** | Nothing to compromise |

### 10.2 Privacy

| Measure | Details |
|---------|--------|
| Private key stays local | zkVM runs entirely on claimant's machine |
| No server dependency | All data on IPFS |
| No trusted setup | STARK-based |
| Deterministic nullifier | Prevents double-claim |
| Front-running impossible | Recipient committed to proof |

### 10.3 Fairness

| Guarantee | Mechanism |
|-----------|-----------|
| **No insider allocation** | 100% minted on claim. No pre-mine. |
| **Equal amounts** | 10,000 ZKM per claimant — hardcoded constant |
| **Transparent eligibility** | Published list, auditable Merkle tree |
| **Immutable rules** | Contract cannot be changed after deployment |
| **Capped supply** | 10B ZKM max — enforced on-chain |
| **Deadline enforced** | No claims after 2027-01-01 — enforced on-chain |

---

## 11. Technical Specifications

| Spec | Value |
|------|-------|
| **Chain** | Base (8453) |
| **Token** | ZKMist (ZKM), ERC-20, 18 decimals |
| **Max Supply** | 10,000,000,000 ZKM (10 billion) |
| **Initial Supply** | 0 (minted on claim) |
| **Claim Amount** | 10,000 ZKM (fixed) |
| **Max Claims** | 1,000,000 |
| **Claim Deadline** | 2027-01-01 00:00:00 UTC |
| **Proof System** | RISC Zero zkVM (STARK) |
| **Trusted Setup** | **None** |
| **Merkle Tree** | 26 levels, Poseidon (leaf + interior) |
| **Nullifier** | sha256(privateKey ∥ "ZKMist_V1_NULLIFIER") |
| **Gas per claim** | ~300,000 (~0.00003 ETH / ~$0.09) via Groth16 wrapper |
| **Contract** | Fully immutable, no admin |
| **Eligibility** | ≥0.004 ETH gas fees, mainnet, before 2026-01-01 |
| **Qualified** | ~65,000,000 addresses |
| **Data** | IPFS + GitHub |

---

## 12. Milestones

| # | Milestone | Duration |
|---|-----------|----------|
| 1 | Final BigQuery extraction & validation | Week 1 |
| 2 | Merkle tree build + publish to IPFS | Week 2 |
| 3 | RISC Zero guest program + testing | Weeks 2–3 |
| 4 | Smart contracts (ZKMToken + ZKMAirdrop) | Weeks 3–4 |
| 5 | CLI tool (fetch → prove → submit) | Weeks 3–4 |
| 6 | Internal security review + testnet | Week 5 |
| 7 | External audit | Weeks 5–7 |
| 8 | Deploy to Base mainnet | Week 8 |
| 9 | Publish all artifacts | Week 8 |
| 10 | Claim window (up to 90 days or 1M claims) | Weeks 8–21 |

---

## 13. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | Eligibility criteria? | ✅ ≥0.004 ETH gas fees, mainnet, before 2026-01-01 |
| 2 | Claim amount? | ✅ 10,000 ZKM fixed |
| 3 | Max claims? | ✅ 1,000,000 |
| 4 | Deadline? | ✅ 2027-01-01 00:00:00 UTC |
| 5 | Supply model? | ✅ Mint on claim, max 10B |
| 6 | Allocation? | ✅ 100% community, zero team/investor/treasury |
| 7 | Contract mutability? | ✅ Fully immutable |
| 8 | Proof system? | ✅ RISC Zero zkVM |
| 9 | Unclaimed supply? | ✅ Never minted. Supply = claims × 10,000. |
| 10 | Exact qualified count after final BigQuery run? | 🔲 Pending |
| 11 | Keccak256 in guest program for address derivation? | 🔲 Pending (recommend: yes) |
| 12 | Contract addresses (multisigs) eligible? | ✅ Ineligible by design — claiming requires a private key to derive address + generate nullifier. Contract wallets appear in the list but cannot claim. |

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **Nullifier** | sha256(privateKey ∥ domain). Prevents double-claim without revealing the qualified address. |
| **Merkle Tree** | 26-level binary hash tree. Leaves are poseidon(address). Root on-chain. |
| **RISC Zero** | Zero-knowledge VM proving correct Rust program execution. |
| **Guest Program** | Rust program inside RISC Zero. Proves membership + nullifier validity. |
| **Journal** | Public output: [merkleRoot, nullifier, recipient]. |
| **Image ID** | Hash of guest program binary. Hardcoded in contract. |
| **STARK** | Proof system requiring no trusted setup. |
| **Fair Launch** | 100% of supply goes to claimants. No pre-mine, no insider allocation. |
| **Relayer** | Third party submitting proofs on behalf of claimants. Permissionless. |

---

## 15. Appendix

### A. References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [RISC Zero Examples](https://github.com/risc0/risc0/tree/main/examples)
- [k256 crate (secp256k1)](https://crates.io/crates/k256)

### B. Gas Estimates (Base)

Assumptions: Base gas price ~0.1 Gwei, ETH at $3,000.

| Operation | Gas | ETH | USD |
|-----------|-----|-----|-----|
| Deploy ZKMToken | ~1,200,000 | ~0.000012 ETH | ~$0.04 |
| Deploy Verifier | ~6,000,000 | ~0.00006 ETH | ~$0.18 |
| Deploy ZKMAirdrop | ~1,000,000 | ~0.00001 ETH | ~$0.03 |
| **Claim** | **~300,000** | **~0.00003 ETH** | **~$0.09** |

The user always generates a **RISC Zero STARK proof** locally. The contract internally compresses it using a **Groth16 wrapper** for cheap on-chain verification (~300K gas instead of ~1.5M). This is transparent to the user — they don't choose or know about it. At 1M claims this saves the community **~$360K** in gas.

### C. Architecture

```
  IPFS (eligibility list)
       │
       ▼
  Local CLI
  $ zkmist prove → proof.json
       │
  ┌────┴────────────┐
  ▼                  ▼
Direct          Any Relayer
  │                  │
  └────────┬─────────┘
           ▼
  ZKMAirdrop (IMMUTABLE)
  ┌──────────────────────┐
  │ claim()              │
  │  verify proof        │
  │  check nullifier     │
  │  check claimCount    │
  │  check deadline      │
  │  MINT 10,000 ZKM     │
  │                      │
  │  No admin. No owner. │
  │  Supply = claims × 10K│
  └──────────────────────┘
```

---

*End of PRD v5.0*
