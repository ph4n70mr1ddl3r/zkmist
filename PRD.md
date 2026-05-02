# ZKMist (ZKM) — Product Requirements Document

**Version:** 1.1  
**Date:** 2026-05-03  
**Status:** Draft  
**Author:** ZKMist Team  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is an ERC-20 token deployed on **Base Chain** featuring a **privacy-preserving airdrop** mechanism. A predefined list of qualified Ethereum addresses are eligible to claim ZKM tokens, but the claiming process is designed so that **the qualified address is never publicly linked to the receiving address**. This is achieved through zero-knowledge proof technology, allowing claimants to prove eligibility without revealing their identity.

### 1.2 Problem Statement

Standard airdrops create a permanent, public on-chain link between a user's qualifying activity (original address) and their claiming address. This:

- **Exposes user portfolios** — anyone can trace a claim back to the qualifying address and inspect its full history and holdings.
- **Creates targeting risk** — whales or early adopters become visible targets for phishing, social engineering, or legal scrutiny.
- **Discourages participation** — privacy-conscious users may avoid claiming airdrops they are entitled to.

### 1.3 Solution

ZKMist uses a **Merkle-tree-based anonymous claim protocol** with **nullifiers**. Qualified addresses generate a zero-knowledge proof (or an off-chain Merkle proof + nullifier scheme) that:

1. Proves they control an address in the eligibility Merkle tree.
2. Reveals only a **nullifier** (a unique, one-time-use derived value) to prevent double-claiming.
3. Specifies a **separate receiving address** that has no on-chain link to the original qualified address.

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

### 6.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         OFF-CHAIN                            │
│                                                              │
│  Google BigQuery ──► Eligibility List (~65M addresses)       │
│                            │                                 │
│                            ▼                                 │
│                  Merkle Tree Builder (server)                │
│                  • 65M leaves, depth 26                      │
│                  • Sorted lexicographically                 │
│                  • Root stored on-chain                      │
│                  • Tree stored in database / KV store        │
│                            │                                 │
│         ┌─────────────────┼──────────────────┐              │
│         ▼                 ▼                   ▼              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Proof API   │  │  Eligibility │  │  Relayer     │       │
│  │  (per-addr   │  │  Checker     │  │  Service     │       │
│  │   Merkle     │  │  (lookup)    │  │  (submits    │       │
│  │   proof)     │  │              │  │   claims)    │       │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘       │
│         │                                   │               │
└─────────┼───────────────────────────────────┼───────────────┘
          │                                   │
          ▼                                   ▼
┌─────────────────────────────────────────────────────────────┐
│                       ON-CHAIN (Base)                        │
│                                                              │
│  ┌───────────────┐      ┌──────────────────────┐            │
│  │  ZKM Token    │◄─────│  ZKMAirdrop Claim    │            │
│  │  (ERC-20)     │      │  Contract            │            │
│  └───────────────┘      └──────────────────────┘            │
│                              │                               │
│         Verifies:            │                               │
│          • Merkle proof      │                               │
│            (26 levels)       │                               │
│          • Nullifier not     │                               │
│            previously used   │                               │
│          • Transfers tokens  │                               │
│            to receiving addr │                               │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 Privacy Mechanism — Nullifier Design

The core privacy guarantee relies on a **nullifier** — a one-way derived value that:

- **Uniquely identifies a qualified address** without revealing it.
- **Prevents double-claiming** — once a nullifier is used, it cannot be reused.
- **Cannot be reversed** to recover the original qualified address.

#### Nullifier Derivation (Option A — Hash-based)

```
nullifier = keccak256(abi.encodePacked(qualifiedAddress, secretSalt))
```

- The claimant generates a random `secretSalt` (32 bytes).
- The contract stores `usedNullifiers[nullifier] = true` after a claim.
- The Merkle proof proves that `qualifiedAddress` is in the tree.
- **On-chain, only the `nullifier` and `receivingAddress` are visible.**
- An observer cannot map `nullifier` → `qualifiedAddress` without knowing the salt.

#### Nullifier Derivation (Option B — ZK Proof / Semaphore-style)

```
nullifier = hash(secret, merkleRoot)
```

- Uses a full zero-knowledge circuit (e.g., circom/Semaphore).
- The ZK proof proves membership in the Merkle tree without revealing which leaf.
- **Stronger privacy** but higher implementation complexity.

> **Recommendation:** Start with Option A (hash-based nullifier) for speed and lower gas cost. Upgrade to Option B (ZK circuit) in a future version if stronger privacy guarantees are needed.
>
> **At 65M addresses**, Option B (ZK circuit) would require proving membership in a 2²⁶-leaf Merkle tree inside a ZK circuit — this is feasible (Semaphore supports large trees) but adds significant complexity and proof generation time (~10–30s on consumer hardware). Option A is strongly recommended for v1.

### 6.3 Claim Flow (Step-by-Step)

1. **Connect Wallet** — Claimant connects the wallet containing their qualified Ethereum address to the ZKMist claim dApp.

2. **Generate Nullifier** — The dApp generates a random `secretSalt` locally and derives the `nullifier`. The salt is stored in the browser's `localStorage` (and optionally encrypted with a password for backup).

3. **Fetch Merkle Proof** — The dApp (or a backend API) looks up the claimant's `qualifiedAddress` in the published eligibility list and generates the corresponding Merkle proof (sibling hashes from leaf to root).

4. **Specify Receiving Address** — The claimant enters or connects a **different** Base address where they want to receive ZKM tokens. This can be a fresh, never-used address for maximum privacy.

5. **Submit Claim Transaction** — The dApp calls `claim(merkleProof, nullifier, amount, receivingAddress)` on the ZKMAirdrop contract on Base.

6. **Contract Verification:**
   - Verify `merkleProof` is valid for `merkleRoot` and corresponds to `keccak256(qualifiedAddress, amount)`. *(Note: the qualifiedAddress is reconstructed from the proof and verified but never emitted in an event.)*
   - Check `usedNullifiers[nullifier] == false`.
   - Set `usedNullifiers[nullifier] = true`.
   - Transfer `amount` ZKM to `receivingAddress`.

7. **Completion** — Tokens arrive in the receiving address. On-chain, observers see only: a nullifier, a receiving address, and a token transfer — **no link to the original qualified address**.

### 6.4 Privacy Guarantees

| What is public on-chain | What is NOT public on-chain |
|--------------------------|-----------------------------|
| Nullifier hash | Qualified (original) address |
| Receiving address | Secret salt |
| Claim amount (uniform — 7.69 ZKM for all) | Merkle proof details (calculated off-chain) |
| Claim timestamp | Link between qualified ↔ receiving address |

**Uniform amount = strongest anonymity set.** With 65M addresses all receiving the same amount, the claim amount reveals nothing. Every claim looks identical on-chain except for the nullifier and receiving address.

### 6.5 Privacy Caveats & Edge Cases

| Risk | Mitigation |
|------|------------|
| **Time correlation** — if a claimant transfers ETH for gas from their qualified address to their receiving address in the same timeframe, the addresses can be linked. | dApp should warn users to fund the receiving address from an independent source (e.g., a CEX withdrawal, bridge). |
| **Uniform amounts eliminate this vector entirely.** All 65M addresses receive the same 7.69 ZKM. No deanonymization via amount. | ✅ Resolved by uniform allocation. |
| **Nullifier collision** — theoretical chance of two addresses generating the same nullifier. | Use 256-bit hash; probability is negligible. |
| **Front-running** — an observer sees the pending tx and could try to extract info. | The nullifier and receiving address are the only visible parameters; no useful info is leaked. |

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description |
|----------|-------------|
| `ZKMToken` | Standard ERC-20 token contract for ZKMist |
| `ZKMAirdrop` | Claim contract with Merkle verification + nullifier tracking |
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
| `claim(bytes32[] proof, bytes32 nullifier, uint256 amount, address receiving)` | Public | Claim tokens. Verifies Merkle proof + nullifier uniqueness. |
| `pause()` | Admin | Pause claims (emergency). |
| `unpause()` | Admin | Unpause claims. |
| `withdrawUnclaimed()` | Admin | After claim period ends, withdraw remaining tokens to treasury. |
| `usedNullifiers(bytes32)` | View | Check if a nullifier has been used. |
| `isClaimed(bytes32)` | View | Alias for nullifier check. |

#### Claim Function Pseudocode

```solidity
// The claim amount is a constant — same for all 65M addresses
uint256 public constant CLAIM_AMOUNT = 7_692_307_000_000_000_000; // ~7.69 ZKM

function claim(
    bytes32[] calldata _proof,
    bytes32 _nullifier,
    address _receiving
) external {
    require(!paused, "Claims paused");
    require(block.timestamp >= claimStart, "Not started");
    require(block.timestamp <= claimEnd, "Claim period ended");
    require(!usedNullifiers[_nullifier], "Already claimed");

    // Reconstruct leaf: hash of (qualifiedAddress, CLAIM_AMOUNT)
    // The qualifiedAddress is msg.sender
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, CLAIM_AMOUNT));

    // Verify Merkle proof (26 levels for 65M leaves)
    require(MerkleProof.verify(_proof, merkleRoot, leaf), "Invalid proof");

    // Mark nullifier as used
    usedNullifiers[_nullifier] = true;

    // Transfer tokens to receiving address
    zkmToken.transfer(_receiving, CLAIM_AMOUNT);

    emit Claimed(_nullifier, CLAIM_AMOUNT, _receiving);
}
```

> **Important Design Note:** In the above, `msg.sender` must be the qualified address. The claim transaction is submitted **from** the qualified address **on Base Chain**. This means:
> - The qualified address must have ETH on Base for gas.
> - The transaction origin (`msg.sender`) is visible on Base — but Base is a separate chain from Ethereum mainnet, so the linkage is cross-chain and not trivially discoverable.
> - For **maximum anonymity**, use the nullifier-based design where the qualified address merely signs an EIP-712 message off-chain, and a **relayer** submits the claim on-chain. The contract verifies the signature, not `msg.sender`.

#### Enhanced Privacy — EIP-712 Signed Claim (Recommended)

```solidity
uint256 public constant CLAIM_AMOUNT = 7_692_307_000_000_000_000; // ~7.69 ZKM

function claim(
    bytes32[] calldata _proof,
    bytes32 _nullifier,
    address _receiving,
    bytes32 _salt,
    bytes calldata _signature  // EIP-712 sig from qualified address
) external {
    require(!paused, "Claims paused");
    require(block.timestamp >= claimStart, "Not started");
    require(block.timestamp <= claimEnd, "Claim period ended");
    require(!usedNullifiers[_nullifier], "Already claimed");

    // Recover signer from EIP-712 typed signature
    // The signed message includes: nullifier, receiving, salt, claimAmount
    address signer = ECDSA.recover(_hashTypedDataV4(structHash), _signature);

    // Verify signer is in the Merkle tree
    bytes32 leaf = keccak256(abi.encodePacked(signer, CLAIM_AMOUNT));
    require(MerkleProof.verify(_proof, merkleRoot, leaf), "Invalid proof");

    // Verify nullifier was derived correctly from signer + salt
    bytes32 expectedNullifier = keccak256(abi.encodePacked(signer, _salt));
    require(_nullifier == expectedNullifier, "Invalid nullifier");

    // Mark nullifier as used
    usedNullifiers[_nullifier] = true;

    // Transfer tokens to receiving address
    zkmToken.transfer(_receiving, CLAIM_AMOUNT);

    emit Claimed(_nullifier, CLAIM_AMOUNT, _receiving);
}
```

With this design, **anyone (a relayer) can submit the claim tx**, and `msg.sender` on Base is the relayer — **not the qualified address**. The qualified address only needs to sign a message off-chain (free, no gas).

### 7.4 Events

```solidity
event Claimed(bytes32 indexed nullifier, uint256 amount, address indexed receiving);
event Paused();
event Unpaused();
event Withdrawn(address to, uint256 amount);
```

### 7.5 Merkle Proof Serving Infrastructure

With **65M addresses**, the Merkle tree has **26 levels** and the raw tree data is ~**2–4 GB**. Merkle proofs **cannot** be generated client-side from a downloaded file — the data is too large for browsers. A dedicated proof-serving infrastructure is required.

| Component | Description |
|-----------|------------|
| **Tree Storage** | Merkle tree stored in a key-value store (LevelDB / RocksDB / PostgreSQL). Indexed by address → leaf index. |
| **Proof API** | REST endpoint: `GET /api/proof/:address` → returns the 26-element Merkle proof array. Response: ~832 bytes. |
| **Caching** | CDN-cached (Cloudflare) proof responses. Proofs are static and immutable. |
| **Redundancy** | Proof data + tree published to IPFS. Community can run independent proof servers. |
| **Fallback** | Pre-computed proof dump as chunked files on IPFS for fully trustless offline verification. |

#### Proof API Specification

```
GET /api/proof/0xAbC...123

Response (200 OK):
{
  "address": "0xAbC...123",
  "eligible": true,
  "claimAmount": "7692307000000000000",
  "proof": [
    "0x...sibling1",
    "0x...sibling2",
    ...  (26 elements)
    "0x...sibling26"
  ],
  "leaf": "0x...",
  "merkleRoot": "0x..."
}

Response (404):
{
  "address": "0xDeF...789",
  "eligible": false
}
```

#### Merkle Tree Construction

```
1. Sort all 65M addresses lexicographically.
2. Pad to next power of 2 (2^26 = 67,108,864) with zero-value leaves.
3. Leaf = keccak256(abi.encodePacked(address, claimAmount))
4. Build binary tree bottom-up:
   node = keccak256(abi.encodePacked(leftChild, rightChild))
5. Root = top-level hash → hardcoded in smart contract.
6. Store tree in DB with address → (leafIndex, proof[]) mapping.
```

> **Estimated resources:** Building the 65M-leaf tree takes ~2–5 minutes on a modern server (32GB RAM). Storage: ~4GB on disk. Proof generation per query: <1ms.

---

## 8. Frontend / dApp

### 8.1 Pages

| Page | Description |
|------|-------------|
| **Landing** | Overview, token info, links |
| **Check Eligibility** | Enter address → see if qualified + claim amount |
| **Claim** | Step-by-step anonymous claim flow (connect wallet → generate nullifier → specify receiving address → submit) |
| **Dashboard** | Live stats: total claimed, unique nullifiers, time remaining |
| **FAQ** | Privacy explanation, troubleshooting |

### 8.2 Claim Flow UX

```
Step 1: "Connect Qualified Wallet"
        └─ Connects the wallet holding the eligible Ethereum mainnet address
        └─ dApp queries Proof API: GET /api/proof/:connectedAddress
        └─ If 404 → "This address is not eligible" (paid < 0.004 ETH in fees)

Step 2: "Verify Eligibility" ✓
        └─ Shows: "You are eligible for ~7.69 ZKM tokens"
        └─ Shows: "Your address paid X ETH in cumulative fees on Ethereum mainnet"
        └─ Generates nullifier (random 32-byte salt, stored in localStorage)

Step 3: "Choose Receiving Address"
        └─ Option A: Connect a different wallet (on Base)
        └─ Option B: Paste any Base address manually
        └─ ⚠️ Warning: "Do not fund this address from your qualified wallet"
        └─ ⚠️ Warning: "Do not send ETH from your qualified address to this address"

Step 4: "Submit Claim"
        └─ Option A (recommended): Sign EIP-712 message (free) + relayer submits
           └─ User signs: {nullifier, receivingAddress, salt, claimAmount}
           └─ Relayer submits tx on Base — msg.sender is the relayer, not user
        └─ Option B: Pay gas on Base directly (~$0.005)
           └─ User must have ETH on Base in their qualified address

Step 5: "Claim Complete!" ✓
        └─ Shows tx hash, link to BaseScan
        └─ Shows: "Your qualified address is NOT linked to your receiving address"
        └─ Shows: "Keep your secret salt safe — it's needed to prove you claimed"
```

### 8.3 Technology Stack

| Layer | Choice |
|-------|--------|
| Framework | Next.js / React |
| Wallet Connect | RainbowKit / wagmi / viem |
| Chain | Base (Chain ID: 8453) |
| Merkle Proofs | Fetched from Proof API (not client-side — tree is too large for browsers) |
| Proof API | Node.js / Go REST API backed by LevelDB / PostgreSQL |
| Relayer (optional) | Gelato / OpenZeppelin Defender / custom |
| Hosting (dApp) | Vercel / IPFS |
| Hosting (Proof API) | Cloudflare Workers / Railway / dedicated VPS |
| CDN | Cloudflare (cache proof responses) |
| Style | TailwindCSS |

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
| **Client-side Salt Generation** | Nullifier salt is generated in-browser, never sent to a server |
| **No Server-Side Logging** | dApp makes no API calls that link qualified address to nullifier |
| **CORS / CSP Headers** | Strict security headers on dApp |
| **Relayer Privacy** | Relayer does not log IP addresses or request parameters |
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
| **Merkle Tree Hash** | keccak256 (double) |
| **Merkle Tree Depth** | 26 levels (65M leaves, padded to 2²⁶) |
| **Merkle Proof Size** | 26 × 32 bytes = 832 bytes per claim |
| **Nullifier Scheme** | keccak256(qualifiedAddress ∥ secretSalt) |
| **Claim Amount** | 7.69 ZKM (constant — uniform for all 65M addresses) |
| **Claim Verification** | Merkle proof (26 levels) + nullifier uniqueness |
| **Claim Method** | EIP-712 signature + relayer (recommended) |
| **Claim Period** | 90 days |
| **Gas Target** | < $0.50 per claim |
| **Solidity Version** | ^0.8.24 |
| **Contract Size Target** | < 24KB (deployment limit) |
| **Eligibility Data Source** | Google BigQuery (`bigquery-public-data.crypto_ethereum`) |
| **Qualified Addresses** | ~65,000,000 |

---

## 12. Milestones & Deliverables

| # | Milestone | Estimated Duration |
|---|-----------|---------------------|
| 1 | Run final BigQuery extraction & validate ~65M address list | Week 1 |
| 2 | Build Merkle tree (26-level, 65M leaves), store to DB, compute root | Week 2 |
| 3 | Develop & test smart contracts (ZKMToken + ZKMAirdrop with constant claim amount) | Weeks 2–3 |
| 4 | Build Proof API + deploy to production with CDN caching | Week 3 |
| 5 | Internal security review + testnet deployment | Week 4 |
| 6 | External audit | Weeks 4–6 |
| 7 | Build frontend dApp (eligibility checker + claim flow) | Weeks 3–5 (parallel) |
| 8 | Set up relayer service (if applicable) | Week 5 |
| 9 | Deploy to Base mainnet | Week 7 |
| 10 | Open claim window | Week 7 |
| 11 | Close claim window + withdraw unclaimed | Week 20 |
| 12 | Renounce admin / decentralize | Week 21 |

---

## 13. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | What is the exact eligibility criteria / snapshot source? | ✅ **Resolved** — ≥ 0.004 ETH cumulative gas fees on Ethereum mainnet before 2026-01-01 UTC. Data from Google BigQuery. ~65M addresses. |
| 2 | Will claim amounts be uniform or tiered? | ✅ **Resolved** — Uniform (~7.69 ZKM per address). Uniform amounts maximize privacy by eliminating amount-based deanonymization. |
| 3 | Should we implement full ZK circuits (circom/Semaphore) or hash-based nullifiers? | 🔲 Pending (strongly recommend hash-based for v1 given 65M-address tree — ZK circuit would require proving 2²⁶ membership) |
| 4 | Will a relayer service be built or use an existing one (Gelato)? | 🔲 Pending |
| 5 | Should the eligibility list be updatable (e.g., to fix errors)? | 🔲 Pending (recommend no — fixed list) |
| 6 | What happens to unclaimed tokens after the claim window? | 🔲 Pending (recommend → treasury) |
| 7 | Will the admin role be fully renounced post-claim? | 🔲 Pending (recommend yes) |
| 8 | Do we need Sybil resistance beyond the 0.004 ETH fee threshold? | ✅ **Mostly resolved** — 0.004 ETH (~$8–12) is a meaningful Sybil filter. Attacker would need to spend 0.004 ETH per address to qualify, making large-scale Sybil attacks economically prohibitive at 65M addresses. |
| 9 | Token listing strategy — DEX liquidity pool at launch or after claim period? | 🔲 Pending |
| 10 | Legal / compliance review needed for the airdrop? | 🔲 Pending |
| 11 | Exact snapshot block number for 2025-12-31 23:59:59 UTC? | 🔲 Pending (need to look up block at that timestamp) |
| 12 | How to handle addresses that are contracts (smart contracts / multisigs)? | 🔲 Pending (recommend: include all `from_address` values regardless of whether EOA or contract — contracts are eligible too) |
| 13 | Should the Proof API log requests? (Privacy implications) | 🔲 Pending (recommend: no logging of IP addresses or queried addresses) |
| 14 | Infrastructure budget for Proof API + CDN + relayer at 65M scale? | 🔲 Pending |
| 15 | What if the actual qualified count differs slightly from 65M after final query? | 🔲 Pending (adjust CLAIM_AMOUNT to ensure total = 500M ZKM) |

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

- [Merkle Airdrop — OpenZeppelin](https://docs.openzeppelin.com/contracts/4.x/utilities#merkle-proofs)
- [Semaphore Protocol — Privacy-preserving group proofs](https://semaphore.pse.dev/)
- [Worldcoin Airdrop — Nullifier-based claims](https://github.com/worldcoin)

### B. Gas Estimation (Base Chain)

| Operation | Estimated Gas | Estimated Cost (Base) |
|-----------|---------------|------------------------|
| Deploy ZKMToken | ~1,200,000 | ~$0.05 |
| Deploy ZKMAirdrop | ~800,000 | ~$0.03 |
| Claim Transaction (26-level proof) | ~160,000 | ~$0.008 |
| Nullifier Storage (SSTORE cold) | ~20,000 | ~$0.001 |
| Nullifier Storage (SSTORE warm) | ~2,900 | ~$0.0001 |

> *Gas estimates based on Base average gas price of ~0.1 Gwei & ETH at $3,000.*
> *26-level Merkle proof verification is ~33% more gas than a typical 20-level proof.*

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
                    │  (CSV on GCS / IPFS)      │
                    └──────────┬───────────────┘
                               │
                               ▼
                    ┌──────────────────────────┐
                    │  Merkle Tree Builder      │
                    │  (server, depth=26)       │
                    └──────────┬───────────────┘
                               │
                    ┌──────────▼───────────────┐
                    │  Merkle Root              │
                    │  (stored in contract)     │
                    └──────────┬───────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                     │
          ▼                    ▼                     ▼
   ┌──────────────┐   ┌──────────────┐    ┌──────────────┐
   │  Proof API   │   │  Frontend    │    │  Relayer     │
   │  (LevelDB)   │◄──│  dApp        │───►│  Service     │
   │              │   │  (React)     │    │  (optional)  │
   └──────────────┘   └──────────────┘    └──────┬───────┘
        │                                        │
        │  Merkle proof (26 siblings)            │
        └────────────────────────────────────────┼───► Base Chain
                                               │     (ZKM + Airdrop)
```

---

*End of PRD v1.1*
