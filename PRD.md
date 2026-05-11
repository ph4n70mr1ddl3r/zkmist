# ZKMist (ZKM) — Product Requirements Document

**Version:** 6.1  
**Date:** 2026-05-11  
**Status:** Draft  
**Author:** ZKMist Community  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is a **fully community-owned** ERC-20 token on **Base Chain**. There is no team allocation, no treasury, no investor share, and no pre-mine. Every ZKM token in existence was claimed by a member of the Ethereum community through a privacy-preserving airdrop.

~65 million Ethereum addresses that paid ≥0.004 ETH in cumulative transaction fees on mainnet before 2026 are eligible. Each claimant receives **10,000 ZKM** — no more, no less. The token supply is determined entirely by how many people claim: up to **10 billion ZKM** across up to **1 million claimants**. Claims close on 2027-01-01 or when 1 million claims are reached, whichever comes first.

**With ~65 million eligible addresses and a 1-million claimant cap, only ~1.5% of eligible addresses can claim.** The claim window is first-come, first-served — those who discover ZKMist early, are technically capable of running the CLI, and are motivated to put in the effort will have a meaningful advantage. This is by design: the claiming process itself acts as a natural filter that rewards engaged community members and makes Sybil farming uneconomical.

The claiming process is **anonymous** — the qualified address is never linked to the receiving address. Claimants generate zero-knowledge proofs locally using the RISC Zero zkVM and submit them to a fully immutable, adminless contract.

**ZKMist has no central team. The value of ZKM is built entirely by the community.**

### 1.2 Philosophy

| Principle | Implementation |
|-----------|---------------|
| **Fair allocation, open access** | Every claimant gets exactly 10,000 ZKM. No exceptions. No tiers. No insider allocation. However, with 65M eligible and 1M cap, claiming is first-come, first-served — see §4.6. |
| **Community-owned** | 100% of supply goes to claimants. Zero team tokens. Zero investor tokens. |
| **Anonymous** | Qualified address is never linked to receiving address on-chain. |
| **Immutable** | Contract has no admin, no owner, no pause, no upgrade. Deploy once, run forever. |
| **Permissionless** | Anyone can build relayers, UIs, tools, markets on top. No gatekeepers. |
| **Transparent** | Eligibility list, Merkle root, and guest program source are all public and auditable. |

### 1.3 Problem Statement

Standard airdrops are neither fair nor private. They create public links between qualifying and claiming addresses, expose user portfolios, and reserve large token allocations for teams and investors. ZKMist exists to prove that a token launch can be **entirely community-owned and privacy-preserving**.

ZKMist is *not* equally accessible to all 65M eligible addresses — the 1M claim cap creates a first-come, first-served contest where technical ability, early awareness, and motivation provide a clear advantage (see §4.6). What ZKMist guarantees is **fairness of allocation** (no insider tokens, equal amounts per claimant) and **fairness of opportunity** (anyone who is eligible can participate), not fairness of outcome.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Deploy ZKM as a community-owned ERC-20 on Base | 100% of supply claimable by community |
| G2 | Enable anonymous claiming | No direct on-chain link between qualified and recipient address in the protocol |
| G3 | Prevent double-claiming | Zero double-claims |
| G4 | Gas-efficient claim | < $0.50 per claim on Base |
| G5 | Fully immutable contract | No admin, no owner, no pause |
| G6 | Equal allocation | Every claimant receives exactly 10,000 ZKM |
| G6.1 | Transparent scarcity dynamics | Claim cap and first-come-first-served model clearly documented and enforced on-chain |
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
| **Burnable** | Yes — any token holder can burn their own ZKM via `burn()` / `burnFrom()` |
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
>
> **Token holders can burn ZKM at any time** via `burn()` or `burnFrom()`, permanently reducing the total supply. Burned tokens are destroyed — they cannot be recovered or re-minted. The `MAX_SUPPLY` cap refers to the upper bound on *minted* tokens; the circulating supply can only decrease through burning. After the claim window closes, no new ZKM can ever be minted, and the supply can only go down.

### 4.6 Scarcity & Access Dynamics

With ~65 million eligible addresses and a cap of 1 million claimants, ZKMist has a **first-come, first-served** claim model. This is a deliberate design choice that creates bounded scarcity while keeping the process open to anyone eligible.

**What this means in practice:**

| Factor | Effect |
|--------|--------|
| **1M claim cap** | Only ~1.5% of eligible addresses can claim. Creates scarcity and per-claimant value. |
| **Technical barrier** | Claiming requires running a CLI, downloading ~1.3 GB, and building a Merkle tree (~4 GB RAM). This filters out casual or unmotivated participants. |
| **Information advantage** | Those who discover ZKMist early have more time and less competition. Early claimants face a lower risk of the cap being reached. |
| **Effort-reward structure** | The claiming process rewards technical competence and proactive engagement — qualities valued in the Ethereum community. |
| **Sybil resistance** | Each claim requires a unique private key tied to an eligible address. Combined with the effort barrier (1.3 GB download, 4 GB RAM, ~90s proving time per claim), mass Sybil farming is inconvenient but not impossible for a well-funded actor. The design raises the cost sufficiently to deter casual farming. |
| **Gas auction risk near cap** | As `totalClaims` approaches 1M, late claimants may engage in priority-fee bidding wars to secure one of the final slots. This could price out users despite holding a valid proof. Additionally, multiple valid claims in the same final block may push `totalClaims` past the cap — only the first N claims that fit under the cap succeed, and the rest revert, wasting their proofs. Accepted as inherent to first-come-first-served on-chain markets. |

**This is not equally accessible to all 65M eligible users.** Some will lack the hardware, bandwidth, technical skill, or awareness to claim. The PRD acknowledges this openly. The design prioritizes:

1. **Fairness of allocation** — no insider tokens, no tiers, equal amounts per claimant.
2. **Fairness of opportunity** — anyone eligible *can* claim; no gatekeepers decide who gets in.
3. **Transparency** — the rules (cap, deadline, process) are public, immutable, and enforced on-chain.

It does **not** guarantee fairness of outcome — not every eligible person will claim, and the 1M cap ensures most won't be able to.

**Why not remove the cap?** An uncapped model (deadline only) would guarantee access to everyone but produce an unpredictable supply, diluting per-claimant value and removing the scarcity that incentivizes early participation and community building. The capped model trades universal access for economic coherence.

**Why 1M and not 5M or 10M?** The 1M cap at 10,000 ZKM each produces a max supply of 10B ZKM — a psychologically round number that is easy to reason about. A higher cap would require either lowering the per-claimant amount (breaking the "10,000 ZKM" simplicity) or inflating the max supply. The current parameters are a balance between inclusivity, scarcity, and simplicity.

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
  SUM(gas_price * receipt_gas_used) / 1e18 AS total_fees_eth
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
  total_fees_eth DESC;  -- optional, for audit convenience only; not needed for eligibility list
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
| **Leaf** | `poseidon(address)` — t=2, R_F=8, R_P=56 |
| **Depth** | 26 levels (65M leaves, padded to 2²⁶ = 67,108,864) |
| **Interior hash** | Poseidon — t=3, R_F=8, R_P=57 |
| **Poseidon params** | BN254 scalar field, x^5 S-box. Leaf: `light-poseidon` Circom t=2 (1 input). Interior: `light-poseidon` Circom t=3 (2 inputs). |
| **Padding** | Empty leaves set to `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` (sentinel value that can never be a valid leaf). Note: the sentinel's raw bytes are larger than the BN254 scalar field modulus (`p ≈ 2^254`), so `Fr::from_be_bytes_mod_order()` would reduce it modulo p. However, the guest program compares the 32-byte Poseidon output (a field element) against the raw sentinel bytes — a Poseidon hash can never equal the sentinel, so the comparison is safe. Do not compare sentinel as a field element. |
| **Root** | Hardcoded in the airdrop contract |

**Merkle path direction convention:**

| `path_index[i]` | Position of current node | Parent hash |
|-----------------|--------------------------|-------------|
| `0` | Left child | `poseidon(current, sibling)` |
| `1` | Right child | `poseidon(sibling, current)` |

This convention MUST be identical in the guest program, CLI tree builder, and any third-party Merkle proof generation. A mismatch will produce a different root and cause all proofs to be rejected on-chain.

**Poseidon parameters:**

- **Field:** BN254 scalar field (`p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`)
- **S-box:** x^5
- **Leaf hash:** `poseidon(address_as_field_element)` — t=2, R_F=8, R_P=56 (`light-poseidon` Circom nr_inputs=1)
- **Interior hash:** `poseidon(left_child, right_child)` — t=3, R_F=8, R_P=57 (`light-poseidon` Circom nr_inputs=2)
- **Implementation:** `light-poseidon` crate (v0.4.x) with `ark-bn254` backend. Same crate used in both guest program and CLI tree builder. Pure Rust, compiles for `riscv32im-risc0-zkvm-elf` target (validated — see §13, #15).
- **Leaf encoding convention:** A 20-byte Ethereum address is converted to a 32-byte big-endian buffer by zero-padding on the LEFT (high-order bytes): `buffer = 0x00…00 || address` (12 zero bytes + 20 address bytes). The resulting 32 bytes are interpreted as a BN254 field element via `Fr::from_be_bytes_mod_order()`. Since the address is at most 160 bits and the BN254 field modulus is ~2^254, no modular reduction occurs. This convention MUST be identical in the guest program, CLI tree builder, and any third-party Merkle tree reconstruction.
- **Guest build configuration:** Building for `riscv32im-risc0-zkvm-elf` requires (1) the RISC Zero custom toolchain (`rzup install rust`), (2) `getrandom_backend="custom"` in `.cargo/config.toml` rustflags for the target, and (3) an atomic shim providing `__atomic_store_1` (riscv32 lacks native 1-byte atomics required by `tracing_core`). See §13, #15 for details.

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
5. **Equal allocation** — every claimant receives exactly 10,000 ZKM. First-come, first-served among 65M eligible (see §4.6).
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
│    ② Stream-build Merkle tree (processes all 65M leaves, ~4 GB RAM)  │
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
nullifier = poseidon(Fr(privateKey), Fr(domain))
domain   = Fr("ZKMist_V1_NULLIFIER")  // left-aligned, zero-padded to 32 bytes
```

Uses the **same Poseidon hasher** as interior Merkle nodes: `light-poseidon` Circom t=3 (2 inputs), R_F=8, R_P=57, over BN254. This keeps all hashing in the same field and reuses an already-constructed hasher instance inside the guest program, saving cycles.

| Property | Explanation |
|----------|-------------|
| **Deterministic** | Same private key → same nullifier → double-claim impossible |
| **Not precomputable** | Requires the private key, not in the published list |
| **Not reversible** | Cannot recover key or address from nullifier (Poseidon is a one-way permutation) |
| **Unique per address** | Different keys produce different field elements → different nullifiers |
| **Versioned** | Domain separator `"ZKMist_V1_NULLIFIER"` encodes the protocol version. If a V2 contract is ever deployed (new guest program, new Merkle tree), it would use `"ZKMist_V2_NULLIFIER"` so V1 nullifiers cannot be replayed on V2. |
| **Field-native** | Stays entirely in the BN254 scalar field. No SHA-256 dependency inside the guest. |

### 6.5 Guest Program (Rust)

```rust
//! ZKMist Airdrop Claim — RISC Zero Guest Program

#![no_main]
risc0_zkvm::guest::entry!(main);

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use k256::ecdsa::{SigningKey, VerifyingKey};
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::guest::env;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

const TREE_DEPTH: usize = 26;
const NULLIFIER_DOMAIN_BYTES: &[u8; 19] = b"ZKMist_V1_NULLIFIER";
const PADDING_SENTINEL: [u8; 32] = [0xFFu8; 32];

pub fn main() {
    // === Public inputs (committed to journal) ===
    let merkle_root: [u8; 32] = env::read();
    let nullifier: [u8; 32] = env::read();
    let recipient: [u8; 20] = env::read();

    // Validate recipient is not zero address — tokens minted to address(0)
    // are irreversibly burned. This check is defense-in-depth alongside the
    // Solidity contract's require(_recipient != address(0)).
    assert!(recipient != [0u8; 20], "Recipient cannot be zero address");

    // === Private inputs ===
    let private_key: [u8; 32] = env::read();

    // Derive Ethereum address
    let address = derive_address(&private_key);

    // Merkle membership proof.
    //
    // path_index convention:
    //   path_index[i] = 0 → current node is the LEFT child at level i
    //                     → parent = poseidon(current, sibling)
    //   path_index[i] = 1 → current node is the RIGHT child at level i
    //                     → parent = poseidon(sibling, current)
    let mut siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices: [u8; TREE_DEPTH] = [0u8; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        siblings[i] = env::read();
        path_indices[i] = env::read();
    }

    // Pre-construct Poseidon hashers once (not per-call) to avoid redundant
    // initialization overhead inside the 26-level Merkle path verification.
    // Each hasher construction involves fixed-string round constant allocation;
    // reusing a single instance across all 26 levels saves ~2.6M–5.2M RISC-V cycles.
    //
    // NOTE: Poseidon::hash() requires &mut self (light-poseidon v0.4.x internal
    // state mutation for sponge absorption). Hashers MUST be declared mutable.
    let mut leaf_hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid leaf params");
    let mut interior_hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid interior params");

    // Compute leaf and verify Merkle membership
    let leaf = poseidon_hash_address_with(&address, &mut leaf_hasher);
    assert!(leaf != PADDING_SENTINEL, "Padding leaf — not a valid claimant");
    let computed_root = compute_merkle_root_with(&leaf, &siblings, &path_indices, &mut interior_hasher);
    assert_eq!(computed_root, merkle_root, "Not in eligibility tree");

    // Verify nullifier: poseidon(Fr(key), Fr(domain)) using the interior hasher.
    // Same hasher as Merkle proof — each hash() call is independent.
    let expected = compute_nullifier(&private_key, &mut interior_hasher);
    assert_eq!(nullifier, expected, "Invalid nullifier");

    // Commit outputs to journal.
    // ⚠️  CRITICAL: The Solidity contract slices the journal bytes directly:
    //     journal[0:32]   = merkleRoot
    //     journal[32:64]  = nullifier
    //     journal[64:84]  = recipient (raw 20 bytes, NOT padded to 32)
    // Total journal must be exactly 84 bytes. This requires that env::commit()
    // writes raw bytes without length prefixes or padding. Verified for
    // risc0-zkvm v5.0.0: commit() uses serde with a custom serializer that
    // writes [u8; N] arrays as N raw bytes (no varint length prefix).
    // Must be re-verified end-to-end before mainnet deployment.
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

fn derive_address(key: &[u8; 32]) -> [u8; 20] {
    let sk = SigningKey::from_slice(key).expect("Invalid key");
    let vk = VerifyingKey::from(&sk);
    let point = vk.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    hasher.update(&point.as_bytes()[1..65]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// Compute nullifier as poseidon(Fr(key), Fr(domain)) using the interior
/// hasher (t=3, 2 inputs). Domain separation prevents nullifier collisions
/// across protocol versions.
fn compute_nullifier(key: &[u8; 32], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let key_elem = Fr::from_be_bytes_mod_order(key);
    let mut domain_padded = [0u8; 32];
    domain_padded[..NULLIFIER_DOMAIN_BYTES.len()].copy_from_slice(NULLIFIER_DOMAIN_BYTES);
    let domain_elem = Fr::from_be_bytes_mod_order(&domain_padded);
    field_element_to_bytes(
        hasher
            .hash(&[key_elem, domain_elem])
            .expect("Nullifier hash failed"),
    )
}

/// Hash a 20-byte Ethereum address into a 32-byte Poseidon leaf.
/// The address is zero-padded to 32 bytes and interpreted as a BN254 field element.
/// Uses light-poseidon (t=2, R_F=8, R_P=56) — same crate as CLI tree builder.
/// Takes a pre-constructed hasher to avoid redundant initialization per call.
fn poseidon_hash_address_with(addr: &[u8; 20], hasher: &mut Poseidon<Fr>) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(addr);
    field_element_to_bytes(hasher.hash(&[Fr::from_be_bytes_mod_order(&padded)]).expect("Leaf hash failed"))
}

/// Compute the Merkle root by hashing siblings up the tree.
///
/// Direction convention:
///   path_index[i] = 0 → current is LEFT child  → parent = poseidon(current, sibling)
///   path_index[i] = 1 → current is RIGHT child → parent = poseidon(sibling, current)
///
/// This convention MUST match the CLI tree builder's path encoding exactly.
/// Takes a pre-constructed hasher to avoid redundant initialization across 26 levels.
fn compute_merkle_root_with(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    path_indices: &[u8; TREE_DEPTH],
    hasher: &mut Poseidon<Fr>,
) -> [u8; 32] {
    let mut current = *leaf;
    for i in 0..TREE_DEPTH {
        let (left, right) = if path_indices[i] == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        let left_elem = Fr::from_be_bytes_mod_order(&left);
        let right_elem = Fr::from_be_bytes_mod_order(&right);
        current = field_element_to_bytes(hasher.hash(&[left_elem, right_elem]).expect("Interior hash failed"));
    }
    current
}

/// Convert a BN254 field element to 32-byte big-endian representation.
fn field_element_to_bytes(elem: Fr) -> [u8; 32] {
    let bytes = elem.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Poseidon hash of a single field element (used for leaf hashing).
/// Uses BN254 scalar field, x^5 S-box, t=2 (1 input), R_F=8 + R_P=56 rounds.
///
/// ⚠️  RESOLVED (Open Question #13): RISC Zero's built-in Poseidon accelerator
/// operates over BabyBear (the recursion field), NOT BN254. It cannot be used
/// for Merkle tree hashing. Instead, use a pure-Rust BN254 Poseidon crate.
///
/// Recommended crate: `light-poseidon` (v0.4.x)
///   - BN254 (ark-bn254::Fr), x^5 S-box, Circom-compatible parameters
///   - Supports t=2 (nr_inputs=1) for leaves and t=3 (nr_inputs=2) for interior
///   - `no_std` compatible via `ark-ff` (pure Rust, compiles for riscv32im)
///   - Use `PoseidonHasher::hash()` for field-element API
///   - Use `PoseidonBytesHasher::hash_bytes_be()` for byte-level API
///
/// Key invariant: the SAME Poseidon implementation must be used in both:
///   1. The guest program (this code) — for proof generation
///   2. The CLI Merkle tree builder (off-chain) — for root computation
/// Import from a shared crate to guarantee parameter consistency.
///
/// Performance: ~50K–100K RISC-V cycles per Poseidon hash. With 27 hashes
/// per claim (1 leaf + 26 Merkle path), total ~1.4–2.7M cycles. Negligible
/// vs. the address derivation (~2M cycles for secp256k1).
///
/// ⚠️  PERFORMANCE: Poseidon hasher instances must be constructed ONCE and reused
/// across all 26+1 hash invocations per claim. Constructing per-call wastes
/// ~100K–200K RISC-V cycles per hash on round-constant initialization.
/// ⚠️  REFERENCE ONLY — not used in the claim flow.
/// Callers should construct a hasher once and reuse it via
/// `poseidon_hash_address_with()` instead.
#[allow(dead_code)]
fn poseidon_hash_single(input: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(1).expect("Invalid params");
    let input_elem = Fr::from_be_bytes_mod_order(input);
    let result = hasher.hash(&[input_elem]).expect("Hash failed");
    field_element_to_bytes(result)
}

/// Poseidon hash of two field elements (used for interior node hashing).
/// Uses BN254 scalar field, x^5 S-box, t=3 (2 inputs), R_F=8 + R_P=57 rounds.
///
/// ⚠️  REFERENCE ONLY — not used in the claim flow.
/// Callers should construct a hasher once and reuse it via
/// `compute_merkle_root_with()` instead.
#[allow(dead_code)]
fn poseidon_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Invalid params");
    let left_elem = Fr::from_be_bytes_mod_order(left);
    let right_elem = Fr::from_be_bytes_mod_order(right);
    let result = hasher.hash(&[left_elem, right_elem]).expect("Hash failed");
    field_element_to_bytes(result)
}
```

### 6.6 Claim Flow (Step-by-Step)

1. **Download eligibility list** — `zkmist fetch` downloads from IPFS (~1.3 GB). Cached locally.

2. **Generate proof** — `zkmist prove`:
   - Prompts for private key (hidden input)
   - Prompts for recipient address
   - **⚠️ Recipient is irrevocable.** Once the proof is generated, tokens can only ever be minted to this address. If the recipient is wrong, you cannot re-claim — your nullifier is consumed. Triple-check before confirming.
   - **⚠️ Recipient must not be the zero address (`0x0`).** Tokens minted to `address(0)` are irreversibly burned. The CLI MUST validate this before starting the (expensive) proof generation, not leave it to the zkVM assertion which would waste ~45–90s of proving time.
   - Stream-builds Merkle tree (~1–2 min, ~4 GB RAM required)
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
| Recipient address reused elsewhere | Use a fresh, never-before-used address as recipient |
| Timestamp correlation | If only a few people claim in a block, timing may narrow candidates |

### 6.9 Privacy Checklist for Claimants

Before claiming, follow this checklist to maximize privacy:

| # | Step | Why |
|---|------|-----|
| 1 | **Use a fresh recipient address** — never transacted on-chain before | Prevents linking recipient to any known identity |
| 2 | **Fund recipient from an independent source** — not from the qualified address or any address linked to you | Prevents gas-funding correlation |
| 3 | **Use a relayer** instead of submitting directly (if possible) | Avoids on-chain link between gas payer and recipient |
| 4 | **Don't publish both addresses** — never mention your qualified and recipient addresses in the same context (social media, forums, ENS) | Prevents off-chain correlation |
| 5 | **Claim during high-activity periods** — when many others are claiming | Reduces timing-based narrowing of candidates |
| 6 | **Don't immediately move tokens** after receiving them | Wait to avoid linking the claim transaction to subsequent token movements |

### 6.10 Journal Layout Specification

The guest program commits exactly 3 values to the journal. The layout is fixed and must match the Solidity contract's byte slicing:

```
Offset  Length  Field         Type
0       32      merkleRoot    bytes32
32      32      nullifier     bytes32
64      20      recipient     address (bytes20)
                              ─────────
Total:  84 bytes
```

Both the Rust guest program (`env::commit()` order) and the Solidity contract (`_journal[offset]` slicing) must conform to this layout. Any mismatch will cause all proofs to be rejected on-chain.

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description | Mutability |
|----------|-------------|------------|
| `ZKMToken` | ERC-20 with max supply, mintable only by airdrop, burnable by holders | Immutable owner (no admin functions) |
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
  - burn(): any holder can burn their own tokens
  - burnFrom(): approved spenders can burn tokens from another address
  - No owner functions
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

    /// @notice Burn tokens from the caller's balance. Permanently reduces total supply.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from an approved address. Permanently reduces total supply.
    /// Uses OpenZeppelin's _spendAllowance() which handles the allowance check and decrement.
    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
```

### 7.3 ZKMAirdrop Contract

**Fully immutable.** No admin, no owner, no pause, no upgrade.

```solidity
contract ZKMAirdrop {
    ZKMToken public immutable token;
    // MUST be the Groth16 verifier variant (RiscZeroGroth16Verifier), not the raw STARK verifier.
    // The Groth16 verifier internally compresses the user's STARK proof for cheap on-chain
    // verification (~400K gas vs. ~1.5M for raw STARK). Uses the IRiscZeroVerifier interface.
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
        require(_recipient != address(0), "Recipient cannot be zero address");

        // Validate journal layout: must be exactly 84 bytes
        // Layout: merkleRoot[0:32] ++ nullifier[32:64] ++ recipient[64:84]
        require(_journal.length == 84, "Invalid journal length");

        // Verify RISC Zero proof
        // RESOLVED: The journal digest scheme is sha256(raw_journal_bytes), confirmed by:
        //   1. Rust: Journal::digest() = S::hash_bytes(&self.bytes) = SHA-256 of raw bytes
        //   2. Solidity: bytes32(sha256(_journal)) = SHA-256 of raw bytes
        //   3. RiscZeroGroth16Verifier.verify() internally calls
        //      ReceiptClaimLib.ok(imageId, journalDigest).digest() which constructs
        //      the full ReceiptClaim and verifies the Groth16 proof against it.
        // See: https://github.com/risc0/risc0-ethereum/blob/main/contracts/src/IRiscZeroVerifier.sol
        bytes32 journalDigest = bytes32(sha256(_journal));
        verifier.verify(_proof, imageId, journalDigest);

        // Validate journal contents match claim parameters
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
- `totalClaims++` is safe from overflow — maximum value is 1,000,000 (enforced by the `require(totalClaims < MAX_CLAIMS)` guard), which is well within `uint256` bounds. No SafeMath needed.

### 7.4 On-Chain Read Queries

| Query | Function | Returns |
|-------|----------|---------|
| Is claim window open? | `isClaimWindowOpen()` | `bool` |
| Claims remaining? | `claimsRemaining()` | `uint256` |
| Total claims so far? | `totalClaims` | `uint256` |
| Has this nullifier claimed? | `isClaimed(bytes32)` | `bool` |
| Total ZKM supply? | `token.totalSupply()` | `uint256` |
| Max ZKM supply? | `token.MAX_SUPPLY` | `uint256` |
| ZKM burned total? | `token.MAX_SUPPLY - (claims × 10,000 + remaining_mintable)` or track via `Transfer` events to `address(0)` | `uint256` |

---

## 8. CLI Tool

### 8.1 Commands

```
zkmist fetch                  Download eligibility list from IPFS (~1.3 GB). Builds and caches the Merkle tree locally so `prove` doesn't need to rebuild it. Falls back to GitHub mirror if IPFS is unavailable.
zkmist prove                  Generate ZK proof (interactive). Uses the cached Merkle tree from `fetch` — does not rebuild from scratch.
zkmist submit <proof.json>    Submit proof to ZKMAirdrop contract
zkmist verify <proof.json>    Verify proof locally: validates the STARK proof and checks that the journal contains the expected merkleRoot, nullifier, and recipient
zkmist check <address>        Check if address is eligible (requires downloaded eligibility list — see §8.7)
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

       ⚠️  RECIPIENT IS IRREVOCABLE — triple-check before submitting.
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
| Crypto | `k256`, `tiny-keccak`, `light-poseidon`, `ark-bn254` |
| CLI | Rust |
| Chain | Base (8453) |
| Data | IPFS + GitHub |

### 8.7 `zkmist check` Privacy Note

`zkmist check <address>` requires the full eligibility list to be downloaded locally first (same ~1.3 GB dataset used by `zkmist prove`). The check is performed entirely offline against the local Merkle tree — no data is sent to any server, and no external API is queried. If the eligibility list is not cached, `zkmist check` will prompt the user to run `zkmist fetch` first.

---

## 9. Timeline

| Phase | Description |
|-------|-------------|
| T-30d | BigQuery extraction finalized, list published |
| T-14d | List + Merkle root + guest program source published for audit |
| T-7d | Contracts deployed on Base |
| T+0 | Claims open |
| T+deadline or 1M claims | Claims close at 2027-01-01 00:00:00 UTC or 1M claims, whichever comes first |
| Post-close | Contract remains immutable forever. No more ZKM can be minted. |

---

## 10. Security

### 10.1 Smart Contract Security

| Measure | Details |
|---------|---------|
| **Audit** | External audit before mainnet |
| **Test Coverage** | ≥ 95% |
| **Guest Program Audit** | Rust source (~80 lines of logic). **Critical:** the guest program binary is frozen at deployment — the `imageId` is hardcoded in the contract and can never be changed. Any bug is permanent. Must receive the same audit rigor as the Solidity contracts. |
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

### 10.3 Disaster Recovery & Accepted Risks

Since both the smart contracts and the guest program (`imageId`) are immutable, **any bug discovered after deployment is permanent**. This is an accepted risk. There is no recovery mechanism by design.

| Risk | Impact | Accepted? | Notes |
|------|--------|-----------|-------|
| Bug in guest program | All proofs may be invalid or incorrect | ✅ Accepted | Mitigated by external audit + testnet trial |
| Bug in Solidity contract | Claims may not work as intended | ✅ Accepted | Mitigated by external audit + formal verification |
| Poseidon parameter mismatch | Proofs rejected on-chain | ✅ Accepted | Mitigated by end-to-end integration test on testnet |
| Journal digest mismatch | Proofs rejected on-chain | ✅ Accepted | Mitigated by verifying against deployed verifier on testnet |
| RISC Zero breaks compatibility | New zkVM version incompatible | N/A | Image ID is frozen — old proofs always work with old verifier |

**There is no upgrade path.** If a critical bug is found, the only option is for the community to deploy an entirely new system (new contracts, new guest program) and choose to migrate. This would be a social coordination effort, not a technical one.

### 10.4 Test Plan

| Phase | Tests | Description |
|-------|-------|-------------|
| Unit | Guest program | Test address derivation, nullifier computation, Poseidon hashing, Merkle proof verification with known test vectors |
| Unit | Guest program (negative) | Invalid key, wrong Merkle proof, mismatched nullifier, zero-address leaf |
| Unit | Smart contracts | `claim()` success path, all revert conditions (deadline, cap, double-claim, journal mismatch) |
| Unit | ZKMToken `burn()` | Holder burns own tokens, supply decreases, event emitted |
| Unit | ZKMToken `burnFrom()` | Approved spender burns from another address, insufficient allowance reverts |
| Integration | Full prove → verify → claim | Generate real RISC Zero proof, submit to local fork, verify mint |
| Integration | Journal layout | Confirm guest program's `env::commit()` order produces exactly 84 bytes matching Solidity slicing |
| Fork test | Base mainnet fork | Deploy contracts against a Base fork, submit real proofs, verify gas costs |
| Negative | Double-claim | Submit same nullifier twice — must revert |
| Negative | Wrong recipient | Submit proof with different recipient — must revert |
| Negative | Expired deadline | Set `block.timestamp` past deadline — must revert |
| Negative | Claim cap reached | Set `totalClaims` to 1M — must revert |
| Property | Poseidon reference | Cross-validate Poseidon output against a reference implementation (e.g., `poseidon` crate) |
| Coverage | ≥ 95% | Both Solidity and Rust code paths |

### 10.5 Fairness & Access

**Fairness of allocation** (what you receive):

| Guarantee | Mechanism |
|-----------|-----------|
| **No insider allocation** | 100% minted on claim. No pre-mine. |
| **Equal amounts** | 10,000 ZKM per claimant — hardcoded constant |
| **Transparent eligibility** | Published list, auditable Merkle tree |
| **Immutable rules** | Contract cannot be changed after deployment |
| **Capped supply** | 10B ZKM max mint — enforced on-chain. Circulating supply can only decrease via burning. |
| **Deadline enforced** | No claims after 2027-01-01 — enforced on-chain |

**Known access asymmetries** (who gets to claim):

| Asymmetry | Impact | Accepted? |
|-----------|--------|----------|
| First-come, first-served (1M cap) | Early claimants have guaranteed access; latecomers may be locked out | ✅ By design |
| Technical barrier (CLI, 4 GB RAM) | Users without technical skill or adequate hardware are excluded | ✅ By design — acts as Sybil filter |
| Bandwidth requirement (1.3 GB download) | Users with slow or expensive internet are disadvantaged | ✅ Accepted — mitigated by IPFS mirroring and relayer ecosystem |
| Information asymmetry | Those who hear about ZKMist first have a major advantage | ✅ Accepted — community-driven discovery is part of the model |
| Contract wallets excluded | Multisigs and Safes appear in the list but cannot claim | ✅ Accepted — see §5.1 note |

### 10.6 Threat Model

This section consolidates the security-relevant adversaries, their capabilities, and the protocol's defenses.

**Adversaries in scope:**

| Adversary | Capabilities | Attack Goal | Defense |
|-----------|-------------|-------------|----------|
| **Double-claimer** | Holds one eligible private key, attempts to claim twice | Receive 20,000 ZKM instead of 10,000 | Nullifier is deterministic (poseidon of private key + domain). Contract rejects duplicate nullifiers. | 
| **Impersonator** | Does NOT hold the eligible private key, but knows the address | Claim someone else's allocation | Must produce a valid ZK proof: address derivation from private key + valid Merkle membership proof. Without the private key, no valid proof exists. |
| **Front-runner** | Observes pending claim transactions in the mempool | Submit the same proof first to steal tokens | Recipient address is committed inside the ZK proof (journal). Front-runner cannot change recipient without invalidating the proof. |
| **Relayer** | Submits proofs on behalf of claimants, sees proof.json | Learn the qualified address or steal tokens | proof.json contains no qualified address — only a nullifier, recipient, and STARK proof. Relayer sees exactly what's on-chain, nothing more. |
| **Sybil farmer** | Controls many eligible addresses, automates claiming at scale | Claim disproportionate share of the 1M cap | Each claim requires a unique private key + ~90s proving time + 4 GB RAM. Amortizable across addresses but still costly at scale (~10 concurrent proofs per 40 GB machine). The 1M cap limits total damage. |
| **Privacy attacker** | Analyzes on-chain data to link qualified → recipient addresses | De-anonymize claimants | Mitigated by: nullifier is poseidon(privateKey, domain), not address-derived; no on-chain link between qualified and recipient; user controls gas-funding path. See §6.8 for residual risks. |
| **Malicious verifier** | Deploys a modified verifier contract | Accept invalid proofs, mint tokens without eligibility | The verifier contract address and image ID are immutable at deployment. Community must verify these match the audited, published source before claiming. |

**Adversaries explicitly out of scope:**

| Adversary | Why out of scope |
|-----------|-----------------|
| **Compromised claimant machine** | If malware runs on the claimant's machine, no protocol-level defense exists. The private key is exposed at OS level. Mitigated by recommending verification of CLI binary checksums. |
| **IPFS censorship / unavailability** | Eligibility list is mirrored on GitHub. Community can re-pin on IPFS. No single point of failure. |
| **Base chain liveness** | ZKMist relies on Base for transaction ordering and execution. If Base is down, claims cannot be submitted, but the claim window deadline is based on block timestamps, not wall-clock time. |
| **Network-level surveillance** | Claimants should use Tor/VPN if they want to hide their IP from IPFS gateways or RPC providers. This is a user-side concern, not a protocol concern. |

---

## 11. Technical Specifications

| Spec | Value |
|------|-------|
| **Chain** | Base (8453) |
| **Token** | ZKMist (ZKM), ERC-20, 18 decimals |
| **Max Supply** | 10,000,000,000 ZKM (10 billion) |
| **Initial Supply** | 0 (minted on claim) |
| **Claim Amount** | 10,000 ZKM (fixed) |
| **Burnable** | Yes — `burn()` and `burnFrom()` on ZKMToken |
| **Max Claims** | 1,000,000 |
| **Claim Deadline** | 2027-01-01 00:00:00 UTC |
| **Proof System** | RISC Zero zkVM (STARK) |
| **risc0-zkvm version** | Must be pinned at build time (e.g., `v5.0.0`). Different versions may produce different Image IDs. Note: `cargo-risczero` (CLI tool, currently v3.0.5) and `risc0-zkvm` (the zkVM crate) are versioned independently. The image ID depends on the zkVM crate version, not the CLI version. |
| **Poseidon crate** | `light-poseidon` v0.4.x — same version in guest program and CLI tree builder |
| **Trusted Setup** | **None** |
| **Merkle Tree** | 26 levels, Poseidon (leaf: t=2/R_P=56, interior: t=3/R_P=57, BN254) |
| **Nullifier** | poseidon(Fr(privateKey), Fr(domain)), domain = "ZKMist_V1_NULLIFIER" |
| **Gas per claim** | ~500,000–520,000 (~0.00005 ETH / ~$0.15) via Groth16 wrapper (validated — see §13, #16) |
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
| 10 | Exact qualified count after final BigQuery run? | 🔲 Pending — final BigQuery run scheduled for T-30d |
| 11 | Keccak256 in guest program for address derivation? | ✅ Resolved — `tiny-keccak` v2 is confirmed and compiles for `riscv32im-risc0-zkvm-elf`. Use `Keccak::v256()` hasher API (not the removed `keccak256()` direct function). See #17 for full API migration notes. |
| 12 | Contract addresses (multisigs) eligible? | ✅ Ineligible by design — claiming requires a private key to derive address + generate nullifier. Contract wallets appear in the list but cannot claim. |
| 13 | Poseidon API: does the guest program's Poseidon output match the off-chain Merkle tree builder? | ✅ **Resolved** — RISC Zero's Poseidon accelerator uses BabyBear (wrong field). Use `light-poseidon` crate (pure Rust, BN254, `no_std`) in BOTH guest program and CLI tree builder. Leaf: t=2 (R_F=8, R_P=56). Interior: t=3 (R_F=8, R_P=57). ~2.7M cycles total — negligible. Must still validate with end-to-end testnet test before T-14d. |
| 14 | Journal digest: does `sha256(raw_journal_bytes)` match the deployed `IRiscZeroVerifier`'s expected digest scheme? | ✅ **Resolved** — Confirmed correct by reading RISC Zero source. Rust `Journal::digest()` = `Sha256::hash_bytes(&self.bytes)`. Solidity `bytes32(sha256(_journal))` matches. The `RiscZeroGroth16Verifier.verify(seal, imageId, journalDigest)` takes the digest as-is and wraps it in `ReceiptClaimLib.ok(imageId, journalDigest).digest()`. End-to-end testnet test still recommended before mainnet. |
| 15 | Do `light-poseidon` + `ark-bn254` compile for `riscv32im-risc0-zkvm-elf`? | ✅ **Resolved** — Validated by building a full guest program (address derivation + Poseidon hashing + Merkle proof + nullifier verification) for `riscv32im-risc0-zkvm-elf` using the RISC Zero toolchain (rzup v1.94.1, cargo-risczero 3.0.5). All crates compile successfully. Three issues required fixes: (1) `getrandom` 0.3 needs `getrandom_backend="custom"` cfg flag in `.cargo/config.toml`, (2) `tracing_core` requires an atomic shim for `__atomic_store_1` (riscv32 limitation), (3) the PRD's guest program code has API mismatches with current crate versions (see #17). Binary size: 442K ELF. |
| 16 | Gas per claim estimate accuracy? | ✅ **Resolved** — Measured with Foundry gas benchmarks. Airdrop contract overhead (with noop verifier): 111,637 gas for first claim, 58,264 for subsequent. Groth16 verification (calculated): ~404,500 gas (5× ECMUL @ 32K + 5× ECADD @ 500 + 2× BN254 pairing @ 80K+77K + overhead). **Total: ~516,000 gas for first claim, ~463,000 for subsequent.** PRD's original estimate of ~300K was too low. Updated §11, Appendix B. At Base prices (0.1 Gwei, $3K ETH): ~$0.15/claim. |
| 17 | Guest program API compatibility with current crate versions? | ✅ **Resolved** — The PRD's Rust code had 6 API mismatches with current crate versions, all fixed in §6.5: (1) `Fr::from_be_bytes()` → `Fr::from_be_bytes_mod_order()` (ark-ff 0.5 removed `from_be_bytes`), (2) `into_bigint().to_bytes_be(&mut out[..])` → `into_bigint().to_bytes_be()` returns `Vec<u8>` (no in-place write), (3) `tiny_keccak::keccak256(data)` → must use `Keccak::v256()` hasher API (tiny-keccak v2 removed the direct function), (4) `k256::ecdsa::SigningKey::from_bytes(key)` → must use `SigningKey::from_slice(key)` (k256 0.13 changed the API), (5) `env::read()` → must use `risc0_zkvm::guest::env::read()` or import `use risc0_zkvm::guest::env`, (6) `&Poseidon<Fr>` → must be `&mut Poseidon<Fr>` because `PoseidonHasher::hash()` requires `&mut self` (light-poseidon v0.4.x mutates internal sponge state). These are all straightforward API updates, not design issues. |

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **Nullifier** | poseidon(Fr(privateKey), Fr(domain)). Prevents double-claim without revealing the qualified address. |
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
- [RISC Zero On-Chain Verification](https://dev.risczero.com/api/on-chain-verification)
- [RISC Zero Poseidon Accelerator](https://dev.risczero.com/api/zkvm/accelerators)

### B. Gas Estimates (Base)

Assumptions: Base gas price ~0.1 Gwei, ETH at $3,000.

| Operation | Gas | ETH | USD |
|-----------|-----|-----|-----|
| Deploy ZKMToken | ~1,200,000 | ~0.000012 ETH | ~$0.04 |
| Deploy Verifier | ~6,000,000 | ~0.00006 ETH | ~$0.18 |
| Deploy ZKMAirdrop | ~1,000,000 | ~0.00001 ETH | ~$0.03 |
| **Claim** | **~510,000** | **~0.000051 ETH** | **~$0.15** |

The user always generates a **RISC Zero STARK proof** locally. The deployed `RiscZeroGroth16Verifier` contract (part of RISC Zero's verifier suite, not a custom implementation) internally compresses STARK proofs into Groth16 proofs for cheap on-chain verification (~510K gas instead of ~1.5M for raw STARK). This is transparent to the user — they don't choose or know about it. Gas breakdown: ~400K for Groth16 verification (5x ECMUL + 2x BN254 pairing + RiscZero overhead) + ~110K for airdrop logic (sha256, SSTORE nullifier, SSTORE totalClaims, ERC20 _mint, event). At 1M claims this saves the community **~$270K** vs raw STARK verification.

> **Note:** The Groth16 wrapping is handled entirely by RISC Zero's verifier contract. ZKMist does not implement any custom proof compression. See [RISC Zero verification](https://dev.risczero.com/api/on-chain-verification) for details.

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

### D. End-to-End Test Vector

The following test vector allows independent verification of the entire claim pipeline. All implementations (guest program, CLI tree builder, Solidity contract) must reproduce these exact outputs.

**Test private key:**
```
0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**Derived Ethereum address:**
```
0xfcad0b19bb29d4674531d6f115237e16afce377c
```

Computed via: secp256k1 public key → Keccak-256 → last 20 bytes.

- Public key (uncompressed, 64 bytes): `0x4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8ffffe77b4dd0a4bfb95851f3b7355c781dd60f8418fc8a65d14907aff47c903a559`
- Keccak-256 of pubkey: `0x8a28e3bd23ede916a38d4a85fcad0b19bb29d4674531d6f115237e16afce377c`
- Address (last 20 bytes): `0xfcad0b19bb29d4674531d6f115237e16afce377c`

**⚠️ Ethereum uses Keccak-256 (the original NIST submission), NOT NIST SHA3-256.** These are different hash functions that produce different outputs. The `tiny_keccak` crate's `Keccak::v256()` implements the correct Keccak-256. Using `sha3::Sha3_256` or Python's `hashlib.sha3_256` will produce the WRONG address.

**Expected nullifier:**
```
nullifier = poseidon(Fr(privateKey), Fr(domain))
         where domain = "ZKMist_V1_NULLIFIER" (19 bytes, zero-padded to 32)
         = poseidon(
             Fr(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef),
             Fr(0x5a4b4d6973745f56315f4e554c4c494649455200000000000000000000000000)
           )
         = 0x078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9
```

Computed with `light-poseidon` v0.4.0, `ark-bn254` v0.5.0, t=3 (2 inputs), R_F=8, R_P=57.

**Leaf computation:**
```
address = 0xfcad0b19bb29d4674531d6f115237e16afce377c
padded  = 0x00000000000000000000000fcad0b19bb29d4674531d6f115237e16afce377c  // 12 zero bytes + 20 address bytes
leaf    = poseidon(Fr::from_be_bytes_mod_order(padded))
        = 0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9
```

Computed with `light-poseidon` v0.4.0, `ark-bn254` v0.5.0, t=2 (1 input), R_F=8, R_P=56.

**Reference values for cross-validation:**

| Input | Hash | Output |
|-------|------|--------|
| `poseidon(Fr(1))` (t=2, leaf hasher) | Leaf | To be computed |
| `poseidon(Fr(1), Fr(2))` (t=3, interior hasher) | Interior | `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` |
| Edge address `0x...0001` | Leaf | `0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133` |

**Field element edge case test:**
An address like `0x0000000000000000000000000000000000000001` produces a very small field element. Verified that `field_element_to_bytes()` correctly zero-pads the output to 32 bytes: `field_element_to_bytes(Fr(1)) = 0x0000000000000000000000000000000000000000000000000000000000000001` (32 bytes, 31 leading zeros). The `into_bigint().to_bytes_be()` returns a `Vec<u8>` whose length depends on the value — for small values, `len < 32`. The copy into `out[32 - bytes.len()..]` correctly handles this.

**Verification steps:**
1. Compute `derive_address(privateKey)` → must match `0xfcad0b19bb29d4674531d6f115237e16afce377c`
2. Compute `compute_nullifier(privateKey)` → must match `0x078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9`
3. Compute `poseidon_hash_address(address)` → must match `0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9`
4. Build a test Merkle tree containing the leaf → verify root matches
5. Run the full guest program with these inputs → verify journal is exactly 84 bytes:
   - `[0:32]` = merkleRoot
   - `[32:64]` = nullifier
   - `[64:84]` = recipient (20 bytes, raw address — NOT padded to 32 bytes)
6. Submit to a local Base fork → verify `claim()` succeeds and mints 10,000 ZKM

### E. Guest Program Build Configuration

The RISC Zero guest program requires specific build configuration to compile for the `riscv32im-risc0-zkvm-elf` target. The following files must be present in the guest program's Cargo workspace.

**`.cargo/config.toml`** (in the guest program crate root):

> ⚠️ **Note on `[build] target`:** Setting a global `[build] target` causes `cargo build` to always target riscv32, which can break host-side tooling (tests, runners) in the same workspace. Standard RISC Zero practice is to keep only the `runner` and `rustflags` in `.cargo/config.toml` and let `cargo risczero build` select the target. If you must keep `[build] target`, isolate the guest program in a separate workspace member where no host code is compiled.

```toml
[target.riscv32im-risc0-zkvm-elf]
runner = "cargo run --bin zkmist-guest-runner"

[build]
target = "riscv32im-risc0-zkvm-elf"

[unstable]
build-std = ["core", "alloc"]

# Required for getrandom 0.3+ on riscv32 targets without OS support.
# RISC Zero provides a custom entropy source via the zkVM environment.
rustflags = ["-C", "getrandom_backend=custom"]
```

**Atomic shim** (required because `riscv32im` lacks native 1-byte atomics needed by `tracing_core`):

```rust
// src/atomics.rs (or inline in main)
#![no_mangle]
pub extern "C" fn __atomic_store_1(ptr: *mut u8, val: u8, _ordering: i32) {
    unsafe { core::ptr::write_volatile(ptr, val) }
}
```

**Toolchain requirements:**
- Install via `rzup install rust` (RISC Zero custom toolchain, currently rzup v1.94.1 / cargo-risczero v3.0.5)
- `risc0-zkvm` crate version must be pinned (e.g., `v5.0.0`) — the image ID changes between versions
- `light-poseidon` v0.4.x — same version in both guest program and CLI tree builder

---

*End of PRD v6.0*
