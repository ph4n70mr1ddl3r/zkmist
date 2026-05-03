# ZKMist (ZKM) — Product Requirements Document

**Version:** 3.0  
**Date:** 2026-05-03  
**Status:** Draft  
**Author:** ZKMist Team  

---

## 1. Overview

### 1.1 Product Summary

ZKMist (ticker: **ZKM**) is an ERC-20 token deployed on **Base Chain** featuring a **privacy-preserving airdrop** mechanism. A predefined list of ~65 million qualified Ethereum addresses are eligible to claim ZKM tokens, but the claiming process is designed so that **the qualified address is never publicly linked to the receiving address**.

The claimant generates a **zero-knowledge proof** entirely on their local machine. The proof system uses **RISC Zero** — a zkVM that executes a Rust "guest program" inside a RISC-V virtual machine and produces a STARK proof of correct execution. This means the "circuit" is just **readable, auditable Rust code**, not inscrutable constraint systems.

The claimant needs only three things:
1. The **published eligibility list** (downloaded from IPFS)
2. Their **qualified Ethereum address** (via raw private key in CLI, or wallet signature in browser)
3. A **recipient address** they choose (not linked to the qualified address)

No server, no API, no trusted third party, and **no trusted setup ceremony** is required.

### 1.2 Problem Statement

Standard airdrops create a permanent, public on-chain link between a user's qualifying activity (original address) and their claiming address. This:

- **Exposes user portfolios** — anyone can trace a claim back to the qualifying address and inspect its full history and holdings.
- **Creates targeting risk** — whales or early adopters become visible targets for phishing, social engineering, or legal scrutiny.
- **Discourages participation** — privacy-conscious users may avoid claiming airdrops they are entitled to.

### 1.3 Solution

ZKMist uses a **RISC Zero zkVM** where claimants generate proofs locally by running a Rust guest program. The proof proves:

1. **Membership** — "My Ethereum address (derived from my private key, or recovered from my wallet signature) is in the published eligibility Merkle tree."
2. **Nullifier uniqueness** — a deterministic nullifier prevents double-claiming.
3. **Recipient binding** — the proof is cryptographically bound to a specific recipient address (front-running impossible).

**No trusted setup is required.** RISC Zero uses STARK-based proving, which has no toxic waste or ceremony dependency.

---

## 2. Goals & Non-Goals

### 2.1 Goals

| # | Goal | Metric |
|---|------|--------|
| G1 | Deploy ZKM as a standard ERC-20 on Base Chain | Successful deployment & verification |
| G2 | Enable anonymous claiming for all qualified addresses | Zero on-chain link between qualified and recipient address |
| G3 | Prevent double-claiming | Zero double-claims |
| G4 | Gas-efficient claim process | Claim tx cost < $0.50 USD on Base |
| G5 | Accessible to non-technical users | Web dApp claim flow (wallet signature, no CLI required) |
| G6 | Fully auditable & verifiable eligibility list | Merkle root & eligibility list published openly |
| G7 | No trusted setup | STARK-based proving — no ceremony, no toxic waste |

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
- Prefers a browser-based experience (wallet connection) over CLI.

### 3.2 Admin (Operator)

- Manages the eligibility list, Merkle tree, and claim contract.
- Responsible for deployment, monitoring, and any post-launch support.
- May need to handle edge cases (e.g., stuck claims, support).

### 3.3 Observer / Auditor

- Wants to verify that the airdrop was conducted fairly.
- Can independently reconstruct the Merkle tree from the published eligibility list.
- Can read and audit the Rust guest program source code.
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
- All qualified addresses receive the **same amount** to preserve anonymity.
- Uniform amounts ensure the claim amount reveals nothing about which address is claiming.
- Exact `CLAIM_AMOUNT` is computed after final BigQuery extraction and hardcoded in the airdrop contract at deployment.

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
    │   • Sort lexicographically for deterministic Merkle tree
    ▼
Final Eligibility List
        Format: CSV
        Published to: IPFS (CID pinned), GitHub release
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
| **Merkle Leaf** | `poseidon(address)` — ZK-friendly hash |

> **Why uniform?** Uniform amounts provide the strongest privacy guarantee — the claim amount reveals nothing about which address is claiming. Tiered amounts would create a deanonymization vector (an observer could narrow candidates by tier).

### 5.4 Eligibility List Format

The list is published as a set of chunked files for practical distribution:

```
eligibility/
├── manifest.json              # Metadata: count, merkleRoot, hash algorithm
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

The list is published on **IPFS** (pinned via Pinata/estuary) and mirrored on GitHub so anyone can audit it.

---

## 6. Anonymous Claim Protocol

### 6.1 Design Principles

1. **Local-only proof generation** — the claimant never sends their private key, qualified address, or any identifying information to any server.
2. **Two claim modes, one verifier** — CLI mode (private key) and web dApp mode (wallet signature) both produce the same public signals, verified by the same on-chain contract.
3. **On-chain reveals nothing** — only a nullifier and the recipient address appear on-chain. The qualified address is never visible.
4. **No trusted third party** — the eligibility list is public, the Merkle root is on-chain, and anyone can verify.
5. **No trusted setup** — RISC Zero uses STARK-based proving. No ceremony, no toxic waste.
6. **Auditable code** — the "circuit" is a Rust program. Anyone can read it.

### 6.2 Why RISC Zero (not circom + Groth16)

| Factor | circom + Groth16 | RISC Zero zkVM |
|--------|------------------|----------------|
| **Ethereum address derivation** | ~400K constraints (secp256k1 + keccak256 gadgets) | Native Rust: `k256` crate |
| **Web dApp (wallet sign)** | ❌ MetaMask won't expose private key | ✅ Wallet signs message → ecrecover in Rust |
| **Trusted setup** | ❌ Required (per-circuit ceremony, toxic waste) | ✅ **None** (STARK-based) |
| **Code readability** | Constraint signals (nearly unreadable) | Regular Rust code |
| **Front-running protection** | Must manually add constraints | Just hash recipient in code |
| **Audit surface** | Custom circom gadgets + circom-ecdsa | Standard Rust crypto libraries (`k256`, `sha2`) |
| **Proof generation** | ~30–120s (ECDSA constraints dominate) | ~30–90s (zkVM overhead, simpler ops) |
| **On-chain verification** | ~300K gas (Groth16 verifier) | ~300K gas (Groth16 wrapper) or ~1.5M gas (STARK) |

### 6.3 High-Level Architecture

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
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌─────────────────────────┐  ┌──────────────────────────────┐
│  CLI / Desktop App       │  │  Web dApp (Browser + WASM)    │
│                          │  │                                │
│  Inputs:                 │  │  Inputs:                       │
│   ① Eligibility list     │  │   ① Eligibility list (partial) │
│   ② Raw private key      │  │   ② Wallet signature           │
│   ③ Recipient address    │  │   ③ Recipient address          │
│                          │  │                                │
│  Mode 0: Private Key     │  │  Mode 1: Signature             │
│   • Derive address       │  │   • Recover address from       │
│     from private key     │  │     ECDSA signature             │
│   • Nullifier from key   │  │   • Nullifier from sig r-value  │
│                          │  │                                │
│  RISC Zero zkVM:         │  │  RISC Zero zkVM:               │
│   • Build Merkle tree    │  │   • Download proof chunk        │
│     (streaming)          │  │   • Generate proof (WASM)       │
│   • Generate proof       │  │     or use Bonsai (cloud)       │
│   • Submit on-chain      │  │   • Submit on-chain             │
└────────────┬─────────────┘  └──────────────┬─────────────────┘
             │                               │
             └───────────────┬───────────────┘
                             │
                             ▼  ZK proof + nullifier + recipient
┌──────────────────────────────────────────────────────────────────┐
│                       ON-CHAIN (Base)                             │
│                                                                  │
│  ┌───────────────┐      ┌──────────────────────┐                 │
│  │  ZKM Token    │◄─────│  ZKMAirdrop Claim    │                 │
│  │  (ERC-20)     │      │  Contract            │                 │
│  └───────────────┘      └──────────────────────┘                 │
│                              │                                   │
│         Receives:            │                                   │
│          • RISC Zero proof   │                                   │
│          • journal (outputs) │                                   │
│          • nullifier         │                                   │
│          • recipientAddress  │                                   │
│                              │                                   │
│         Verifies:            │                                   │
│          • STARK proof valid │                                   │
│          • journal matches   │                                   │
│          • nullifier unused  │                                   │
│          • transfers ZKM     │                                   │
│            to recipient      │                                   │
│                                                                  │
│  On-chain visibility:                                            │
│    ✗ qualified address — HIDDEN (private input to zkVM)          │
│    ✗ private key — HIDDEN                                       │
│    ✓ nullifier (opaque, not linkable to address)                 │
│    ✓ recipient address                                           │
│    ✓ zkVM proof + journal                                        │
└──────────────────────────────────────────────────────────────────┘
```

### 6.4 Nullifier Design — Deterministic, Two Modes

The nullifier is a unique, opaque value that prevents double-claiming without revealing the qualified address. It is **deterministic** — the same inputs always produce the same nullifier.

#### Mode 0 (CLI — Private Key)

```
nullifier = sha256(privateKey || "ZKMist_V1_NULLIFIER")
```

- Same private key → same nullifier → double-claim prevented.
- Cannot be computed from the published address list (requires private key).
- Cannot be reversed to recover the private key or address.

#### Mode 1 (Web dApp — Wallet Signature)

```
signedMessage = EIP-191("\x19Ethereum Signed Message:\n32" + sha256("ZKMist_V1_CLAIM" + recipientAddress))
signature = wallet.sign(signedMessage)
r = signature.r  // deterministic per RFC 6979
nullifier = sha256(r || "ZKMist_V1_NULLIFIER")
```

- The `r` value of an ECDSA signature is deterministic (RFC 6979) — the same private key signing the same message always produces the same `r`.
- Cannot be computed from the published address list (requires the private key to produce the signature).
- The `recipientAddress` is bound into the signed message, preventing front-running (changing the recipient changes the message, changes `r`, changes the nullifier).

> **Both modes produce the same on-chain format** — a `bytes32` nullifier. The contract does not know or care which mode was used.

### 6.5 Guest Program (Rust) — The "Circuit"

The RISC Zero guest program is the zkVM equivalent of a ZK circuit. It is a **regular Rust program** that runs inside the RISC-V VM. The VM produces a proof that the program executed correctly with the given inputs.

```rust
//! ZKMist Airdrop Claim — RISC Zero Guest Program
//!
//! This program proves that the claimant's Ethereum address is in the
//! eligibility Merkle tree, without revealing which address.

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
    let mode: u8 = env::read(); // 0 = private key, 1 = signature

    // --- Derive Ethereum address from private input ---
    let address: [u8; 20] = match mode {
        0 => {
            // CLI mode: derive address from raw private key
            let private_key: [u8; 32] = env::read();
            derive_address_from_private_key(&private_key)
        }
        1 => {
            // Web dApp mode: recover address from wallet signature
            let message_hash: [u8; 32] = env::read();
            let signature_r: [u8; 32] = env::read();
            let signature_s: [u8; 32] = env::read();
            let signature_v: u8 = env::read();
            recover_address_from_signature(
                &message_hash, &signature_r, &signature_s, signature_v
            )
        }
        _ => panic!("Invalid mode"),
    };

    // --- Merkle membership proof (private) ---
    let mut siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    let mut path_indices: [bool; TREE_DEPTH] = [false; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        siblings[i] = env::read();
        path_indices[i] = env::read();
    }

    // --- Verify Merkle membership ---
    let leaf = poseidon_hash_address(&address);
    let computed_root = compute_merkle_root(&leaf, &siblings, &path_indices);
    assert_eq!(
        computed_root, merkle_root,
        "Address not found in eligibility tree"
    );

    // --- Verify nullifier (computed differently per mode) ---
    let expected_nullifier = match mode {
        0 => {
            let pk: [u8; 32] = env::read();
            compute_nullifier_from_key(&pk)
        }
        1 => {
            let sig_r: [u8; 32] = env::read();
            compute_nullifier_from_r(&sig_r)
        }
        _ => unreachable!(),
    };
    assert_eq!(nullifier, expected_nullifier, "Invalid nullifier");

    // === Commit public outputs to journal ===
    env::commit(&merkle_root);
    env::commit(&nullifier);
    env::commit(&recipient);
}

/// Derive Ethereum address from secp256k1 private key.
/// Uses the k256 crate (audited, standard Rust crypto).
fn derive_address_from_private_key(key: &[u8; 32]) -> [u8; 20] {
    let signing_key = k256::ecdsa::SigningKey::from_bytes(key)
        .expect("Invalid private key");
    let verifying_key = k256::ecdsa::VerifyingKey::from(&signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let pub_key_bytes = encoded.as_bytes(); // 65 bytes: 0x04 || x || y
    let hash = Sha256::digest(&pub_key_bytes[1..65]); // keccak256 ideally
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Recover Ethereum address from ECDSA signature.
fn recover_address_from_signature(
    msg_hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    v: u8,
) -> [u8; 20] {
    let sig = k256::ecdsa::Signature::from_scalars(
        k256::elliptic_curve::ScalarPrimitive::from_slice(r).unwrap(),
        k256::elliptic_curve::ScalarPrimitive::from_slice(s).unwrap(),
    ).unwrap();
    let recovery_id = k256::ecdsa::RecoveryId::try_from(v).unwrap();
    let verifying_key = k256::ecdsa::VerifyingKey::recover_from_digest(
        k256::elliptic_curve::FieldBytes::from_slice(msg_hash),
        &sig,
        recovery_id,
    ).unwrap();
    let encoded = verifying_key.to_encoded_point(false);
    let pub_key_bytes = encoded.as_bytes();
    let hash = Sha256::digest(&pub_key_bytes[1..65]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Compute deterministic nullifier from private key.
fn compute_nullifier_from_key(key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(DOMAIN_SEPARATOR);
    hasher.finalize().into()
}

/// Compute deterministic nullifier from signature r-value.
fn compute_nullifier_from_r(r: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(r);
    hasher.update(DOMAIN_SEPARATOR);
    hasher.finalize().into()
}

/// Compute Merkle root from leaf + proof.
fn compute_merkle_root(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    indices: &[bool; TREE_DEPTH],
) -> [u8; 32] {
    let mut current = *leaf;
    for i in 0..TREE_DEPTH {
        let mut hasher = Sha256::new();
        if indices[i] {
            hasher.update(siblings[i]);
            hasher.update(current);
        } else {
            hasher.update(current);
            hasher.update(siblings[i]);
        }
        current = hasher.finalize().into();
    }
    current
}
```

> **Key insight:** The `recipient` address is a public input that is committed to the journal. The guest program does not need to constrain it further — the RISC Zero proof is bound to the journal contents. If anyone changes the recipient in the on-chain calldata, the journal hash won't match the proof, and verification fails. **Front-running is impossible.**

### 6.6 Claim Flow — CLI Mode (Step-by-Step)

1. **Download eligibility list** — The claimant downloads the published list from IPFS (~1.3 GB, chunked CSV). One-time download; cached locally.

2. **Build Merkle tree locally** — The CLI tool builds the tree in a **streaming fashion** using O(log n) memory. As it streams through the 65M sorted addresses, it finds the claimant's address and extracts its Merkle proof (26 siblings).

   > **Performance:** Streaming 65M leaves takes ~1–2 minutes on a modern computer.

3. **Provide inputs** — The claimant provides:
   - Their Ethereum **private key** (entered via interactive hidden prompt — never in shell history)
   - A **recipient address** (any Base address, preferably fresh)

4. **Generate proof** — The tool runs the RISC Zero zkVM locally:
   - The guest program derives the address, verifies Merkle membership, computes the nullifier
   - Output: STARK proof + journal (merkleRoot, nullifier, recipient)

   > **Performance:** ~30–90 seconds on a modern computer.

5. **Submit on-chain** — The claimant submits the proof + journal to the ZKMAirdrop contract on Base via any wallet. `msg.sender` is irrelevant.

6. **Contract verification:**
   - Verify the STARK proof against the on-chain verifier.
   - Verify the journal's `merkleRoot` matches the immutable on-chain root.
   - Check `usedNullifiers[journal.nullifier] == false`.
   - Set `usedNullifiers[journal.nullifier] = true`.
   - Transfer `CLAIM_AMOUNT` ZKM to `journal.recipient`.

7. **Completion** — Tokens arrive in the recipient address. **Nothing on-chain links to the qualified address.**

### 6.7 Claim Flow — Web dApp Mode (Step-by-Step)

1. **Connect qualified wallet** — The claimant connects the wallet holding their eligible Ethereum mainnet address (MetaMask, Rainbow, Coinbase Wallet, etc.).

2. **Check eligibility** — The dApp downloads the proof index (~520 MB, or a partial chunk) from IPFS and checks if the connected address is in the list.

   > If not found → "This address is not eligible (paid < 0.004 ETH in fees)."

3. **Choose recipient address** — The claimant enters or connects a **different** Base address.

   > ⚠️ "Do not fund this address from your qualified wallet."

4. **Sign message** — The dApp prompts the wallet to sign a ZKMist claim message:
   ```
   ZKMist Claim
   Recipient: 0xRecipientAddress
   ```
   The wallet signs this via `personal_sign` or `eth_signTypedData_v4`. The signature's `r` value is deterministic (RFC 6979).

5. **Generate proof** — The dApp runs the RISC Zero zkVM in the browser (WASM) or delegates to **Bonsai** (RISC Zero's cloud proving service):
   - Private inputs: signature components, Merkle proof
   - The guest program recovers the address from the signature, verifies Merkle membership
   - Output: STARK proof + journal

   > **Performance:** WASM proving ~60–180s in browser. Bonsai proving ~5–15s (but requires sending the signature to RISC Zero's servers — see §6.9).

6. **Submit on-chain** — The dApp submits the proof via the connected wallet or a relayer (gasless).

7. **Completion** — Tokens arrive. **Nothing on-chain links to the qualified address.**

### 6.8 Privacy Guarantees

| What is public on-chain | What is NOT public on-chain |
|--------------------------|-----------------------------|
| STARK proof (reveals nothing beyond validity) | Qualified (original) address |
| Nullifier (opaque, not precomputable from address) | Private key / signature components |
| Recipient address | Merkle proof / tree position |
| Claim amount (uniform — 7.69 ZKM for all 65M) | Link between qualified ↔ recipient |
| Journal (merkleRoot, nullifier, recipient only) | Mode (CLI vs web dApp) |

**Uniform amount = strongest anonymity set.** Every claim looks identical on-chain except for the nullifier and recipient address.

**msg.sender is irrelevant.** The transaction submitter can be anyone.

**Front-running is impossible.** The recipient address is committed to the journal, and the journal hash is part of the STARK proof. Changing the recipient invalidates the proof.

### 6.9 Privacy Caveats & Edge Cases

| Risk | Mitigation |
|------|------------|
| **Time correlation** — transferring ETH for gas from qualified → recipient. | Tool warns users to fund recipient from independent source (CEX, bridge). |
| **Bonsai (cloud proving) sees signature** — if the web dApp uses Bonsai, RISC Zero's servers see the signature and can recover the address. | Bonsai is optional. Users who want maximum privacy use local WASM proving (slower but fully private). Bonsai mode should display a privacy warning. |
| **Nullifier cannot be precomputed** — requires private key or signature. | ✅ Inherent in the design. |
| **No double-claim** — nullifier is deterministic per mode. | ✅ Same key → same nullifier. Same signature `r` → same nullifier. |
| **Signature replay across modes** — could a user claim in CLI mode AND web mode? | The nullifiers differ because they're derived from different sources (private key vs signature `r`). A single address could produce two different nullifiers. **This must be addressed** — see Open Question #16. |

---

## 7. Smart Contracts

### 7.1 Contracts Overview

| Contract | Description |
|----------|-------------|
| `ZKMToken` | Standard ERC-20 token contract for ZKMist |
| `ZKMAirdropVerifier` | RISC Zero STARK verifier contract (auto-generated) |
| `ZKMAirdrop` | Claim contract — verifies proof + journal + nullifier uniqueness |
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
IRiscZeroVerifier public immutable verifier;  // RISC Zero verifier
bytes32 public immutable imageId;             // Guest program image ID
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
| `claim(bytes calldata proof, bytes calldata journal, bytes32 _nullifier, address _recipient)` | Public | Claim tokens. Verifies RISC Zero proof + nullifier uniqueness. |
| `pause()` | Admin | Pause claims (emergency). |
| `unpause()` | Admin | Unpause claims. |
| `withdrawUnclaimed()` | Admin | After claim period ends, withdraw remaining tokens to treasury. |
| `usedNullifiers(bytes32)` | View | Check if a nullifier has been used. |
| `isClaimed(bytes32)` | View | Alias for nullifier check. |

#### Claim Function Pseudocode

```solidity
uint256 public constant CLAIM_AMOUNT = 7_692_307_000_000_000_000; // ~7.69 ZKM

function claim(
    bytes calldata _proof,        // RISC Zero STARK proof
    bytes calldata _journal,      // Journal: [merkleRoot, nullifier, recipient]
    bytes32 _nullifier,
    address _recipient
) external {
    require(!paused, "Claims paused");
    require(block.timestamp >= claimStart, "Not started");
    require(block.timestamp <= claimEnd, "Claim period ended");
    require(!usedNullifiers[_nullifier], "Already claimed");

    // Verify the RISC Zero proof
    // This checks: proof is valid, imageId matches our guest program,
    // and the journal was honestly computed from the private inputs
    bytes32 journalRoot = bytes32(sha256(_journal));
    verifier.verify(_proof, imageId, journalRoot);

    // Decode journal and validate public outputs
    bytes32 journalMerkleRoot = abi.decode(_journal[0:32], (bytes32));
    bytes32 journalNullifier = abi.decode(_journal[32:64], (bytes32));
    address journalRecipient = abi.decode(_journal[64:84], (address));

    require(journalMerkleRoot == merkleRoot, "Root mismatch");
    require(journalNullifier == _nullifier, "Nullifier mismatch");
    require(journalRecipient == _recipient, "Recipient mismatch");

    // Mark nullifier as used
    usedNullifiers[_nullifier] = true;

    // Transfer tokens to recipient
    zkmToken.transfer(_recipient, CLAIM_AMOUNT);

    emit Claimed(_nullifier, CLAIM_AMOUNT, _recipient);
}
```

**Key design properties:**
- `msg.sender` is **not used** for verification — anyone can submit the claim.
- The qualified address is **never visible** on-chain — it's a private input to the zkVM.
- The guest program image ID is immutable — only proofs from the published Rust program are accepted.
- The journal is validated inside the STARK proof — tampering with the recipient invalidates the proof.
- The nullifier is verified inside the zkVM (guest program asserts `nullifier == expectedNullifier`).

### 7.4 Events

```solidity
event Claimed(bytes32 indexed nullifier, uint256 amount, address indexed recipient);
event Paused();
event Unpaused();
event Withdrawn(address to, uint256 amount);
```

### 7.5 Published Data Artifacts

All data and artifacts needed for proof generation are **published and publicly verifiable**. No server interaction is required.

#### Published Files (IPFS + GitHub mirror)

```
zkmist-airdrop/
├── manifest.json                      # Metadata (see §5.4)
├── addresses_00000001.csv              # Sorted address list (1M rows each, ~65 files)
├── addresses_00000002.csv
├── ...
├── merkle_root.txt                    # The Merkle root (also on-chain)
├── guest_program.elf                  # Compiled RISC Zero guest program (RISC-V binary)
├── image_id.txt                       # Guest program image ID (also on-chain)
├── guest_program_source.tar.gz        # Full Rust source code (auditable)
└── risc_zero_verifier.sol             # Auto-generated verifier contract
```

> **No proving key.** Unlike Groth16, RISC Zero does not require a proving key or trusted setup. The guest program binary and image ID are all that's needed.

#### Local Merkle Tree Construction (Streaming)

The claimant's CLI tool builds the Merkle tree locally from the published address list using a **streaming algorithm** that requires only O(log n) memory:

```
Streaming Merkle Tree Builder:

1. Download sorted address list from IPFS (stream, don't load all at once)
2. For each address (in sorted order):
   a. Compute leaf = poseidon(address)
   b. Push leaf onto stack
   c. While top 2 elements on stack are at the same level:
      - Pop both, compute parent = sha256(left || right)
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

---

## 8. Claimant Tool & dApp

### 8.1 Two Claim Modes

| Mode | Input | Target User | Privacy |
|------|-------|-------------|---------|
| **CLI / Desktop App** (Mode 0) | Raw private key (hidden prompt) | Power users | Maximum — no third party involved |
| **Web dApp** (Mode 1) | Wallet signature (MetaMask, etc.) | All users | High — signature stays local (or Bonsai sees it) |

Both modes produce proofs verified by the **same on-chain contract** with the **same public signals**.

### 8.2 CLI / Desktop App — Claim Flow

```
$ zkmist claim --recipient 0xRecip...

[1/5] Downloading eligibility list from IPFS...
       ████████████████████████████████ 100%  (1.3 GB)

[2/5] Building Merkle tree (streaming)...
       Processing 65,000,000 addresses...
       Found your address at index 42,317,891
       Merkle proof extracted (26 levels)
       ✓ Root matches on-chain value

[3/5] Enter private key (hidden):
       ********

[4/5] Generating RISC Zero proof...
       Guest program: zkmist-claim (image_id: 0xabc...)
       zkVM execution: 2,847,331 cycles
       ████████████████████████████████ done  (45s)
       Nullifier: 0x4a7f...e2c1

[5/5] Submit claim?
       Recipient: 0xRecip...EntAddress
       Amount:    7.69 ZKM
       Gas cost:  ~$0.01 (Base)

       [Y/n] Y

       Transaction submitted: 0xabc123...
       ✓ Claimed! 7.69 ZKM → 0xRecip...EntAddress

       Your qualified address is NOT visible on-chain.
```

### 8.3 Web dApp — Claim Flow

```
Step 1: "Connect Qualified Wallet"
        └─ Connect MetaMask / Rainbow / Coinbase Wallet
        └─ dApp checks eligibility via proof index download from IPFS
        └─ If not found → "This address is not eligible"

Step 2: "Verify Eligibility" ✓
        └─ Shows: "You are eligible for ~7.69 ZKM tokens"

Step 3: "Choose Recipient Address"
        └─ Option A: Connect a different wallet (on Base)
        └─ Option B: Paste any Base address manually
        └─ ⚠️ "Do not fund this address from your qualified wallet"

Step 4: "Sign Claim Message"
        └─ Wallet prompts: "Sign ZKMist Claim for 0xRecipient..."
        └─ User clicks "Sign" (free, no gas)
        └─ dApp extracts deterministic signature r-value

Step 5: "Download Merkle Proof"
        └─ Downloads the relevant proof chunk from IPFS (~few MB)
        └─ Verified against the on-chain Merkle root

Step 6: "Generate Proof"
        └─ Option A: Local (WASM) — ~60–180s, fully private
        └─ Option B: Bonsai (cloud) — ~5–15s, ⚠️ Bonsai sees your signature
        └─ Progress bar

Step 7: "Submit Claim"
        └─ Option A: Submit directly (recipient needs ETH on Base)
        └─ Option B: Submit via relayer (gasless)

Step 8: "Claim Complete!" ✓
        └─ Shows tx hash, link to BaseScan
        └─ "Your qualified address is NOT linked to your recipient address"
```

### 8.4 Technology Stack

| Layer | Choice |
|-------|--------|
| **zkVM** | RISC Zero (risc0-zkvm) |
| **Guest Program** | Rust (compiled to RISC-V) |
| **Proof System** | STARK (RISC Zero) with optional Groth16 wrapper for gas reduction |
| **Crypto Libraries** | `k256` (secp256k1), `sha2` (SHA-256), `poseidon` |
| **CLI Tool** | Rust |
| **Web dApp** | Next.js / React + RISC Zero WASM |
| **Cloud Proving** | Bonsai (RISC Zero) — optional |
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
| **Snapshot** | T-30 days | BigQuery extraction finalized; eligibility list published |
| **Publication** | T-14 days | Eligibility list + Merkle root + guest program source published for audit |
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
| **Guest Program Audit** | Audit the Rust guest program source code (readable, not constraints) |
| **Pause Mechanism** | Admin can pause claims if vulnerability discovered |
| **No Upgradeability** | Immutable contracts (no proxy pattern) — simplicity is security |
| **Renounce Admin** | Admin role can be renounced after claim period |

### 10.2 Privacy Security

| Measure | Details |
|---------|--------|
| **Private key never leaves local machine** | zkVM execution is entirely local (CLI or browser WASM). |
| **No server dependency** | No Proof API, no backend. All data is published on IPFS. |
| **No trusted setup** | STARK-based proving — no ceremony, no toxic waste. |
| **Deterministic nullifier** | Prevents double-claim without requiring server-side state. |
| **Front-running impossible** | Recipient is committed to the journal, which is part of the STARK proof. |
| **Bonsai privacy trade-off** | Bonsai (cloud proving) sees the signature. Display warning. Local proving is fully private. |
| **User Guidance** | Clear warnings about not linking addresses via on-chain transfers. |

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
| **Proof System** | RISC Zero zkVM (STARK) |
| **Guest Program** | Rust, compiled to RISC-V ELF |
| **Trusted Setup** | **None** (STARK-based) |
| **Merkle Tree Hash** | SHA-256 (interior nodes), Poseidon (leaf) |
| **Merkle Tree Depth** | 26 levels (65M leaves, padded to 2²⁶) |
| **Merkle Proof Size** | 26 × 32 bytes = 832 bytes per claim |
| **Nullifier (CLI)** | sha256(privateKey ∥ "ZKMist_V1_NULLIFIER") |
| **Nullifier (Web)** | sha256(signature_r ∥ "ZKMist_V1_NULLIFIER") |
| **Claim Amount** | 7.69 ZKM (constant — uniform for all 65M addresses) |
| **Claim Modes** | 0: Private key (CLI), 1: Wallet signature (Web dApp) |
| **On-chain Verification** | RISC Zero STARK verifier + journal validation |
| **Proof Generation (local)** | ~30–90s (CLI), ~60–180s (browser WASM) |
| **Proof Generation (Bonsai)** | ~5–15s (cloud, privacy trade-off) |
| **Claim Method** | Anyone submits proof — msg.sender irrelevant |
| **Claim Period** | 90 days |
| **Gas Target** | < $0.50 per claim (~300K gas with Groth16 wrapper, ~1.5M gas raw STARK) |
| **Solidity Version** | ^0.8.24 |
| **Eligibility Data Source** | Google BigQuery |
| **Qualified Addresses** | ~65,000,000 |
| **Data Distribution** | IPFS (chunked CSV) + GitHub mirror |

---

## 12. Milestones & Deliverables

| # | Milestone | Estimated Duration |
|---|-----------|---------------------|
| 1 | Run final BigQuery extraction & validate ~65M address list | Week 1 |
| 2 | Build Merkle tree, compute root, publish to IPFS | Week 2 |
| 3 | Write RISC Zero guest program (Rust) + test with small tree | Weeks 2–3 |
| 4 | Develop & test smart contracts (ZKMToken + Verifier + ZKMAirdrop) | Weeks 3–4 |
| 5 | Build CLI tool (download list → stream tree → generate proof → submit) | Weeks 3–4 |
| 6 | Build web dApp (wallet signature → proof generation → submit) | Weeks 4–6 |
| 7 | Internal security review + testnet deployment | Week 6 |
| 8 | External audit (guest program + contracts) | Weeks 6–8 |
| 9 | Set up Bonsai integration (optional cloud proving for web dApp) | Week 7 |
| 10 | Deploy to Base mainnet | Week 9 |
| 11 | Open claim window | Week 9 |
| 12 | Close claim window + withdraw unclaimed | Week 22 |
| 13 | Renounce admin / decentralize | Week 23 |

---

## 13. Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | What is the exact eligibility criteria / snapshot source? | ✅ **Resolved** — ≥ 0.004 ETH cumulative gas fees on Ethereum mainnet before 2026-01-01 UTC. |
| 2 | Will claim amounts be uniform or tiered? | ✅ **Resolved** — Uniform (~7.69 ZKM per address). |
| 3 | Proof system: circom+Groth16 vs RISC Zero? | ✅ **Resolved** — RISC Zero zkVM. Eliminates trusted setup, enables web dApp via wallet signatures, produces auditable Rust code. |
| 4 | Will a relayer service be built or use an existing one (Gelato)? | 🔲 Pending |
| 5 | Should the eligibility list be updatable (e.g., to fix errors)? | 🔲 Pending (recommend no — fixed list) |
| 6 | What happens to unclaimed tokens after the claim window? | 🔲 Pending (recommend → treasury) |
| 7 | Will the admin role be fully renounced post-claim? | 🔲 Pending (recommend yes) |
| 8 | Sybil resistance beyond the 0.004 ETH fee threshold? | ✅ **Resolved** — 0.004 ETH (~$8–12) is a meaningful Sybil filter. |
| 9 | Token listing strategy — DEX liquidity pool at launch or after claim period? | 🔲 Pending |
| 10 | Legal / compliance review needed for the airdrop? | 🔲 Pending |
| 11 | Exact snapshot timestamp/block for 2025-12-31 23:59:59 UTC? | 🔲 Pending |
| 12 | How to handle addresses that are contracts (smart contracts / multisigs)? | 🔲 Pending (recommend: include all — contracts are eligible too) |
| 13 | Should Bonsai (cloud proving) be offered as an option for the web dApp? | 🔲 Pending (recommend yes, with privacy warning: Bonsai sees the signature) |
| 14 | Groth16 wrapper on STARK for lower gas (~300K) or raw STARK (~1.5M gas)? | 🔲 Pending (recommend Groth16 wrapper — cheaper per claim at the cost of a larger verifier contract) |
| 15 | What if the actual qualified count differs slightly from 65M after final query? | 🔲 Pending (adjust CLAIM_AMOUNT to ensure total = 500M ZKM) |
| 16 | **Cross-mode double-claim:** Can a user claim via CLI (nullifier from private key) AND web dApp (nullifier from signature r-value) for the same address? | 🔲 **Critical — unresolved.** The nullifiers differ per mode, so both would pass the uniqueness check. Options: (a) accept it (each address gets max 2× claim — budget for 130M claims), (b) store a separate nullifier per mode, (c) make the nullifier mode-agnostic by deriving from the address directly (reduces privacy). |
| 17 | Guest program keccak256 vs SHA-256 for address derivation? | 🔲 Pending (keccak256 is the Ethereum standard but requires a keccak crate in RISC Zero guest; SHA-256 is native in RISC Zero but doesn't match Ethereum addresses. Recommend keccak256.) |
| 18 | Should the web dApp download the full list + stream tree (trustless, ~1.3 GB) or use a compact proof index (~520 MB) that maps address → leaf index? | 🔲 Pending (recommend proof index for web dApp, full list for CLI) |

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **Nullifier** | A deterministic hash derived from the private key (CLI mode) or signature r-value (web mode). Used to prevent double-claiming without revealing the qualified address. |
| **Merkle Tree** | A binary hash tree where each leaf is a Poseidon hash of a qualified Ethereum address. The root is stored on-chain. |
| **Merkle Proof** | The 26 sibling hashes needed to prove a specific leaf is part of the tree. |
| **Base Chain** | Coinbase's Ethereum Layer-2 blockchain. |
| **RISC Zero** | A zero-knowledge virtual machine (zkVM) that proves correct execution of Rust programs compiled to RISC-V. |
| **Guest Program** | The Rust program that runs inside the RISC Zero zkVM. Equivalent to a "circuit" in other ZK frameworks. |
| **Journal** | The public output of a RISC Zero guest program execution. Contains the values committed via `env::commit()`. |
| **Image ID** | A hash identifying a specific guest program binary. Stored on-chain to ensure only the intended program's proofs are accepted. |
| **STARK** | Scalable Transparent ARgument of Knowledge. A proof system that requires no trusted setup. Used by RISC Zero. |
| **Bonsai** | RISC Zero's cloud proving service. Generates proofs on behalf of users (faster but less private than local proving). |
| **Relayer** | A service that submits transactions on behalf of a user. The relayer pays gas; the user only signs a message. |

---

## 15. Appendix

### A. Reference Implementations

- [RISC Zero — zkVM documentation](https://dev.risczero.com/)
- [RISC Zero — Bonsai cloud proving](https://dev.risczero.com/bonsai/)
- [circom-ecdsa — ECDSA verification in circom (v2.0 alternative)](https://github.com/0xPARC/circom-ecdsa)
- [Semaphore Protocol — Privacy-preserving group proofs](https://semaphore.pse.dev/)
- [Tornado Cash — ZK-based private transactions](https://github.com/tornadocash)
- [snarkjs — ZK proof generation and verification](https://github.com/iden3/snarkjs)

### B. Gas Estimation (Base Chain)

| Operation | Estimated Gas | Estimated Cost (Base) |
|-----------|---------------|------------------------|
| Deploy ZKMToken | ~1,200,000 | ~$0.05 |
| Deploy RISC Zero Verifier (STARK) | ~6,000,000 | ~$0.25 |
| Deploy RISC Zero Verifier (Groth16 wrapper) | ~4,500,000 | ~$0.20 |
| Deploy ZKMAirdrop | ~1,000,000 | ~$0.04 |
| Claim (raw STARK verification) | ~1,500,000 | ~$0.07 |
| Claim (Groth16 wrapper) | ~300,000 | ~$0.015 |
| Nullifier Storage (SSTORE cold) | ~20,000 | ~$0.001 |

> *Gas estimates based on Base average gas price of ~0.1 Gwei & ETH at $3,000.*
> *The Groth16 wrapper reduces per-claim gas from ~1.5M to ~300K at the cost of a larger verifier deployment. Recommended for 65M+ potential claims.*

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
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
      ┌──────────────────┐        ┌──────────────────┐
      │  CLI (Mode 0)     │        │  Web dApp (Mode 1)│
      │                   │        │                    │
      │  ① Download list  │        │  ① Connect wallet  │
      │  ② Stream tree    │        │  ② Sign message    │
      │  ③ Enter privkey  │        │  ③ Download proof  │
      │     (hidden)      │        │     chunk           │
      │  ④ zkVM: derive   │        │  ④ zkVM: ecrecover │
      │     addr from key │        │     addr from sig   │
      │  ⑤ Prove + submit │        │  ⑤ Prove + submit  │
      └──────────┬────────┘        └──────────┬─────────┘
                 │                            │
                 └────────────┬───────────────┘
                              │  STARK proof + journal
                              │  [merkleRoot, nullifier, recipient]
                              ▼
                   ┌────────────────────────┐
                   │  Base Chain             │
                   │                          │
                   │  ZKMAirdrop Contract:    │
                   │   • Verify STARK proof   │
                   │   • Validate journal     │
                   │   • Check nullifier      │
                   │   • Transfer ZKM         │
                   │                          │
                   │  On-chain sees:          │
                   │   ✓ nullifier (opaque)   │
                   │   ✓ recipient address    │
                   │   ✗ qualified address    │
                   └────────────────────────┘
```

### D. Cross-Mode Double-Claim Analysis (Open Question #16)

The most critical unresolved issue: **can a user claim twice by using both modes?**

```
CLI mode nullifier:   sha256(privateKey || "ZKMist_V1_NULLIFIER")
Web dApp nullifier:   sha256(signature_r || "ZKMist_V1_NULLIFIER")
```

These produce **different nullifiers** for the same address because they're derived from different inputs (private key vs signature r-value). The contract cannot detect that both nullifiers belong to the same address.

**Options:**

| Option | Description | Trade-off |
|--------|-------------|-----------|
| **A. Accept 2× claims** | Budget for up to 130M claims (reduce per-address amount to ~3.85 ZKM) | Simplest; all addresses treated equally |
| **B. Separate nullifier namespaces** | Contract tracks `usedNullifiersCLI` and `usedNullifiersWeb` separately; each address can claim once per mode | Still allows 2× claims per address |
| **C. Derive nullifier from address** | `nullifier = sha256(address || domain)` — same regardless of mode | **Breaks privacy** — address is no longer hidden (it's the nullifier pre-image) |
| **D. Require same nullifier derivation** | Both modes must produce the same nullifier. Web mode signs a message that includes a nullifier commitment; the nullifier is derived from the private key even in web mode. | Requires a way to derive the nullifier from the private key in web mode without exposing the key. Possible: user signs `(nullifier_seed, recipient)` where `nullifier_seed = sha256(privateKey || domain)` — but this requires computing the seed off-circuit, which means the web dApp needs the private key. Circular. |
| **E. Single mode only** | Only offer web dApp mode (wallet signature). No CLI mode. | Simplest. No cross-mode issue. But removes power-user option. |

> **Recommendation:** Option A (accept 2× claims, reduce per-address to ~3.85 ZKM) or Option E (web-only). The privacy loss from Option C is unacceptable. Option D is technically circular.

---

*End of PRD v3.0*
