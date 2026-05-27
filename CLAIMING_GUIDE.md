# ZKMist (ZKM) — Step-by-Step Claim Guide

> **🚀 V2 Planned:** This guide describes the V1 (RISC Zero) claiming process.
> A V2 (Halo2-KZG) redesign is planned that would reduce proof generation to
> **~10-30 seconds**. V2 is not yet implemented — see [V2_PLAN.md](./V2_PLAN.md).
> V1 and V2 would be separate token contracts.

A detailed walkthrough for claiming your **10,000 ZKM** tokens via the ZKMist privacy-preserving airdrop on Base.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Am I Eligible?](#2-am-i-eligible)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
5. [Claiming Step-by-Step](#5-claiming-step-by-step)
   - [Step 1: Download the Eligibility List](#step-1-download-the-eligibility-list)
   - [Step 2: Check Your Eligibility](#step-2-check-your-eligibility)
   - [Step 3: Generate Your ZK Proof](#step-3-generate-your-zk-proof)
   - [Step 4: Submit Your Claim](#step-4-submit-your-claim)
   - [Step 5: Verify Your Tokens](#step-5-verify-your-tokens)
6. [Privacy Best Practices](#6-privacy-best-practices)
7. [Using a Relayer](#7-using-a-relayer)
8. [Troubleshooting](#8-troubleshooting)
9. [FAQ](#9-faq)

---

## 1. Overview

**ZKMist (ZKM)** is a fully community-owned, privacy-preserving ERC-20 token on **Base** (chain ID: 8453).

- **~64.1 million** Ethereum addresses are eligible
- Each claimant receives exactly **10,000 ZKM**
- Claims are **anonymous** — your qualifying address is never revealed on-chain
- **First-come, first-served** — only **1,000,000 claims** are available
- Claim deadline: **2027-01-01 00:00:00 UTC**
- No team allocation, no investors, no pre-mine. 100% goes to claimants.

---

## 2. Am I Eligible?

You are eligible if your Ethereum mainnet address meets **both** criteria:

| Criterion | Requirement |
|-----------|-------------|
| **Total gas fees paid** | ≥ **0.004 ETH** (cumulative, across all successful transactions) |
| **Cutoff date** | Before **2026-01-01 00:00:00 UTC** |

> **Note:** Only Ethereum L1 mainnet transactions count (not L2s). Only **successful** transactions (not reverts) are included. ~$8–12 at average prices — this filters out dust/spam and captures virtually all real users.

> **Contract wallets** (multisigs, Safes, etc.) may appear in the eligibility list but **cannot claim** because they lack a single private key needed for proof generation.

The eligibility list is published on GitHub Releases. You'll download it in Step 1 and check your address(es) in Step 2.

---

## 3. Prerequisites

### 3.1 Hardware & Disk

| Resource | Minimum |
|----------|---------|
| **RAM** | ~4 GB (for Merkle tree construction + ~2 GB for proof generation) |
| **Disk space** | ~3 GB (eligibility list + Merkle tree cache + proof files) |
| **Internet** | To download ~1.3 GB eligibility list (one time) |

### 3.2 Software

| Tool | How to install |
|------|---------------|
| **Rust** (stable) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` |
| **RISC Zero toolchain** | Install Rust first, then:<br>`curl -L https://risczero.com/install \| bash`<br>`rzup install rust` |
| **Git** | Already installed on most systems. For cloning: `git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git` |

### 3.3 Base Chain Setup

To submit your claim on Base, you'll need:

- **A Base RPC URL** — public endpoints like `https://mainnet.base.org` work, or use a provider like Alchemy, Infura, QuickNode
- **~$0.15 worth of ETH on Base** — to pay gas for the claim transaction (~510K gas)
- **A wallet** — for signing the claim transaction (this can be any wallet; your qualifying address's private key is used only locally for proof generation and never leaves your machine)

> **Gas cost:** Claims cost about **510K gas** on Base, which is roughly **~$0.15** at typical Base gas prices.

---

## 4. Installation

### 4.1 Clone the Repository

```shell
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist
```

> The `--recursive` flag is important — it pulls in the Solidity submodules needed for contract dependencies.

### 4.2 Build the CLI

```shell
cargo build --release -p zkmist-cli
```

This compiles the `zkmist` binary to `target/release/zkmist`. It may take a few minutes on first build.

### 4.3 Build the Guest Program

```shell
cargo risczero build --manifest-path guest/Cargo.toml
```

This compiles the RISC Zero guest program (the ZK proof logic). This is needed once before you can generate proofs.

### 4.4 Verify Installation

```shell
./target/release/zkmist --help
```

You should see a list of available commands: `fetch`, `check`, `prove`, `submit`, `verify`, `status`.

---

## 5. Claiming Step-by-Step

### Step 1: Download the Eligibility List

```shell
./target/release/zkmist fetch
```

**What happens:**
- Downloads the eligibility list from GitHub Releases (~1.3 GB). This is a list of all ~64.1M qualified Ethereum addresses.
- Verifies the data integrity using SHA-256 checksums and the Merkle root.
- Builds and caches the Merkle tree locally so you won't need to rebuild it for future proof generations.

**Time:** 5–15 minutes depending on your internet speed.

**Output location:** `~/.zkmist/eligibility/`

---

### Step 2: Check Your Eligibility

Before spending time generating a proof, verify your address is actually in the list:

```shell
./target/release/zkmist check 0xYourEthereumAddress...
```

**Example:**
```shell
./target/release/zkmist check 0x742d35Cc6634C0532925a3b844Bc9e7595f235Cc
```

**Possible outputs:**

| Output | Meaning |
|--------|---------|
| `✓ Eligible` | Your address is in the eligibility list. Proceed to Step 3. |
| `✗ Not in eligibility list` | Your address did not meet the ≥0.004 ETH fee threshold before the cutoff. |
| `✗ Eligibility list not downloaded` | Run `zkmist fetch` first. |

> **Privacy note:** The check runs entirely offline against your local copy of the eligibility list. No data is sent anywhere. You can check as many addresses as you want.

---

### Step 3: Generate Your ZK Proof

This is the core step — it produces a cryptographic proof that you own an eligible address **without revealing which address**.

```shell
./target/release/zkmist prove
```

**What you'll be prompted for:**

#### 3a. Private Key (hidden input)

Enter the private key of your **eligible** Ethereum address. This input is hidden (no echo) for security.

```
Enter private key (hidden): ********
→ Address: 0x742d...35Cc ✓ Eligible
→ Nullifier: 0x4a7f...e2c1
```

> **⚠️ CRITICAL:** Your private key never leaves your machine. The ZK proof is generated entirely locally. However, as a security best practice, consider using a hardware wallet to sign a message proving ownership, or transfer any remaining assets from this address before claiming if you're cautious. The ZKMist software is open-source and auditable — review the guest program code at `guest/src/main.rs` if you have concerns.

#### 3b. Recipient Address

Enter the Base address where you want to receive your 10,000 ZKM tokens.

```
Recipient address: 0xYourBaseAddress...
```

> **⚠️ IRREVOCABLE — READ CAREFULLY:**
>
> - **You cannot change the recipient after the proof is generated.** The recipient is baked into the cryptographic proof.
> - **You cannot re-claim.** Once your nullifier is used, your eligible address cannot claim again — ever.
> - **Do NOT use address(0).** The CLI will reject it. Tokens minted to the zero address are irreversibly burned.
> - **Triple-check the recipient address before confirming.** Copy-paste it and verify the first 4 and last 4 characters.

#### 3c. Proof Generation

After confirming the inputs, the zkVM runs locally:

```
[1/4] Loading eligibility list...
       Using cached list: ~/.zkmist/eligibility/

[2/4] Building Merkle tree...
       Processing 64,116,228 addresses... done (1m 23s)
       Found your address at index 42,317,891
       ✓ Root matches on-chain: 0xabc123...

[3/4] Enter credentials:
       Private key (hidden): ********
       → Address: 0x742d...35Cc ✓ Eligible
       → Nullifier: 0x4a7f...e2c1
       Recipient address: 0xRecip...EntAddress

[4/4] Generating proof...
       Guest: zkmist-claim-v1 | Cycles: 2,847,331
       ████████████████████████████████ done (45 min)

       ✓ Proof saved: ./zkmist_proof_YYYY-MM-DD.json

       ⚠️  RECIPIENT IS IRREVOCABLE — triple-check before submitting.
       10,000 ZKM will be minted to 0xRecip...EntAddress on claim.
       Run: zkmist submit ./zkmist_proof_YYYY-MM-DD.json
       Or send to any relayer.
```

**Time:** ~1–2 minutes for Merkle tree reconstruction, then ~30–90 minutes for STARK proof generation (single-threaded). The CLI will warn you before starting this step.

**Output:** A proof file saved to your current directory (e.g., `zkmist_proof_2026-05-24.json`).

#### What the proof contains

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

The proof is self-contained. Anyone can submit it on your behalf, but **no one can modify the recipient or nullifier** — the proof would become invalid.

---

### Step 4: Submit Your Claim

You have three options for submission. Choose based on your privacy and convenience preferences.

#### Option A: Direct Submission (Simplest)

Submit the proof yourself from your machine:

```shell
./target/release/zkmist submit ./zkmist_proof_YYYY-MM-DD.json
```

**Requirements:**
- ETH on Base to pay gas (~$0.15)
- A configured RPC endpoint (set via `ETH_RPC_URL` or `--rpc-url` flag)

```shell
# Example with explicit RPC and private key
export ETH_RPC_URL=https://mainnet.base.org
./target/release/zkmist submit ./zkmist_proof_YYYY-MM-DD.json --private-key 0xYourBaseWalletKey
```

> **Privacy implication:** The transaction sender (gas payer) is linked on-chain to the claim. If your Base wallet is linked to your identity, an observer could correlate you to the claim. For stronger privacy, use Option B (relayer) or fund the submitting wallet from an independent source.

#### Option B: Use a Relayer (More Private)

Send your `proof.json` file to any permissionless relayer service. The relayer submits the proof and pays gas on your behalf (possibly charging a small fee).

**What the relayer sees:**
- The ZK proof
- The nullifier (opaque hash — cannot be reversed to your address)
- The recipient address

**What the relayer CANNOT do:**
- Modify the recipient (proof would break)
- Steal your tokens (they're minted to the recipient in the proof)
- Learn your qualifying Ethereum address

**How to find relayers:** Community-operated relayers will be listed on the ZKMist GitHub and community channels. Anyone can build and operate a relayer — it's fully permissionless.

#### Option C: Manual Submission

Submit via any contract interaction tool (BaseScan, cast, ethers, etc.):

```shell
# Using cast (Foundry)
cast send 0xAirdropContractAddress \
  "claim(bytes,bytes,bytes32,address)" \
  0x...proof_hex \
  0x...journal_hex \
  0x...nullifier \
  0xRecipientAddress \
  --rpc-url https://mainnet.base.org \
  --private-key 0xYourBaseWalletKey
```

---

### Step 5: Verify Your Tokens

#### 5a. Check the transaction

After submission, you'll receive a transaction hash. Look it up on [basescan.org](https://basescan.org). The `Claimed` event will be emitted:

```
Event: Claimed(nullifier, amount, recipient, totalClaims)
```

#### 5b. Check your ZKM balance

Add the ZKM token to your wallet:

| Parameter | Value |
|-----------|-------|
| **Contract Address** | (deployed contract address — see GitHub/community) |
| **Symbol** | ZKM |
| **Decimals** | 18 |

Your balance should show **10,000 ZKM**.

#### 5c. Check claim window status

```shell
./target/release/zkmist status
```

```
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

---

## 6. Privacy Best Practices

To maximize your privacy when claiming, follow this checklist:

| # | Step | Why |
|---|------|-----|
| **1** | **Use a fresh recipient address** — an address that has never transacted on-chain before | Prevents linking the recipient to any known identity |
| **2** | **Fund the recipient from an independent source** — not from your qualified address or any address linked to you | Prevents gas-funding correlation between your identity and the recipient |
| **3** | **Use a relayer** instead of submitting directly | Avoids direct on-chain link between gas payer and recipient |
| **4** | **Never publish both addresses** — don't mention your qualified and recipient addresses in the same context (social media, forums, ENS) | Prevents off-chain correlation |
| **5** | **Claim during high-activity periods** — when many others are claiming | Reduces timing-based narrowing of which address is being claimed |
| **6** | **Wait before moving tokens** — don't immediately transfer ZKM after receiving them | Avoids linking the claim transaction to subsequent token movements |
| **7** | **Verify the proof locally before submitting** — run `zkmist verify proof.json` | Confirms the proof is valid without revealing anything on-chain |

### Privacy Guarantee

| Visible on-chain | Remains hidden |
|-----------------|----------------|
| ZK proof | Your qualified Ethereum address |
| Nullifier (opaque Poseidon hash) | Your private key |
| Recipient address (where tokens go) | Your position in the eligibility tree |
| Claim amount (10,000 ZKM for everyone) | The link between qualified ↔ recipient |

---

## 7. Using a Relayer

### What is a relayer?

A relayer is a service that submits your `proof.json` to the ZKMAirdrop contract on Base, paying the gas fee on your behalf. Relayers are permissionless — anyone can operate one.

### How it works

```
You                          Relayer                       Base
 │                              │                             │
 │  Send proof.json ──────────▶ │                             │
 │                              │  claim(proof, ...) ───────▶ │
 │                              │  ← gas paid by relayer     │
 │                              │  ← tokens minted to YOU    │
 │  ← confirmation (optional)   │                             │
```

### What to look for in a relayer

- **Fee transparency** — clear fee structure (flat fee, percentage, or free)
- **No custody** — the relayer never holds your tokens; they're minted directly to your recipient address
- **Proof validation** — good relayers validate your proof locally before submitting (saving gas on invalid proofs)
- **Reputation** — community-vetted relayers with public track records

### Running your own relayer

If you want to run a relayer for others or yourself:

1. Set up a Base wallet with ETH for gas
2. Accept proof files from users (API, bot, web form)
3. Optionally validate proofs locally (`zkmist verify proof.json`)
4. Submit valid proofs to the contract using your wallet
5. Optionally charge a service fee (out of band, since tokens go directly to the claimant)

**Relayers cannot:**
- Modify the recipient address
- Claim tokens for themselves
- Learn the qualified Ethereum address
- Front-run claims (recipient is bound to the proof)

---

## 8. Troubleshooting

### 8.1 Build Issues

| Problem | Solution |
|---------|----------|
| `cargo: command not found` | Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| `cargo risczero: no such command` | Install RISC Zero toolchain: `curl -L https://risczero.com/install \| bash && rzup install rust` |
| Guest build fails on `riscv32im` target | Make sure you ran `rzup install rust` and that `.cargo/config.toml` has the correct target configuration |
| `light-poseidon` build errors | Requires `ark-bn254`. Ensure the workspace `Cargo.toml` has the correct features enabled |
| `foundry: command not found` | Only needed for contract development, not for claiming. Skip if you're just a claimant. |

### 8.2 Fetch Issues

| Problem | Solution |
|---------|----------|
| Download fails | Check your internet connection and GitHub availability. Retry `zkmist fetch`. |
| SHA-256 checksum mismatch | Delete `~/.zkmist/eligibility/` and re-run `zkmist fetch`. The data may have been corrupted during download. |
| Disk full | You need ~3 GB free. Clear space and retry. |
| Fetch never completes | Try running with `--timeout 600` or check your firewall settings. |

### 8.3 Proof Generation Issues

| Problem | Solution |
|---------|----------|
| "Not in eligibility list" | Your address didn't meet the ≥0.004 ETH cumulative fee threshold before the cutoff. Double-check that you're using an L1 mainnet address (not L2). |
| Out of memory (OOM) | You need ~4 GB RAM. Close other applications or use a machine with more memory. The streaming tree builder keeps usage low but still needs ~2 GB peak. |
| Proof generation takes >5 minutes | First run is slower (cold cache). Subsequent runs with the cached tree are faster (~30–90s). Ensure you have no CPU throttling. |
| "Guest program not found" | You need to build it first: `cargo risczero build --manifest-path guest/Cargo.toml` |
| "Root mismatch" | The on-chain Merkle root differs from your local root. Your eligibility list may be outdated — re-run `zkmist fetch`. |
| CLI hangs at "Enter private key" | This is expected — the input is hidden. Type your key and press Enter (you won't see any characters appear). |

### 8.4 Submission Issues

| Problem | Solution |
|---------|----------|
| "Claim period ended" | The deadline (2027-01-01) has passed or 1M claims have been reached. Check with `zkmist status`. |
| "Claim cap reached" | All 1,000,000 claims have been used. No more ZKM will ever be minted. |
| "Already claimed" | This nullifier (tied to your eligible address) has already been used. You can only claim once per eligible address. |
| "Nullifier mismatch" | The nullifier in the journal doesn't match what you submitted. Ensure you're submitting the correct proof file. |
| "Recipient mismatch" | The recipient in the journal doesn't match what you submitted. Do not modify the proof file. |
| "Root mismatch" (on-chain) | The Merkle root in the proof doesn't match the contract's root. Your local eligibility list may be corrupted or outdated. Re-run `zkmist fetch`. |
| Transaction reverts with no clear error | Verify your proof locally first: `zkmist verify proof.json` |
| Gas estimation failed | You may not have enough ETH on Base for gas. Add ~$0.15 worth of ETH to your submitting wallet. |

### 8.5 General Tips

- **Run `zkmist verify proof.json` before submitting.** This validates everything locally without spending gas. If verification passes, the on-chain submission should succeed.
- **Keep your proof file safe.** Anyone who has it can submit the claim (though they can't change the recipient). If you accidentally submit it twice, the second attempt will fail with "Already claimed."
- **Check `zkmist status` regularly.** If claims are approaching 1M, submit sooner rather than later to avoid the cap being reached.

---

## 9. FAQ

### Q: Can I claim multiple times with different eligible addresses?

**Yes.** Each eligible address you control can claim exactly once, producing 10,000 ZKM per claim. However, each claim requires:
- A separate private key
- A separate proof generation run (~45–90s each)
- A Merkle tree rebuild if you haven't cached it

The first-come, first-served cap of 1M applies globally — space runs out for everyone at the same time.

### Q: What happens to unclaimed tokens?

**They are never minted.** If only 300,000 people claim, the total supply is 3 billion ZKM — forever. No one can mint the remaining 7 billion. The 10 billion figure is the theoretical maximum; the actual supply is determined entirely by how many people claim.

### Q: Can I burn my ZKM tokens?

**Yes.** The ZKMToken contract supports standard ERC-20 `burn()` and `burnFrom()` functions. Burning permanently reduces the total supply — burned tokens can never be recovered or re-minted.

### Q: Is there a team behind ZKMist?

**No.** ZKMist is fully community-owned. There is no team allocation, no treasury, no investor share, and no pre-mine. Every ZKM token in existence was claimed by community members. The contracts are immutable — no admin keys exist.

### Q: Why Base and not Ethereum mainnet?

Base offers:
- Significantly lower gas costs (~$0.15 vs. potentially $10+ on mainnet for a 510K gas transaction)
- Fast block times
- EVM compatibility
- Established ecosystem and bridge infrastructure

You can always bridge your ZKM to other chains after claiming.

### Q: What if I lose my proof file?

You can regenerate it. Since proofs are deterministic for the same inputs, running `zkmist prove` again with the same private key and recipient will produce an identical proof. However, you can only **submit** a claim once per eligible address — the nullifier prevents double-claims even with a regenerated proof.

### Q: Can I change my recipient after submitting?

**No.** The recipient is baked into the ZK proof. Once submitted, the 10,000 ZKM are minted to that address and cannot be redirected. If you need a different recipient, you'd need a different eligible address.

### Q: Can I sell or transfer my eligibility to someone else?

**Not directly.** Claiming requires the private key of the eligible address. If you give someone your private key, they could claim on your behalf (and set their own recipient), but this means you've given them full control of that Ethereum address — including any remaining assets.

### Q: Is the claiming process audited?

The entire stack is open-source:
- **Guest program** (`guest/src/main.rs`): ~80 lines of logic verifying address derivation, Merkle membership, and nullifier correctness
- **Smart contracts** (`contracts/src/`): ~75 lines of claim logic
- **Merkle tree library** (`merkle-tree/`): Shared Poseidon Merkle tree implementation
- **CLI tool** (`cli/`): User-facing interface

All code is publicly readable on GitHub. The contracts are immutable after deployment. External audits will be conducted before mainnet deployment.

### Q: What if the contracts have a bug?

The contracts and guest program are **immutable** — no admin, no owner, no upgrade path. This is an accepted design choice. If a critical bug is found, the community would need to coordinate socially to deploy a new system. Mitigation: extensive testing (33 Solidity tests, cross-implementation test vectors, testnet dry runs) and external audit before mainnet.

### Q: How do I know the claim window hasn't closed?

Run `zkmist status` anytime to see:

```shell
./target/release/zkmist status
```

This shows the current claim count, remaining claim slots, deadlines, and whether the window is open.

---

## Quick Reference Card

```shell
# 1. Install & build
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist
cargo build --release -p zkmist-cli
cargo risczero build --manifest-path guest/Cargo.toml

# 2. Download eligibility list (~1.3 GB, one time)
./target/release/zkmist fetch

# 3. Check if eligible
./target/release/zkmist check 0xYourAddress...

# 4. Generate proof (~1–2 min)
./target/release/zkmist prove

# 5. Verify locally (optional, recommended)
./target/release/zkmist verify ./zkmist_proof_*.json

# 6. Submit (requires ETH on Base for gas)
./target/release/zkmist submit ./zkmist_proof_*.json

# 7. Check status
./target/release/zkmist status
```

---

## Resources

| Resource | Link |
|----------|------|
| **GitHub** | [github.com/ph4n70mr1ddl3r/zkmist](https://github.com/ph4n70mr1ddl3r/zkmist) |
| **PRD (full spec)** | `PRD.md` in the repository |
| **Contributing** | `CONTRIBUTING.md` in the repository |
| **Base Bridge** | [bridge.base.org](https://bridge.base.org) |
| **BaseScan** | [basescan.org](https://basescan.org) |
| **RISC Zero** | [risczero.com](https://risczero.com) |

---

**Good luck, and welcome to the community-owned future. 🚀**
