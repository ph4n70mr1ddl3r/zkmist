# ZKMist (ZKM)

**Fully community-owned, privacy-preserving ERC-20 token on Base.**

[![Chain](https://img.shields.io/badge/chain-Base-0052FF)](https://base.org)

> **📋 Beta.** Halo2-KZG circuits implemented, 55 circuit tests + 53 contract tests passing. Soundness hardened with carry-propagated arithmetic and intermediate range checks. Production verifier generation and testnet deployment remaining. See [V2_PLAN.md](./V2_PLAN.md) for architecture details.

ZKMist is an airdrop token where 100% of supply goes to claimants — no team allocation, no treasury, no investors, no pre-mine. Every claimant receives exactly **10,000 ZKM**. Claims are anonymous: the qualified Ethereum address is never linked to the receiving address on-chain.

~64.1 million Ethereum addresses that paid ≥0.004 ETH in cumulative transaction fees on mainnet before 2026 are eligible. Up to **1 million claimants** can claim before **2027-01-01**.

---

## How It Works

```
  GitHub (eligibility list, ~2.8 GB)
       │
       ▼
  Local CLI
  $ zkmist fetch                        # download eligibility list (GitHub Releases)
  $ zkmist prove                        # generate Halo2-KZG ZK proof locally (~10-30 sec)
       │
  ┌────┴────────────┐
  ▼                  ▼
Direct submit    Any Relayer
  │                  │      (permissionless)
  └────────┬─────────┘
           ▼
  ZKMAirdrop (Base) — IMMUTABLE
  • Verify Halo2-KZG proof
  • Check nullifier unused, claim cap, deadline
  • MINT 10,000 ZKM to recipient

  On-chain: ✗ qualified address (HIDDEN)
            ✓ nullifier (opaque) + recipient
            No admin. No owner. No pause.
```

### Privacy Guarantee

The claimant's qualified Ethereum address is **never revealed on-chain**. The proof commits only:
- A **nullifier** — `poseidon(privateKey, domain)` — prevents double-claims without revealing identity
- A **recipient** — any address the claimant chooses

A relayer or observer cannot link the qualified address to the receiving address.

---

## Token Economics

| Parameter | Value |
|-----------|-------|
| **Name** | ZKMist |
| **Symbol** | ZKM |
| **Decimals** | 18 |
| **Max Supply** | 10,000,000,000 ZKM (10 billion) |
| **Initial Supply** | 0 (minted on claim) |
| **Per-Claim Amount** | 10,000 ZKM (fixed) |
| **Max Claims** | 1,000,000 |
| **Claim Deadline** | 2027-01-01 00:00:00 UTC |
| **Chain** | Base (chain ID: 8453) |
| **Burnable** | Yes — holders can burn via `burn()` / `burnFrom()` |

**Unclaimed tokens are never minted.** If only 300K people claim, the total supply is 3B ZKM — forever.

---

## Eligibility

> Any Ethereum mainnet address that paid **≥0.004 ETH** in cumulative gas fees on successful transactions before **2026-01-01 00:00:00 UTC**.

- **Qualified addresses:** 64,116,228 (extracted from Google BigQuery)
- **Scope:** Ethereum L1 mainnet only
- **Threshold:** ~$8–12 at average prices — filters dust/spam, captures virtually all real users

---

## Quick Start

### Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs)
- **~2 GB RAM** for proof generation
- **~3 GB disk** for eligibility list

### Build

```shell
# Clone (with Solidity submodules for contract development)
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist

# Build the CLI
cargo build --release -p zkmist-cli
```

### Claim Tokens

```shell
# 0. Check claim window status
zkmist status

# 1. Download the eligibility list (~2.8 GB, verifies SHA-256 + Merkle root)
zkmist fetch

# 2. Check if your address is eligible
zkmist check 0xYourAddress...

# 3. Generate a Halo2-KZG proof locally (interactive — prompts for private key + recipient)
zkmist prove

# 4. Submit the proof to Base (pay gas, or use a relayer)
zkmist submit ~/.zkmist/proofs/zkmist_proof_*.json
```

### Verify a Proof Locally

```shell
zkmist verify ~/.zkmist/proofs/zkmist_proof_*.json
```

---

## Project Structure

```
zkmist/
├── circuits/          # Halo2-KZG circuit definitions
│   └── src/
│       ├── lib.rs     # Top-level ZKMistClaim circuit
│       ├── secp256k1.rs
│       ├── keccak.rs
│       ├── poseidon.rs
│       ├── merkle.rs
│       ├── nullifier.rs
│       └── gadgets/   # Shared low-level gadgets
├── cli/               # User-facing CLI tool (Rust)
│   └── src/
│       ├── main.rs    # fetch, prove, submit, verify, check, status, bench
│       ├── halo2_prover.rs
│       └── commands.rs
├── merkle-tree/       # Poseidon Merkle tree library (shared)
│   └── src/lib.rs
├── tools/             # Dev utilities
│   └── src/
│       ├── compute_root.rs    # Compute Merkle root from CSV
│       ├── gen_verifier.rs     # Generate Halo2Verifier.sol + VK blob
│       ├── monitor.rs          # On-chain monitoring tool
│       └── readiness.rs        # Pre-deployment readiness checker
├── contracts/         # Solidity (Foundry)
│   ├── src/
│   │   ├── ZKMToken.sol       # ERC-20, mintable by airdrop, burnable
│   │   ├── ZKMAirdrop.sol     # Immutable claim contract
│   │   └── Halo2Verifier.sol  # Auto-generated KZG verifier
│   ├── test/          # Unit + e2e + fuzz + integration tests
│   └── script/
│       └── Deploy.s.sol
├── scripts/           # Deployment and testing scripts
│   ├── testnet-deploy.sh     # Base Sepolia deployment
│   └── e2e-test.sh           # Full local E2E test suite
└── V2_PLAN.md         # Architecture document
```

---

## Smart Contracts

| Contract | Description |
|----------|-------------|
| **ZKMToken** | ERC-20 with 10B max supply. Mintable only by the airdrop contract. Burnable by holders. |
| **ZKMAirdrop** | Immutable claim contract — verifies Halo2-KZG proof, checks nullifier/cap/deadline, mints tokens. |
| **Halo2Verifier** | Auto-generated from circuit VK. KZG pairing verification using BN254 ecPairing precompile. |

### Gas

| Operation | Gas | Cost (Base) |
|-----------|-----|-------------|
| **Claim** | **~350-400K** | **~$0.10-0.12** |
| **Full Deploy (3 contracts)** | **~2.1M** | **~$0.50** |

### Test

```shell
cd contracts
forge test -vvv
forge snapshot                     # Gas snapshot
```

---

## ZK Proof Pipeline

### Circuit (`circuits/`)

The Halo2-KZG circuit proves:

1. **Key → Address:** Derives an Ethereum address from the private key via secp256k1 + Keccak-256
2. **Merkle Membership:** Verifies the address is in the eligibility tree (26-level Poseidon)
3. **Nullifier Correctness:** Confirms `poseidon(Fr(key), Fr(domain))` matches the submitted nullifier
4. **Non-zero Recipient:** Rejects `address(0)` to prevent token burns

Public inputs: `[merkleRoot, nullifier, recipient]`. No journal — inputs are direct calldata.

### Merkle Tree (`merkle-tree/`)

| Parameter | Value |
|-----------|-------|
| **Depth** | 26 levels (67,108,864 leaves, ~64.1M populated) |
| **Leaf Hash** | Poseidon t=2 (1 input), R_F=8, R_P=56 |
| **Interior Hash** | Poseidon t=3 (2 inputs), R_F=8, R_P=57 |
| **Field** | BN254 scalar field |
| **Padding** | `0xFF..FF` sentinel |
| **Nullifier** | `poseidon(Fr(key), Fr("ZKMist_V2_NULLIFIER"))` |

---

## Test Vectors

The project includes verified test vectors for cross-implementation validation:

| Component | Input | Expected Output |
|-----------|-------|-----------------|
| Address derivation | Private key `0x0123...cdef` | `0xfcad0b19bb29d4674531d6f115237e16afce377c` |
| Leaf hash | Address above | `0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9` |
| Interior hash | `poseidon(Fr(1), Fr(2))` | `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` |

---

## Development

### Run Tests

```shell
# Rust unit tests (fast)
cargo test -p zkmist-merkle-tree
cargo test -p zkmist-circuits
cargo test -p zkmist-cli --bin zkmist

# Slow circuit tests (E2E MockProver, ~15-30 min each)
cargo test -p zkmist-circuits -- --ignored --nocapture

# Solidity tests
cd contracts && forge test -vvv
```

### Lint

```shell
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cd contracts && forge fmt --check
```

### Compute Merkle Root

```shell
cargo run --release -p zkmist-tools --bin compute-root -- /path/to/addresses.csv
```

### Generate Halo2Verifier.sol

```shell
cargo run --release -p zkmist-tools --bin gen-verifier --features v2 -- --output contracts/src/Halo2Verifier.sol
```

### Check Pre-deployment Readiness

```shell
cargo run -p zkmist-tools --bin readiness
```

### Monitor Deployed Contracts

```shell
cargo run -p zkmist-tools --bin monitor -- <airdrop_address> --rpc https://mainnet.base.org --interval 60
```

### Benchmark Proving Pipeline

```shell
cargo run --release -p zkmist-cli --bin zkmist -- bench --tree-depth 4
```

---

## Deployment

```shell
cd contracts

# 1. Set deployer key (needs ETH on Base for gas)
export PRIVATE_KEY=0x...

# 2. Deploy to testnet first (Base Sepolia)
./scripts/testnet-deploy.sh

# 3. After testnet validation, deploy to mainnet (Base)
forge script script/Deploy.s.sol --rpc-url https://mainnet.base.org --broadcast

# 4. Verify contracts
forge verify-contract <address> Halo2Verifier --chain base
forge verify-contract <address> ZKMToken --chain base
forge verify-contract <address> ZKMAirdrop --chain base

# 5. Update AIRDROP_CONTRACT in cli/src/constants.rs
```

---

## Security

| Property | Mechanism |
|----------|-----------|
| **No admin keys** | Nothing to compromise — contracts are fully immutable |
| **No double-claim** | Deterministic nullifier stored in on-chain mapping |
| **Front-running protected** | Recipient committed inside ZK proof |
| **Privacy** | Qualified address never appears on-chain; nullifier is a one-way hash |
| **Supply cap** | 10B ZKM max mint enforced on-chain; circulating supply can only decrease via burns |

---

## Status

> **⚠️ Beta — not yet deployed.**
>
> **201 tests passing** (60 circuit + 56 CLI + 13 merkle-tree + 72 Solidity). Zero clippy warnings. Gas snapshot regenerated.
>
> **Soundness hardening (completed):**
> - secp256k1 scalar multiplication uses correct MSB-first bit ordering with P255 MSB correction
> - `field_add_carried` uses raw limb sums for carry chain (not mod-p reduced values)
> - `field_mul` uses constrained schoolbook products and wide limb accumulation
> - Reduction from wide-to-narrow is witness-guided (soundness from terminal `check_on_curve` + `constrain_affine`)
> - `check_on_curve` verifies y² = x³ + 7 on the computed EC point
> - `constrain_affine` verifies the computed point matches the expected public key
> - Intermediate range checks every 32 scalar mul steps
> - Limb range checks with correct MSB-first byte decomposition
> - `conditional_select` uses single-assignment pattern (no double-writes to same cell)
> - `IS_PRODUCTION_VERIFIER` guard prevents deployment with placeholder verifier
> - KZG params caching in `~/.zkmist/cache/`
> - Diverse test vectors: 7 keys including edge cases (MSB=0, MSB=1, key=1, key=n-1)
> - 50K nullifier collision test passing
>
> **Known issue (blocking mainnet):**
> - The secp256k1 MockProver test (`test_secp256k1_mock_prover`, `#[ignore]`) produces 8 permutation failures in `constrain_affine`. The circuit computes a valid curve point (check_on_curve passes) but the affine coordinates don't match the expected public key. Root cause: the hand-rolled non-native field arithmetic in `field_mul` lacks a constrained reduction from wide limbs to the final result. **This gadget must be replaced with an audited library** (e.g., `scroll-tech/halo2-secp256k1` or `halo2wrong`) before mainnet.
> - The full E2E circuit test (`test_circuit_merkle_nullifier_e2e`, `#[ignore]`) requires k=23 (8M rows) and takes 30-90 minutes. It cannot pass until the secp256k1 gadget is fixed.
>
> **Tooling:**
> - `zkmist bench` — proves timing benchmark on reference hardware
> - `monitor` — on-chain monitoring with anomaly detection
> - `readiness` — pre-deployment readiness checker (8 checks)
> - `gen-verifier` — generates VK-embedded verifier + serialized VK blob
> - `scripts/testnet-deploy.sh` — one-command testnet deployment
> - `scripts/e2e-test.sh` — full local E2E test suite
>
> **Remaining blockers before deployment:**
> - Replace hand-rolled secp256k1 with audited library (`scroll-tech/halo2-secp256k1` or `halo2wrong`)
> - Regenerate `Halo2Verifier.sol` from circuit VK using `halo2-solidity-verifier`
> - Fix and pass full E2E MockProver test
> - **External security review** of circuit (especially after secp256k1 library swap)
> - Testnet deployment on Base Sepolia
>
> See [SECURITY.md](./SECURITY.md) for the full pre-deployment checklist.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| ZK Proofs | [Halo2-KZG](https://github.com/privacy-scaling-explorations/halo2) (PLONKish, BN254) |
| Merkle Tree | Poseidon hash (BN254) via [light-poseidon](https://github.com/dmpierre/poseidon) v0.4 |
| CLI | Rust, [clap](https://docs.rs/clap), [alloy](https://github.com/alloy-rs/alloy) |
| Smart Contracts | Solidity 0.8.28, [Foundry](https://book.getfoundry.sh/), [OpenZeppelin](https://openzeppelin.com/contracts/) |
| On-chain Verification | BN254 ecPairing precompile (address `0x08`) |
| Eligibility Data | [Google BigQuery](https://cloud.google.com/bigquery), GitHub Releases |

---

## License

MIT
