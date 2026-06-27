# ZKMist (ZKM)

**Fully community-owned, privacy-preserving ERC-20 token on Base.**

[![Chain](https://img.shields.io/badge/chain-Base-0052FF)](https://base.org)

> **⚠️ Pre-alpha — NOT audited, NOT deployable.** Halo2-KZG circuits are implemented and the soundness-critical **wiring between the secp256k1 scalar, the Keccak-derived address, and the nullifier is constrained** (leaf↔address, nullifier↔scalar, pubkey↔Keccak-input), but the circuit has **not been externally audited** and the full end-to-end proof test has not yet passed at production `k`. Do not deploy to mainnet. The secp256k1 gadget uses **hand-rolled non-native field arithmetic** that requires an independent security audit. See [SECURITY.md](./SECURITY.md) for audit status and [V2_PLAN.md](./V2_PLAN.md) for architecture.
>
> Note: a high test count is **not** a soundness signal — Halo2's `MockProver` only verifies gates that exist; it cannot detect a *missing* constraint.

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

> **Note:** Halo2-KZG proofs are ~5.6 KB (5632 bytes). The verifier performs
> full BN254 pairing verification via the `ecPairing` precompile (address `0x08`).

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

**Soundness:** Every `field_mul` in the secp256k1 gadget includes a Schwartz–Zippel product
verification check that constrains the multiplication result is correct modulo the secp256k1
field prime, with soundness error ≤ 6/p_BN254 per operation (negligible).

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

## Data Availability

The eligibility list (~2.8 GB) is distributed via GitHub Releases with per-file SHA-256 integrity checks and a hardcoded Merkle root. For redundancy:

- The manifest root is hardcoded in `cli/src/constants.rs` — even if GitHub is compromised, the CLI will reject tampered data
- SHA-256 checksums are verified for each downloaded file
- The full Merkle tree root is recomputed during `zkmist fetch` (optional, `--no-verify` to skip)

**Recommendation for mirrors:** After initial release, consider mirroring the eligibility list to IPFS or another CDN for censorship resistance. The `zkmist fetch` command supports multiple download sources with automatic fallback.

## Relayer Support

Claims can be submitted by anyone (permissionless relaying). A third-party relayer can:
1. Receive a `zkmist_proof_*.json` file from a claimant
2. Submit the proof to the `ZKMAirdrop` contract, paying gas on behalf of the recipient
3. The recipient receives ZKM tokens regardless of who submitted the proof

The recipient address is bound inside the ZK proof — it cannot be changed by the relayer.

**Building a relayer:** A minimal relayer needs only:
- An Ethereum address with ETH on Base for gas
- The Alloy/ethers library to submit a `claim(bytes, bytes32, address)` transaction
- The proof JSON file from the claimant

No special permissions or contract setup is required.

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

> **⚠️ Pre-alpha — not audited, not yet deployed.**
>
> **Soundness status — do NOT rely on this for value yet:**
> - The circuit now **constrains the binding** between its three pillars: the
>   secp256k1 scalar `k`, the Keccak-derived address (`keccak(k·G)`), and the
>   emitted nullifier (`poseidon(k, domain)`). Specifically: the Merkle leaf is
>   constrained equal to the Keccak address bits; the nullifier key is
>   constrained equal to the accumulated scalar bits; and the Keccak input is
>   constrained equal to the scalar-mul output coordinates. (An earlier revision
>   left these as free advice cells — a catastrophic soundness break — and is now
>   fixed.)
> - **secp256k1 non-native field arithmetic: VALIDATED in isolation (2026).**
>   The isolated secp256k1 gadget — `field_mul` / `field_add_carried` / `field_sub`
>   carry-chain reductions, `check_on_curve`, `constrain_affine` (k·G == pubkey),
>   and limb range checks — **passes MockProver at k=24** and derives the
>   test-vector address. k rose 22→24 because the sound reductions add rows per
>   field op. (This was the largest unknown and it is now exonerated.)
> - **Full E2E circuit: ✅ PASSES at k=24 (2026).** The honest end-to-end proof —
>   real key → secp256k1 → Keccak address → Merkle membership → nullifier →
>   recipient — verifies, and the binding between the three pillars is sound.
>   Getting here required fixing three latent Keccak correctness bugs that
>   MockProver could not catch on its own (gates were satisfiable but the
>   witness was wrong): a corrupted `RC` round-constant table, a backwards
>   `rotate_lane`, and a transposing `chi_step`. Each is now pinned by an
>   instant native test plus a constrained `tiny_keccak` cross-check. See
>   [SECURITY.md](./SECURITY.md).
> - The secp256k1 gadget uses **hand-rolled non-native field arithmetic** that
>   has **not been externally audited**. An independent audit of both the
>   arithmetic and the circuit wiring is required before mainnet.
>
> **Defense-in-depth mechanisms in place (NOT a substitute for audit):**
> - `field_mul` Schwartz–Zippel product verification at r=65537
> - `field_add_carried` carry-propagated limb addition
> - `check_on_curve` (y² = x³ + 7) and `constrain_affine` terminal checks
> - Intermediate + terminal limb range checks; MSB-corrected scalar mul
> - Real (non-vacuous) recipient non-zero (`s_nonzero` gate) and uint160 range
>   constraints
>
> **A test count is not a security signal.** `MockProver` verifies only the
> gates that exist; it cannot detect a missing constraint. The negative tests
> cover the constraints that are present.
>
> **Known issues (blocking mainnet):**
> - The four full-circuit negative tests (`*_rejected`) are `#[ignore]`d
>   (~30 min each at k=24); they should be run to confirm forged Merkle proofs /
>   rotated nullifiers / zero or out-of-range recipients are rejected for the
>   right reason now that the honest path verifies.
> - Production circuit `k` is now **24** (16M rows), up from 23, due to the
>   secp256k1 soundness rewrite. E2E MockProver at k=24 ≈ 32 min, ~30 GiB RSS.
>
> **Already validated (2026):**
> - **Full E2E MockProver** (`test_circuit_merkle_nullifier_e2e`) at k=24 ✅
> - secp256k1 non-native reductions via `test_secp256k1_mock_prover` at k=24 ✅
> - Keccak chip via `test_keccak_mock_prover_full` at k=22 (constrained
>   `tiny_keccak` cross-check on 160 address bits) ✅
> - `cond_swap` Merkle gadget soundness (`s_mul`/`s_add` product gates) ✅
> - `field_add_carried` Phase 1 carry chain ✅
> - `EXPECTED_CS_DIGEST` regenerated to `f8f4b46128dd613f` ✅
>
> **Tooling:**
> - `zkmist bench` — proving timing benchmark with proof size validation
> - `monitor` — on-chain monitoring with anomaly detection (surge, supply mismatch)
> - `readiness` — pre-deployment readiness checker (automated checks)
> - `gen-verifier` — generates VK-embedded verifier + serialized VK blob
> - `scripts/testnet-deploy.sh` — one-command testnet deployment with automatic contract verification
> - `scripts/e2e-test.sh` — full local E2E test suite
>
> **Remaining blockers before deployment:**
> - Run the four full-circuit negative tests to confirm rejection semantics (honest E2E path already passes at k=24)
> - Regenerate `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` from the full circuit VK (at k=24) using `halo2-solidity-verifier`
> - **NOTE**: Current `Halo2VerifyingKey.sol` has k=21 with all-zero fixed commitments (placeholder). Must regenerate from the full production circuit (k=24).
> - **External security review** of circuit (especially secp256k1 and Keccak gadgets)
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
