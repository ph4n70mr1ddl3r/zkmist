# ZKMist (ZKM)

**Fully community-owned, privacy-preserving ERC-20 token on Base.**

[![Chain](https://img.shields.io/badge/chain-Base-0052FF)](https://base.org)

> **⚠️ Pre-alpha — NOT audited, NOT deployable.** The axiom Halo2-KZG circuits are implemented and the soundness-critical **wiring between the secp256k1 scalar, the Keccak-derived address, and the nullifier is constrained** (leaf↔address, nullifier↔scalar, pubkey↔Keccak-input). The full circuit verifies at production **k=21** (honest happy-path + four negative cases reject; the real-KZG prover and revm-EVM round-trips pass), but the circuit has **not been externally audited** and the committed-verifier on-chain round-trip (`contracts/test/ZKM.realroundtrip.t.sol`) is an **opt-in** gate (`RUN_REAL_ROUNDTRIP=1`) with an intentionally-uncommitted fixture — so the end-to-end "real proof mints on-chain" property is not yet locked into CI. The KZG SRS is pinned and its provenance is byte-confirmed against the public ceremony transcript (`tools/src/verify_srs_from_ptau.rs`); the on-chain verifier is the real axiom one. The secp256k1 scalar multiplication runs on **halo2-ecc's audited chips**, but the custom pubkey byte-bridge / Keccak / Poseidon-Merkle gadgets and the three-pillar wiring still need an independent audit. Do not deploy to mainnet. See [SECURITY.md](./SECURITY.md), [DEPLOYMENT.md](./DEPLOYMENT.md), and [V2_PLAN.md](./V2_PLAN.md) for architecture.
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
- **~32 GiB RAM** for proof generation. The real KZG path (`keygen_vk` + `create_proof`) peaks ≳26–28 GiB at k=23 — empirically measured 2026-07-03 (`keygen_vk` alone exceeded 24 GiB *before* `create_proof` began). This is substantially more than the ~19.5 GiB `MockProver` peak (which skips the KZG commitment matrices), so a 32 GiB machine is the practical floor; a 26 GiB WSL2 VM is OOM-killed during `keygen_vk`. See [SECURITY.md](./SECURITY.md) for the benchmarks.
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

Runs the real on-chain `Halo2Verifier` (the exact Base bytecode) inside a local
EVM (revm) via `forge test` — a pass means `submit` will succeed, with no
transaction broadcast. Requires the source tree + Foundry (unlike `prove`/
`submit`, which ship standalone); install Foundry from
<https://book.getfoundry.sh>.

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
| **Claim** | **~600K** | **~$0.15-0.20** |
| **Full Deploy (3 contracts)** | **~2.1M** | **~$0.50** |

> **Note:** axiom Halo2-KZG (SHPLONK) proofs are ~1.4 KB (1376 bytes). The
> verifier performs full BN254 pairing verification via the `ecPairing`
> precompile (address `0x08`); the pairing check dominates claim gas.

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

**Soundness:** `field_mul` / `field_add_carried` / `field_sub` in the secp256k1
gadget reduce their wide products modulo the secp256k1 field prime using sound
integer carry chains (`carry_chain_columns`, final carry-out constrained to 0)
plus a witnessed quotient `q` with `result + q·p = V` and a canonicalization
proof `result < p` (`reduce_canonical_mod_p`) — the same strategy as audited
non-native libraries (`halo2wrong`, `scroll-tech/halo2-secp256k1`). (An earlier
Schwartz–Zippel product check was reverted as mathematically incorrect for
base-2^64 limbs.) The k=23 MockProver confirmation of this gadget is a pending
pre-deployment gate; see [DEPLOYMENT.md](./DEPLOYMENT.md) Phase 0.

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

### Regenerate Halo2Verifier.axiom.sol (only if the circuit changes)

The on-chain verifier is emitted by the axiom round-trip test under explicit
env gates (an ordinary test run never writes the file). Emit against the
**pinned ceremony SRS** — the only mode that produces a mainnet-sound verifier:

```shell
ZKMIST_RUN_CLAIM_ROUNDTRIP=1 \
ZKMIST_EMIT_VERIFIER=contracts/src/Halo2Verifier.axiom.sol \
ZKMIST_USE_PINNED_SRS=1 \
cargo test --release -p zkmist-circuits test_claim_circuit_evm_roundtrip -- --nocapture
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
> - **secp256k1 non-native field arithmetic: ✅ MockProver-CONFIRMED at
>   k=23 (2026-06-29 run).** The isolated secp256k1 gadget — `field_mul` /
>   `field_add_carried` / `field_sub` carry-chain reductions, `check_on_curve`,
>   `constrain_affine` (k·G == pubkey), and limb range checks — implements the
>   audited-library strategy (`carry_chain_columns` +
>   `reduce_canonical_mod_p`) and **passes MockProver at k=23** (36s, 14.8 GiB
>   RSS), deriving the test-vector address `0xfcad0b19bb29d4674531d6f115237e16afce377c`.
>   Still required before mainnet: external audit and the real-KZG round-trip
>   (MockProver confirms constraints, not the commitment/transcript path). See
>   [SECURITY.md](./SECURITY.md) and [DEPLOYMENT.md](./DEPLOYMENT.md).
> - **Full E2E circuit: ✅ PASSES at k=23 (2026-06-29 run).** The honest
>   end-to-end proof — real key → secp256k1 → Keccak address → Merkle membership
>   → nullifier → recipient — verifies (2:49, 19.5 GiB RSS), and the binding
>   between the three pillars is sound as constraints. Getting the honest path
>   *possible* required fixing three latent Keccak correctness bugs that
>   MockProver could not catch on its own (gates were satisfiable but the
>   witness was wrong): a corrupted `RC` round-constant table, a backwards
>   `rotate_lane`, and a transposing `chi_step`. Each is now pinned by an
>   instant native test plus a constrained `tiny_keccak` cross-check. See
>   [SECURITY.md](./SECURITY.md) and [DEPLOYMENT.md](./DEPLOYMENT.md).
> - The secp256k1 gadget uses **hand-rolled non-native field arithmetic** that
>   has **not been externally audited**. An independent audit of both the
>   arithmetic and the circuit wiring is required before mainnet.
>
> **Defense-in-depth mechanisms in place (NOT a substitute for audit):**
> - `field_mul` / `field_add_carried` / `field_sub` sound integer carry chains (`carry_chain_columns`) + witnessed-quotient mod-p reduction (`reduce_canonical_mod_p`)
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
> - Production circuit `k` is **23** (8.4M rows). The soundness rewrite raised
>   it to 24, but the secp256k1 `point_add_mixed` optimization halved the witness
>   and brought it back to k=23. E2E MockProver at k=23 ≈ 2 min (release),
>   ~15 GiB RSS.
>
> **✅ MockProver-confirmed at k=23 (2026-06-29 run):**
> - **Full E2E MockProver** (`test_circuit_merkle_nullifier_e2e`) — PASS (2:49, 19.5 GiB)
> - **Four full-circuit negative tests** (wrong root / wrong nullifier /
>   zero recipient / >uint160 recipient all correctly rejected) — all PASS
>   (~2:11–2:31 each, 19.5 GiB)
> - secp256k1 non-native reductions via `test_secp256k1_mock_prover` — PASS
>   (36s, 14.8 GiB), derives test-vector address
> - Keccak chip via `test_keccak_mock_prover_full` at k=22 (constrained
>   `tiny_keccak` cross-check on 160 address bits) — PASS (1:25, 3.7 GiB)
>
> **Also validated by the fast/native test suite (155 tests, green):**
> - `cond_swap` Merkle gadget soundness (`s_mul`/`s_add` product gates) ✅
> - `field_add_carried` Phase 1 carry chain ✅
> - `EXPECTED_CS_DIGEST` pinned to `f8f4b46128dd613f` ✅
> - Keccak `keccak_f` / `rotate_lane` / `chi_step` native cross-checks vs `tiny_keccak` ✅
>
> **What MockProver does NOT cover (still required before mainnet):**
> - External security audit of the secp256k1 / Keccak / Poseidon gadgets
> - The real KZG commitment/transcript path (needs pinned SRS + Solidity verifier round-trip)
> - Testnet deployment on Base Sepolia
>
> **Tooling:**
> - `zkmist bench` — proving timing benchmark with proof size validation
> - `monitor` — on-chain monitoring with anomaly detection (surge, supply mismatch)
> - `readiness` — pre-deployment readiness checker (automated checks)
> - the on-chain verifier is regenerated by `circuits/tests/claim_evm_roundtrip.rs` under `ZKMIST_EMIT_VERIFIER` (see DEPLOYMENT.md Phase 3)
> - `scripts/testnet-deploy.sh` — one-command testnet deployment with automatic contract verification
> - `scripts/e2e-test.sh` — full local E2E test suite
>
> **Remaining blockers before deployment:**
> - ✅ `Halo2Verifier.axiom.sol` is the snark-verifier-generated axiom verifier at **k=21** (VK embedded inline — no separate verifying-key contract), emitted against the pinned PSE ceremony SRS; the readiness checker confirms `AXIOM_CIRCUIT_K=21` and real VK data. ✅ The real-KZG → on-chain round-trip PASSES (`RUN_REAL_ROUNDTRIP=1 forge test --match-contract RealRoundtrip`): happy-path claim mints, double-claim reverts, and a tampered proof reverts. ✅ SRS transcript provenance is confirmed (`tools/src/verify_srs_from_ptau.rs`). **Remaining:** external audit (DEPLOYMENT.md Phase 1) and a Base Sepolia deployment (Phase 5).
> - **External security review** of circuit (especially secp256k1 and Keccak gadgets)
> - Testnet deployment on Base Sepolia
>
> See [SECURITY.md](./SECURITY.md) for the full pre-deployment checklist and
> [DEPLOYMENT.md](./DEPLOYMENT.md) for the ordered, step-by-step runbook.

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
