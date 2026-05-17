# ZKMist (ZKM)

**Fully community-owned, privacy-preserving ERC-20 token on Base.**

ZKMist is an airdrop token where 100% of supply goes to claimants — no team allocation, no treasury, no investors, no pre-mine. Every claimant receives exactly **10,000 ZKM**. Claims are anonymous: the qualified Ethereum address is never linked to the receiving address on-chain.

~64.1 million Ethereum addresses that paid ≥0.004 ETH in cumulative transaction fees on mainnet before 2026 are eligible. Up to **1 million claimants** can claim before **2027-01-01**.

---

## How It Works

```
  IPFS / GitHub (eligibility list, ~2.8 GB)
       │
       ▼
  Local CLI
  $ zkmist fetch                        # download eligibility list
  $ zkmist prove                        # generate ZK proof locally
       │
  ┌────┴────────────┐
  ▼                  ▼
Direct submit    Any Relayer
  │                  │      (permissionless)
  └────────┬─────────┘
           ▼
  ZKMAirdrop (Base) — IMMUTABLE
  • Verify RISC Zero ZK proof (Groth16)
  • Validate journal (root + nullifier + recipient)
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
- **RISC Zero toolchain** — `curl -L https://risczero.com/install | bash && rzup install rust`
- **~4 GB RAM** for Merkle tree construction
- **~3 GB disk** for eligibility list

### Build

```shell
# Clone (with Solidity submodules for contract development)
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist

# Build the CLI
cargo build --release -p zkmist-cli

# Build the guest program (requires cargo-risczero)
cargo risczero build --manifest-path guest/Cargo.toml
```

### Claim Tokens

```shell
# 1. Download the eligibility list (~2.8 GB, verifies SHA-256 + Merkle root)
zkmist fetch

# 2. Check if your address is eligible
zkmist check 0xYourAddress...

# 3. Generate a ZK proof locally (interactive — prompts for private key + recipient)
zkmist prove

# 4. Submit the proof to Base (pay gas, or use a relayer)
zkmist submit ~/.zkmist/proofs/zkmist_proof_*.json
```

### Verify a Proof Locally

```shell
zkmist verify ~/.zkmist/proofs/zkmist_proof_*.json
```

### Check Claim Window Status

```shell
zkmist status
```

---

## Project Structure

```
zkmist/
├── guest/              # RISC Zero zkVM guest program (Rust)
│   └── src/main.rs     # Proves: key→address, Merkle membership, nullifier
├── cli/                # User-facing CLI tool (Rust)
│   └── src/main.rs     # fetch, prove, submit, verify, check, status
│   └── tests/          # End-to-end guest execution tests
├── merkle-tree/        # Poseidon Merkle tree library (shared)
│   └── src/lib.rs      # Tree build, proof gen/verify, nullifier, serialization
├── tools/              # Dev utilities
│   └── src/            # compute-root, compute-image-id
├── contracts/          # Solidity (Foundry)
│   ├── src/
│   │   ├── ZKMToken.sol       # ERC-20, mintable by airdrop, burnable
│   │   ├── ZKMAirdrop.sol     # Immutable claim contract
│   │   └── IRiscZeroVerifier.sol
│   ├── test/           # Unit + e2e tests (33 tests)
│   ├── script/         # Deploy scripts (Deploy.s.sol, DeployAll.s.sol)
│   └── deploy-base.sh  # One-command deployment helper
├── PRD.md              # Full product requirements document (1,342 lines)
└── Cargo.toml          # Workspace root
```

---

## Smart Contracts

| Contract | Description |
|----------|-------------|
| **ZKMToken** | ERC-20 with 10B max supply. Mintable only by the airdrop contract. Burnable by holders. |
| **ZKMAirdrop** | Immutable claim contract — verifies RISC Zero Groth16 proof, validates journal, checks nullifier/cap/deadline, mints tokens. |
| **RiscZeroGroth16Verifier** | Deployed from [risc0-ethereum](https://github.com/risc0/risc0-ethereum). Accepts Groth16-compressed STARK proofs. |

### Journal Layout (84 bytes)

The ZK proof journal is sliced directly by the contract — no ABI decoding:

```
[0:32]   merkleRoot   (bytes32)
[32:64]  nullifier    (bytes32)
[64:84]  recipient    (address — raw 20 bytes)
```

### Gas

| Operation | Gas | Cost (Base) |
|-----------|-----|-------------|
| Deploy (all 3 contracts) | ~8.2M | ~$0.25 |
| **Claim** | **~510K** | **~$0.15** |

### Test

```shell
cd contracts
forge test -vvv                    # All 33 tests
forge test --match-contract ZKME2E # Integration tests only
forge snapshot                     # Gas snapshot
```

---

## ZK Proof Pipeline

### Guest Program (`guest/`)

The RISC Zero guest program proves:

1. **Key → Address:** Derives an Ethereum address from the private key via secp256k1 + Keccak-256
2. **Merkle Membership:** Verifies the address is in the eligibility tree (26-level Poseidon)
3. **Nullifier Correctness:** Confirms `poseidon(Fr(key), Fr(domain))` matches the submitted nullifier
4. **Non-zero Recipient:** Rejects `address(0)` to prevent token burns

Journal output: 84 bytes (`root ‖ nullifier ‖ recipient`).

### Merkle Tree (`merkle-tree/`)

| Parameter | Value |
|-----------|-------|
| **Depth** | 26 levels (67,108,864 leaves, ~64.1M populated) |
| **Leaf Hash** | Poseidon t=2 (1 input), R_F=8, R_P=56 |
| **Interior Hash** | Poseidon t=3 (2 inputs), R_F=8, R_P=57 |
| **Field** | BN254 scalar field |
| **Padding** | `0xFF..FF` sentinel (exceeds field modulus — Poseidon output can never equal it) |
| **Nullifier** | `poseidon(Fr(key), Fr("ZKMist_V1_NULLIFIER"))` |

### Streaming Build

The CLI uses `build_tree_streaming` which keeps only 2 tree layers in memory at a time (~2 GB peak vs ~8.6 GB for full tree). Per-address proof caching (~900 bytes) eliminates repeat tree builds.

---

## Test Vectors

The project includes verified test vectors for cross-implementation validation:

| Component | Input | Expected Output |
|-----------|-------|-----------------|
| Address derivation | Private key `0x0123...cdef` | `0xfcad0b19bb29d4674531d6f115237e16afce377c` |
| Leaf hash | Address above | `0x1b074e636009c422c17f904b91d117b96f506bc28f55c428ccdbe5e80d4d18e9` |
| Nullifier | Key + domain | `0x078f972a9364d143a172967523ed8d742aab36481a534e97dae6fd7f642f65b9` |
| Interior hash | `poseidon(Fr(1), Fr(2))` | `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` |

---

## Development

### Run Tests

```shell
# Rust unit tests
cargo test -p zkmist-merkle-tree

# Guest e2e (dev-mode, fast)
cargo risczero build --manifest-path guest/Cargo.toml --features test-small-tree
RISC0_DEV_MODE=1 cargo test -p zkmist-cli --test e2e_zkvm

# Full STARK proof (30+ min, manual only)
cargo risczero build --manifest-path guest/Cargo.toml
cargo test -p zkmist-cli --test e2e_zkvm -- --ignored

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

### Compute Guest Image ID

```shell
cargo run --release -p zkmist-tools --bin compute-image-id
```

---

## Deployment

```shell
cd contracts

# 1. Set deployer key (needs ETH on Base for gas ~$0.25)
export PRIVATE_KEY=0x...

# 2. Verify prerequisites
./deploy-base.sh check

# 3. Simulate
./deploy-base.sh dry-run

# 4. Deploy for real
./deploy-base.sh deploy
```

Deploys 3 contracts in one transaction via CREATE nonce prediction:
1. `RiscZeroGroth16Verifier` (from risc0-ethereum)
2. `ZKMToken` (minter = predicted airdrop address)
3. `ZKMAirdrop` (immutable — all parameters set in constructor)

---

## Security

| Property | Mechanism |
|----------|-----------|
| **No admin keys** | Nothing to compromise — contracts are fully immutable |
| **No double-claim** | Deterministic nullifier stored in on-chain mapping |
| **Front-running protected** | Recipient committed inside ZK proof |
| **Privacy** | Qualified address never appears on-chain; nullifier is a one-way hash |
| **No trusted setup** | STARK-based proving (RISC Zero zkVM) |
| **Supply cap** | 10B ZKM max mint enforced on-chain; circulating supply can only decrease via burns |

See [PRD.md §10](PRD.md) for the full threat model and security analysis.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| ZK Proofs | [RISC Zero zkVM](https://risczero.com/) v3.0.5 (STARK → Groth16) |
| Merkle Tree | Poseidon hash (BN254) via [light-poseidon](https://github.com/dmpierre/poseidon) v0.4 |
| CLI | Rust, [clap](https://docs.rs/clap), [alloy](https://github.com/alloy-rs/alloy) |
| Smart Contracts | Solidity 0.8.28, [Foundry](https://book.getfoundry.sh/), [OpenZeppelin](https://openzeppelin.com/contracts/) |
| On-chain Verification | [risc0-ethereum](https://github.com/risc0/risc0-ethereum) Groth16 verifier |
| Eligibility Data | [Google BigQuery](https://cloud.google.com/bigquery), IPFS, GitHub Releases |

---

## License

MIT
