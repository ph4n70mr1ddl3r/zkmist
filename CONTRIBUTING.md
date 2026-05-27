# Contributing to ZKMist

Thank you for your interest in ZKMist! This project is fully community-owned — contributions are welcome and encouraged.

> **Note:** ZKMist V2 uses Halo2-KZG circuits instead of RISC Zero. See [V2_PLAN.md](./V2_PLAN.md)
> for the V2 architecture. The instructions below cover both V1 and V2 development.

## Quick Start

### V2 (Halo2 — recommended)

```shell
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist

# Build the CLI
 cargo build --release -p zkmist-cli

# Build and test circuits
cargo test -p zkmist-circuits
```

### V1 (RISC Zero — legacy)

```shell
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist

# Build the CLI
cargo build --release -p zkmist-cli

# Build the guest program (requires cargo-risczero)
cargo risczero build --manifest-path guest/Cargo.toml
```

## Development Setup

### Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs)
- **RISC Zero toolchain** — `curl -L https://risczero.com/install | bash && rzup install rust`
- **Foundry** — [getfoundry.sh](https://book.getfoundry.sh/) (for Solidity contracts)

### Running Tests

```shell
# Rust unit tests
cargo test -p zkmist-merkle-tree
cargo test -p zkmist-cli --bin zkmist

# Guest E2E tests (dev-mode, fast)
cargo risczero build --manifest-path guest/Cargo.toml --features test-small-tree
RISC0_DEV_MODE=1 cargo test -p zkmist-cli --test e2e_zkvm

# Solidity tests
cd contracts && forge test -vvv
```

### Linting & Formatting

```shell
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cd contracts && forge fmt --check
```

All of the above must pass before submitting a PR.

## Code Organization

| Directory | Purpose |
|-----------|---------|
| `guest/` | RISC Zero zkVM guest program (Rust, compiles to RISC-V) |
| `cli/` | User-facing CLI tool (Rust) |
| `merkle-tree/` | Shared Poseidon Merkle tree library (Rust) |
| `tools/` | Dev utilities (compute-root, compute-image-id) |
| `contracts/` | Solidity contracts (Foundry project) |

## Key Invariants

When modifying code, be aware of these cross-component invariants that **must** remain consistent:

1. **Poseidon parameters** — Leaf: t=2 (1 input, R_P=56), Interior: t=3 (2 inputs, R_P=57). Must match in `guest/`, `cli/`, and `merkle-tree/`.

2. **Leaf encoding** — 12 zero bytes + 20 address bytes → BN254 field element. Same convention everywhere.

3. **Nullifier domain** — `b"ZKMist_V1_NULLIFIER"` (19 bytes, zero-padded to 32). Must match in guest program and CLI.

4. **Journal layout** — 84 bytes: `root[0:32] + nullifier[32:64] + recipient[64:84]`. Must match between guest program (`env::commit_slice`) and Solidity contract (`_journal[0:32]`, etc.).

5. **Merkle path direction** — `path_index[i]=0` → left child, `path_index[i]=1` → right child. Must match in guest program, CLI tree builder, and `merkle-tree` library.

6. **Test vectors** — PRD Appendix D defines expected outputs for a known private key. All implementations must reproduce these exact values. Run the relevant tests after any change to hashing or address derivation.

7. **⚠️ Guest program immutability** — Contracts are deployed on Base mainnet with a fixed `imageId` (SHA-256 of the guest binary). **Any change to `guest/src/main.rs` or `guest/Cargo.toml` changes the image ID, which will cause ALL proofs to be rejected by the on-chain verifier.** Do NOT modify the guest program source code unless you are intentionally preparing for a new deployment. Comments are safe to add; code changes are not. Suggestions for future versions are annotated with `NOTE (V2)` comments in the source.

## Pull Request Process

1. **Create a feature branch** from `main`.
2. **Make your changes** with clear, descriptive commit messages.
3. **Add tests** for any new functionality or bug fixes.
4. **Run the full lint suite** (`cargo fmt`, `cargo clippy`, `forge fmt`).
5. **Run all tests** and ensure they pass.
6. **Submit your PR** with a description of the change and motivation.

### What to include in your PR description

- What the change does and why
- Which components are affected (guest, CLI, contracts, merkle-tree)
- Whether any of the key invariants above are impacted
- Test results (paste output if relevant)

## Reporting Issues

When reporting bugs, please include:

- Steps to reproduce
- Expected vs actual behavior
- Rust version (`rustc --version`) and toolchain info
- Operating system
- Relevant log output

## Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability, please disclose it responsibly by opening a private security advisory on GitHub or contacting the maintainers directly.

## Code Style

- **Rust**: Follow `rustfmt` defaults. Add doc comments (`///`) for public functions explaining purpose, parameters, and invariants.
- **Solidity**: Follow `forge fmt` defaults. Use NatSpec comments (`@notice`, `@dev`) for all public/external functions.
- **Commits**: Use imperative mood ("add feature", "fix bug", not "added feature" or "fixes bug").

## License

By contributing to ZKMist, you agree that your contributions will be licensed under the MIT License.
