# Contributing to ZKMist

Thank you for your interest in ZKMist! This project is fully community-owned — contributions are welcome and encouraged.

## Quick Start

```shell
git clone --recursive https://github.com/ph4n70mr1ddl3r/zkmist.git
cd zkmist

# Build the CLI
cargo build --release -p zkmist-cli

# Run tests
cargo test -p zkmist-merkle-tree
cargo test -p zkmist-circuits
cargo test -p zkmist-cli --bin zkmist
```

## Development Setup

### Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs)
- **Foundry** — [getfoundry.sh](https://book.getfoundry.sh/) (for Solidity contracts)

### Running Tests

```shell
# Rust unit tests
cargo test -p zkmist-merkle-tree
cargo test -p zkmist-circuits
cargo test -p zkmist-cli --bin zkmist

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
| `circuits/` | Halo2-KZG circuit definitions (Rust) |
| `cli/` | User-facing CLI tool (Rust) |
| `merkle-tree/` | Shared Poseidon Merkle tree library (Rust) |
| `tools/` | Dev utilities (compute-root, gen-verifier) |
| `contracts/` | Solidity contracts (Foundry project) |

## Key Invariants

When modifying code, be aware of these cross-component invariants that **must** remain consistent:

1. **Poseidon parameters** — Leaf: t=2 (1 input, R_P=56), Interior: t=3 (2 inputs, R_P=57). Must match in `circuits/`, `cli/`, and `merkle-tree/`.

2. **Leaf encoding** — 12 zero bytes + 20 address bytes → BN254 field element. Same convention everywhere.

3. **Nullifier domain** — `b"ZKMist_V2_NULLIFIER"` (19 bytes, zero-padded to 32). Must match in circuit and CLI.

4. **Merkle path direction** — `path_index[i]=0` → left child, `path_index[i]=1` → right child. Must match in circuit, CLI tree builder, and `merkle-tree` library.

5. **Test vectors** — The project defines expected outputs for a known private key. All implementations must reproduce these exact values. Run the relevant tests after any change to hashing or address derivation.

6. **Circuit invariants** — The Halo2 circuit must reproduce the exact same Poseidon outputs as the `light-poseidon` crate for test vectors to match.

## Pull Request Process

1. **Create a feature branch** from `main`.
2. **Make your changes** with clear, descriptive commit messages.
3. **Add tests** for any new functionality or bug fixes.
4. **Run the full lint suite** (`cargo fmt`, `cargo clippy`, `forge fmt`).
5. **Run all tests** and ensure they pass.
6. **Submit your PR** with a description of the change and motivation.

### What to include in your PR description

- What the change does and why
- Which components are affected (circuits, CLI, contracts, merkle-tree)
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
