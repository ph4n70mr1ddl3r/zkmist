# Deployment Runbook — ZKMist (ZKM)

> **Status: NOT deployable.** This runbook is the precise, ordered path from the
> current pre-alpha state to a mainnet deployment. Every step lists the exact
> command, the success criterion, and the artifact it produces. Do not skip
> steps or reorder them — each gate exists because deploying an incomplete step
> is either a brick (every honest claim reverts) or a soundness hole (proofs are
> forgeable). See [SECURITY.md](./SECURITY.md) for the threat model and
> [README.md](./README.md) for architecture.

The four blocking issues from the production review, current status:

| # | Blocker | Current status |
|---|---------|----------------|
| 1 | On-chain verifier was a non-functional placeholder (all-zero VK) | **RESOLVED.** `contracts/src/Halo2Verifier.axiom.sol` is the real snark-verifier-generated axiom verifier (a `fallback` contract ending in a BN254 ecPairing precompile call `0x8`, 565 non-zero VK constants). Emitted by `circuits/tests/claim_evm_roundtrip.rs` under `ZKMIST_EMIT_VERIFIER` + `ZKMIST_USE_PINNED_SRS`, at circuit **k=21** against the pinned SRS. Readiness checks `[1/8]` + `[1b/8]` are green. |
| 2 | KZG SRS not pinned → forgeable random SRS | **RESOLVED.** `KZG_SRS_SHA256` / `KZG_SRS_URL` (`cli/src/constants.rs`) pin the PSE perpetual-powers-of-tau **k=23** file (universal; `srs_k ≥ circuit_k`). Provenance is byte-confirmed against the public beaconed ceremony transcript by `tools/src/verify_srs_from_ptau.rs`. Readiness `[1c/8]` (no random SRS) + `[1d/8]` (pinned) are green. |
| 3 | secp256k1 non-native arithmetic was hand-rolled & unaudited | **Mostly resolved.** The hand-rolled PSE `secp256k1.rs` is replaced by `secp_axiom.rs`, built on **halo2-ecc's audited chips** (`FpChip` / `EccChip::fixed_base_scalar_mult` / `ProperCrtUint`). Remaining custom surface to audit: the pubkey **byte-bridge** (`field_point_to_le_bytes`), the Keccak-256 chip, the Poseidon/Merkle gadgets, and the three-pillar (secp↔Keccak-address↔nullifier) wiring. **Still needs an external audit.** |
| 4 | No real proof has verified on-chain; no testnet | **Partially open.** The Rust prover generates valid real-KZG proofs (`test_axiom_claim_real_kzg_roundtrip` passes at k=21) and the revm EVM round-trip (`test_claim_circuit_evm_roundtrip`) passes. The committed-verifier on-chain gate (`contracts/test/ZKM.realroundtrip.t.sol`) is **opt-in** (`RUN_REAL_ROUNDTRIP=1`) with an intentionally-uncommitted fixture — a manual pre-mainnet step. No testnet deployment yet. |

> **Bottom line:** still **NOT deployable.** Open work: external audit (Phase 1), the opt-in on-chain fixture round-trip (Phase 4), testnet (Phase 5).

---

## Phase 0 — Confirm the circuit is sound (gate for everything else)

> **✅ Status: PASSING.** The axiom claim-circuit test suite
> (`cargo test -p zkmist-circuits`) is green: the honest happy-path verifies,
> the four negative cases reject, the production depth-26 circuit is
> MockProver-satisfied at **k=21**, and the real-KZG + revm-EVM round-trips
> pass. **Re-run after any change to `circuits/`** — it is the regression gate
> for every later phase.

All circuit-soundness work is moot if the honest proof doesn't verify and the
negatives don't reject. On the axiom backend these run as ordinary (non-`#[ignore]d`)
tests under `cargo test -p zkmist-circuits`; the depth-26 claim + real-KZG
round-trip dominate the runtime (the `claim_axiom` suite is the heavy one).
Run on a machine with ample RAM:

```bash
# Full suite (honest + negatives + production depth + real-KZG + EVM round-trip)
cargo test --release -p zkmist-circuits -- --nocapture

# Or the claim-circuit soundness tests individually:
cargo test --release -p zkmist-circuits test_axiom_claim_happy_path          -- --nocapture
cargo test --release -p zkmist-circuits test_axiom_claim_production_depth26 -- --nocapture
# Negatives must REJECT:
cargo test --release -p zkmist-circuits test_axiom_claim_rejects_wrong_root     -- --nocapture
cargo test --release -p zkmist-circuits test_axiom_claim_rejects_wrong_nullifier -- --nocapture
cargo test --release -p zkmist-circuits test_axiom_claim_rejects_zero_recipient -- --nocapture
cargo test --release -p zkmist-circuits test_axiom_claim_rejects_key_above_n   -- --nocapture
```

**Pass criterion:** the honest happy-path verifies; the four negative cases
reject; `test_axiom_claim_production_depth26` is satisfied at k=21.

**Do not proceed** if any honest test fails (soundness bug) or any negative
test passes (missing constraint).

> Caveat (unchanged from the PSE era): MockProver (axiom's `base_test()`) only
> checks the constraints that *exist* — it cannot detect a *missing* constraint.
> That gap is exactly what the external audit (Phase 1) closes.

---

## Phase 1 — External audit (parallelizable with Phase 0, blocks Phase 4)

> Phase 0 is now complete; **Phase 1 is the next gate.**

Commission an independent audit of:

1. **`circuits/src/secp_axiom.rs`** — the secp256k1 pubkey gadget. The scalar
   mult now runs on **halo2-ecc's audited chips** (`FpChip` /
   `Secp256k1Chip` / `EccChip::fixed_base_scalar_mult` / `ProperCrtUint`);
   the custom surface to audit is the **pubkey byte-bridge**
   (`field_point_to_le_bytes` — extracting an secp256k1-Fp coordinate as 32
   constrained little-endian bytes) and `enforce_scalar_less_than_n`.
2. **`circuits/src/keccak_axiom.rs`** — the Keccak-256 chip (θ/ρ/π/χ/ι), the
   `RC` table, and the constrained `tiny_keccak` cross-check.
3. **`circuits/src/poseidon_axiom.rs`** and the Merkle gadget
   (`merkle_axiom.rs`) — the Poseidon sponge + the leaf/interior hashing and
   the path-index conditional swap.
4. The three-pillar binding: secp scalar `k` ↔ Keccak-derived address ↔
   nullifier (`claim_axiom.rs` wiring + the public-instance copy constraints).

**Note:** the earlier "replace the hand-rolled secp256k1 gadget with an
audited library" recommendation is **done** — `halo2-ecc` is that library.
Remaining audit scope is the custom glue above, not non-native field arithmetic.

**Artifact:** signed audit report with no Critical/High findings open.

---

## Phase 2 — Pin the KZG SRS (the system's only trust root)

Halo2-KZG commits against a Structured Reference String. A self-generated SRS
(`Params::new`) is a 1-of-1 trust root: whoever generated it knows the trapdoor
and can forge any proof. Mainnet MUST use the public PSE perpetual
powers-of-tau ceremony SRS.

1. **Obtain** the PSE halo2 KZG params file at k ≥ 23 (≈hundreds of MB). Source:
   https://github.com/privacy-scaling-explorations/perpetualpowersoftau
   (download the halo2-format params for the BN254/KZG ceremony, k ≥ 23).
2. **Independently verify** its SHA-256 against the community-published digest
   (do not trust a single source — cross-check the PSE repo, mirrors, and any
   audit report). See `docs/kzg-srs.md`.
3. **Pin** the URL and SHA-256 in `cli/src/constants.rs`:
   ```rust
   pub const KZG_SRS_URL: &str = "https://<mirror>/halo2-kzg-srs-k23.bin";
   pub const KZG_SRS_SHA256: &str = "<lowercase hex, no 0x>";
   ```
4. **Confirm the readiness checker passes** check `[1d/8]`:
   ```bash
   cargo run -p zkmist-tools --bin readiness
   ```

**Pass criterion:** readiness check `[1d/8]` is green and the prover loads the
pinned file (no `ZKMIST_DEV_SRS` fallback) when generating a proof.

> The same pinned SRS file MUST also be fed to the verifier generator
> (Phase 3, `--params-file`). The VK's commitments are SRS-dependent; if the
> prover's SRS and the generator's SRS differ, every honest proof is rejected.

---

## Phase 3 — The on-chain verifier (axiom backend)

> **✅ DONE.** `contracts/src/Halo2Verifier.axiom.sol` is the **real**
> snark-verifier-generated axiom verifier — a `fallback` contract whose final
> gate is a BN254 pairing-precompile call (`staticcall(gas(), 0x8, …)`), with
> 565 non-zero VK `mstore` constants. It was emitted against the **pinned**
> ceremony SRS (its header carries the `PINNED-SRS VERIFIER` banner, not the
> `DEV-SRS WIRING-ONLY` one). Circuit **k=21**; the SRS is k=23 (universal,
> `srs_k ≥ circuit_k`). Readiness `[1/8]` (pairing gate present) + `[1b/8]`
> (real VK data) are green. **No action is needed unless the circuit changes.**

The verifier is generated by `circuits/tests/claim_evm_roundtrip.rs`
(`test_claim_circuit_evm_roundtrip`). Generation is env-var-gated so an
ordinary test run never silently overwrites the committed verifier:

| env var | effect |
|---|---|
| `ZKMIST_EMIT_VERIFIER=<path>` | write the generated `.sol` to `<path>` (otherwise the verifier is built only in-memory for the revm round-trip) |
| `ZKMIST_USE_PINNED_SRS=1` | prove/emit against the **pinned** PSE ceremony SRS (`PINNED-SRS VERIFIER` banner). Unset ⇒ toxic-waste `gen_srs` (`DEV-SRS WIRING-ONLY` banner — wiring-valid, **not** mainnet-sound) |

### Regenerating the verifier (only if the circuit changes)

Re-run Phase 0 first; if the circuit `k` or VK changed, this is where it
lands on-chain.

```bash
# Emit against the PINNED ceremony SRS — the only mode that produces a
# mainnet-sound verifier.
ZKMIST_EMIT_VERIFIER=contracts/src/Halo2Verifier.axiom.sol \
ZKMIST_USE_PINNED_SRS=1 \
cargo test --release -p zkmist-circuits test_claim_circuit_evm_roundtrip -- --nocapture
```

**Pass criterion:**
- The file header carries the `PINNED-SRS VERIFIER` banner (NOT `DEV-SRS`).
- `cargo run -p zkmist-tools --bin readiness` checks `[1/8]` + `[1b/8]` stay green.
- `cd contracts && forge build && forge test` still passes.

```bash
cd contracts && forge build && forge test -vvv
```

> **Safeguard:** without `ZKMIST_EMIT_VERIFIER` the test never writes a file,
> and without `ZKMIST_USE_PINNED_SRS=1` the emitted file is banner-marked
> `DEV-SRS WIRING-ONLY`, so a dev-SRS VK can never be mistaken for a
> mainnet verifier. (The retired PSE workflow — `gen-production-verifier` /
> `Halo2VerifyingKey.sol` / the crates.io↔git-fork compat shim — no longer
> exists; the whole stack is now axiom `halo2-base` + `snark-verifier-sdk`.)

---

## Phase 4 — Real proof → Solidity verifier round-trip (local)

Before any testnet spend, prove the end-to-end plumbing works against the
REAL verifier generated in Phase 3.

```bash
# 1. Spin up a local Base fork
anvil --fork-url https://mainnet.base.org &

# 2. Deploy the three contracts locally
cd contracts && forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast

# 3. Generate a real Halo2 proof (against the pinned SRS)
ZKMIST_DEV_SRS=0  # ensure the pinned SRS is used, not a random one
cargo run --release -p zkmist-cli --bin zkmist -- prove   # interactive

# 4. Submit the proof to the locally-deployed ZKMAirdrop
cast send <AIRDROP_ADDR> "claim(bytes,bytes32,address)" \
    $(cat ~/.zkmist/proofs/zkmist_proof_*.json | jq -r '.proof' ...) \
    <nullifier> <recipient> --rpc-url http://127.0.0.1:8545 --private-key 0x...

# 5. Assert the claim minted 10,000 ZKM
cast call <TOKEN_ADDR> "balanceOf(address)(uint256)" <recipient> --rpc-url http://127.0.0.1:8545
```

**Pass criterion:** balance is exactly `10_000_000_000_000_000_000_000` (10,000e18).
Then replay step 3–4 with a **tampered** proof (flip one byte) and assert it
REVERTS with `"Invalid proof"`.

---

## Phase 5 — Testnet deployment (Base Sepolia)

```bash
export PRIVATE_KEY=0x...   # deployer wallet, funded with Base Sepolia ETH
./scripts/testnet-deploy.sh
```

The script deploys, verifies contracts on Basescan, and prints addresses.
Update `AIRDROP_CONTRACT` and `TOKEN_CONTRACT` in `cli/src/constants.rs`.

Run a full real claim on testnet end-to-end (the `--full` path):
```bash
./scripts/e2e-test.sh --full
```

**Pass criterion:** a real claim mints on Base Sepolia, a replayed nullifier
reverts (`"Already claimed"`), and a tampered proof reverts (`"Invalid proof"`).

---

## Phase 6 — Mainnet deployment (Base)

Only after Phases 0–5 are green AND the audit report has no open
Critical/High findings.

```bash
cd contracts
forge script script/Deploy.s.sol --rpc-url https://mainnet.base.org --broadcast
forge verify-contract <addr> Halo2Verifier    --chain base
forge verify-contract <addr> ZKMToken         --chain base
forge verify-contract <addr> ZKMAirdrop       --chain base
```

Update `AIRDROP_CONTRACT` / `TOKEN_CONTRACT` in `cli/src/constants.rs`,
rebuild the CLI, cut a release, and publish the eligibility list to GitHub
Releases with per-file SHA-256 (the CLI verifies these against the hardcoded
Merkle root on `zkmist fetch`).

---

## Phase 7 — Post-deployment monitoring

```bash
cargo run -p zkmist-tools --features monitoring --bin monitor -- \
    <AIRDROP_ADDR> --rpc https://mainnet.base.org --interval 60
```

Alert on: claims/hour > 10,000 (surge), `totalSupply() != totalClaims × 10_000e18`
(supply anomaly), any `"Already claimed"` revert (nullifier collision — should
never happen, see the birthday-bound analysis in SECURITY.md). See SECURITY.md
"Post-Deployment Monitoring" for the full metric table.

---

## One-page checklist

```
[x] Phase 0  — axiom circuit suite green (happy-path + 4 negatives + depth-26 @ k=21)
[ ] Phase 1  — external audit (secp byte-bridge, Keccak, Poseidon/Merkle, wiring)  ← NEXT GATE
[x] Phase 2  — PSE SRS pinned + provenance confirmed; readiness [1c/8]+[1d/8] green
[x] Phase 3  — Halo2Verifier.axiom.sol is the real pinned-SRS axiom verifier (k=21)
[ ] Phase 4  — opt-in on-chain round-trip (RUN_REAL_ROUNDTRIP=1) + local anvil mint
[ ] Phase 5  — real claim mints on Base Sepolia; nullifier replay reverts
[ ] Phase 6  — mainnet deploy + Basescan verification; CLI constants updated
[ ] Phase 7  — monitor running; alerts configured
```

`cargo run -p zkmist-tools --bin readiness` should report **all green** before
Phase 6.
