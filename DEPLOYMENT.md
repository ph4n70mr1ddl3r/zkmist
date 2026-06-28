# Deployment Runbook — ZKMist (ZKM)

> **Status: NOT deployable.** This runbook is the precise, ordered path from the
> current pre-alpha state to a mainnet deployment. Every step lists the exact
> command, the success criterion, and the artifact it produces. Do not skip
> steps or reorder them — each gate exists because deploying an incomplete step
> is either a brick (every honest claim reverts) or a soundness hole (proofs are
> forgeable). See [SECURITY.md](./SECURITY.md) for the threat model and
> [README.md](./README.md) for architecture.

The four blocking issues from the production review, in resolution order:

| # | Blocker | Owner | Why it blocks |
|---|---------|-------|---------------|
| 1 | On-chain verifier is a non-functional placeholder (`Halo2VerifyingKey.sol` k=21, all-zero fixed commitments; `gen-production-verifier` `synthesize` is a stub) | eng | Every honest proof would revert → airdrop mints nothing, forever |
| 2 | KZG SRS not pinned (`KZG_SRS_URL`/`KZG_SRS_SHA256` empty → prover falls back to a forgeable random SRS) | deployer | Whoever ran the prover can forge proofs → unlimited mint |
| 3 | secp256k1 non-native arithmetic is hand-rolled and unaudited; k=23 MockProver confirmation pending | eng + auditor | A missing constraint = forged proofs |
| 4 | No real proof has ever verified against the Solidity verifier; no testnet deployment | eng | The one property that matters is empirically unproven |

---

## Phase 0 — Confirm the circuit is sound (gate for everything else)

All circuit-soundness work is moot if the honest proof doesn't verify and the
negatives don't reject. The heavy tests are `#[ignore]d` (~2 min, ~15 GiB RSS
each at k=23, release build). Run them on a machine with ≥16 GiB free RAM:

```bash
# Honest proofs must verify
cargo test --release -p zkmist-circuits test_secp256k1_mock_prover        -- --ignored --nocapture
cargo test --release -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture

# Forged/invalid proofs must REJECT
cargo test --release -p zkmist-circuits test_wrong_merkle_root_rejected            -- --ignored --nocapture
cargo test --release -p zkmist-circuits test_wrong_nullifier_rejected              -- --ignored --nocapture
cargo test --release -p zkmist-circuits test_zero_recipient_rejected               -- --ignored --nocapture
cargo test --release -p zkmist-circuits test_recipient_exceeding_uint160_rejected  -- --ignored --nocapture
```

**Pass criterion:** all six pass. The honest tests must additionally derive the
test-vector address `0xfcad0b19bb29d4674531d6f115237e16afce377c`. The code
comment in `circuits/src/secp256k1.rs` (`carry_chain_columns` /
`reduce_canonical_mod_p`) explicitly flags this confirmation as
not-yet-validated-in-this-environment — treat the circuit as
IMPLEMENTED-BUT-UNVALIDATED until these pass.

**Do not proceed** if any honest test fails (soundness bug) or any negative test
passes (missing constraint).

> Note on the `EXPECTED_CS_DIGEST` guard: it only pins `configure()` (the
> gate/column STRUCTURE). It cannot detect a wrong `synthesize` witness or a
> missing copy constraint. `MockProver` is what catches those — which is why
> Phase 0 is non-negotiable.

---

## Phase 1 — External audit (parallelizable with Phase 0, blocks Phase 4)

Commission an independent audit of:

1. **`circuits/src/secp256k1.rs`** — the hand-rolled non-native field arithmetic:
   `field_mul` / `field_add_carried` / `field_sub`, the `carry_chain_columns`
   integer carry chain, `reduce_canonical_mod_p` (witnessed quotient
   `result + q·p = V` + canonicalization `result < p`), `check_on_curve`,
   `constrain_affine`, limb range checks, `scalar_mul`.
2. **`circuits/src/keccak.rs`** — the Keccak-256 chip (θ/ρ/π/χ/ι), the `RC`
   table, and the constrained `tiny_keccak` cross-check.
3. **`circuits/src/poseidon.rs`** and the Merkle `cond_swap` gadget
   (`s_bool`/`s_mul`/`s_add` product gates).
4. The three-pillar binding: secp scalar `k` ↔ Keccak address ↔ nullifier
   (`bind_limb_to_inputs` and the nullifier↔scalar copy constraints).

**Strongly recommended (defense-in-depth):** replace the hand-rolled secp256k1
gadget with an audited library — `scroll-tech/halo2-secp256k1` or
`privacy-scaling-explorations/halo2wrong`. Either eliminates the largest
unaudited surface. If swapped, re-run Phase 0 (the circuit `k` and
`EXPECTED_CS_DIGEST` will change — regenerate both).

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

## Phase 3 — Generate the REAL on-chain verifier (eliminates the placeholder)

The current `contracts/src/Halo2Verifier.sol` + `Halo2VerifyingKey.sol` are a
**placeholder**: the VK has `k = 0x15 (21)` with all-zero fixed commitments, but
the prover runs at `CIRCUIT_K = 23`. A k=23 proof cannot verify against a k=21
VK. This must be regenerated from the real circuit.

**Why this is non-trivial (the version split):** `zkmist-circuits` and the CLI
build against crates.io `halo2_proofs 0.3.x`. The Solidity codegen library
(`vendor/halo2-solidity-verifier`) builds against the PSE **git fork** of halo2
(tag v0.3.0). The two halo2 versions have divergent APIs
(`query_fixed(col, Rotation)` vs `(col)`; `lookup(name, closure)` vs `(closure)`;
transcript `Blake2bRead/Write::init`, `SingleVerifier`, lifetimes) and are
distinct crates to Cargo, so `gen-production-verifier` cannot simply `use
zkmist_circuits::ZKMistV2Claim`. Today it carries a hand-maintained re-port of
`configure()` and a **stub `synthesize()`**, guarded by `SYNTHESIZE_IS_STUB`
so it refuses to emit.

**Choose one path (in order of preference):**

### Path A — Swap in an audited secp256k1 library AND unify on one halo2 (best)
If Phase 1's recommendation to swap secp256k1 is taken, port the whole workspace
onto the PSE git fork in the same change (so `gen-production-verifier` depends
on `zkmist-circuits` directly and the stub is deleted). This requires adapting
the CLI prover's transcript calls to the git-fork API — security-critical, so
re-run Phase 0 afterward. The version split then disappears entirely.

### Path B — Complete the `synthesize()` re-port in `gen-production-verifier`
Keep the version split. Port the full `synthesize()` body + all chips listed in
the `PORT-TODO` comment at the top of `gen-production-verifier/src/main.rs`
into the git-fork API (`query_fixed(col, Rotation::cur())`, `lookup(name, …)`).
Then set `SYNTHESIZE_IS_STUB = false`. **Re-run Phase 0 afterward** (the port is
a transcription of security-critical witness assignment).

Either way, generate against the **same pinned SRS** from Phase 2:

```bash
# Path A or B, once synthesize is real:
cargo run --release -p zkmist-gen-production-verifier -- \
    --output contracts/src \
    --k 23 \
    --params-file /path/to/pse-halo2-kzg-srs-k23.bin
```

**Cross-check (mandatory):** the generator prints the VK `transcript_repr` and a
pinned SHA-256. They MUST match the values printed by the prover-side tool
against the same SRS:
```bash
cargo run --release -p zkmist-tools --bin gen-verifier --features v2 -- \
    --params-file /path/to/pse-halo2-kzg-srs-k23.bin
```
Mismatch ⇒ the circuit or SRS drifted; do not deploy.

**Pass criterion:**
- `contracts/src/Halo2VerifyingKey.sol` has `k = 0x17 (23)` and NON-zero fixed
  commitments (range8, secp `SECP_P`, keccak `RC`, poseidon round constants).
- VK `transcript_repr` matches between the generator and the prover tool.
- `cargo run -p zkmist-tools --bin readiness` check `[1b/8]` is green (no more
  "ALL fixed commitments are zero" / "k-value MISMATCH" warnings).

```bash
cd contracts && forge build && forge test -vvv
```

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
[ ] Phase 0  — all 6 #[ignore]d MockProver tests pass at k=23
[ ] Phase 1  — external audit report, no open Critical/High
[ ] Phase 2  — PSE SRS pinned; readiness [1d/8] green
[ ] Phase 3  — real Halo2Verifier.sol + Halo2VerifyingKey.sol (k=23, non-zero fixed); VK repr matches prover; readiness [1b/8] green
[ ] Phase 4  — real proof mints on local anvil; tampered proof reverts
[ ] Phase 5  — real claim mints on Base Sepolia; nullifier replay reverts
[ ] Phase 6  — mainnet deploy + Basescan verification; CLI constants updated
[ ] Phase 7  — monitor running; alerts configured
```

`cargo run -p zkmist-tools --bin readiness` should report **all green** before
Phase 6.
