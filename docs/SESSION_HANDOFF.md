# Session Handoff — ZKMist Production Readiness & Axiom Migration

> **Read this first in a fresh session.** It captures everything needed to
> continue the work without re-discovering it. Last updated 2026-07-04.

## Project

**ZKMist (ZKM)** — privacy-preserving ERC-20 airdrop on Base. Halo2-KZG ZK
proofs. Claimant proves ownership of an eligible Ethereum private key without
revealing it. ~64M eligible addresses, up to 1M claims, 10,000 ZKM per claim.

**Machine:** 32 GB physical / 28 GB WSL2 (`.wslconfig` set to 28 GB this session).

## Current state — what's done

### Master (6 commits, clean, production-safe)
- `40e439b` — **preflight recalibration**: the OOM crash fix (real-KZG proving
  peaks ~25 GiB at k=23; preflight now refuses <31 GiB with clear guidance).
- `1884265` — migration design doc (`docs/secp256k1-migration-plan.md`).
- `c095fe9` — Phase A: halo2wrong dep added + binding glue extracted to
  `gadgets/field_accumulator.rs` (digest-neutral, production-safe).
- `ef53562` — halo2wrong integration test (scalar·G MockProver PASSES).
- `dd7569e` — binding re-derivation spec (§5a, API-confirmed).
- `3c5cce6` — nullifier binding mechanism proven (native() positive + negative).

### Phase 0 soundness — PROVEN on this machine
All 7 heavy MockProver tests pass at k=23 (the hand-rolled secp256k1 circuit):
secp256k1 MockProver, full E2E, 4 negative forgery-rejection tests, Keccak.
This required the `.wslconfig` fix (28 GB → ~26 GiB available; 19.5 GiB peak).

### Key config changes
- `/mnt/c/Users/riddler/.wslconfig`: `memory=28GB` (was 32 — the 32 starved
  Windows, causing WSL2 balloon-reclaim → OOM). Do NOT raise back to 32.
- `cli/src/halo2_prover.rs`: `CIRCUIT_K = 23`. `min_required_ram_gib` anchored
  to ~27 GiB (real-KZG peak). Do NOT change back to the old VmPeak anchor.

## The core problem (why we're migrating)

The hand-rolled secp256k1 (`circuits/src/secp256k1.rs`, 3700 lines) is:
1. **Unaudited** — the #1 production blocker.
2. **k=23** — real-KZG proving peaks ~25 GiB, OOMs on 32 GB machines (both dev
   and every claimant's `zkmist prove`).

A library swap would fix both (k=18 → ~1 GiB proving + audited code). But:

### Both PSE-compatible library options are BLOCKED (proven this session)
- **halo2wrong** (PSE backend, compatible): its CRT/RNS limb representation
  **cannot expose the pubkey as bytes** → the `keccak(pubkey)→address` binding
  (unique to ZKMist; only zkEVMs do this) is impossible. Both `native()` (wrong
  for base-field Fp) and per-limb binding (limbs are CRT residues, not bit-slices)
  fail. Confirmed at 68-bit AND 72-bit. Root-caused on `phase-b-halo2wrong-rewiring`.
- **halo2-ecc** (axiom backend): **CAN** extract pubkey bytes (PSE's own
  `zkevm-circuits` uses it for exactly this) — BUT it requires the entire axiom
  halo2 stack (`halo2curves-axiom` ≠ PSE `halo2curves`) → incompatible `Fr`
  types → **not a chip swap, a full backend switch**.

### The decision: axiom backend migration
Full migration to the axiom stack is the **only viable path** to:
- **k=18** (~1 GiB proving — fits 32 GB and claimants' laptops).
- **Audited secp256k1** (halo2-ecc) + **audited Poseidon** (halo2-base ships one).
- **Wirable keccak bridge** (halo2-ecc exposes pubkey bytes).
- **2 of 3 hand-rolled gadgets replaced** (secp → halo2-ecc, Poseidon →
  halo2-base). Only Keccak needs porting.

Scope documented in `docs/axiom-backend-migration.md` (4-phase plan, ~2-4 weeks).

## Active branch: `axiom-backend-migration`

**This is where to continue.** Commits (latest first):
- _(pending)_ — **Phase 4 step 1: off-chain tree → halo2-base convention** —
  `merkle-tree/src/halo2base.rs`; cross-checked byte-for-byte against
  `poseidon_axiom` AND end-to-end (off-chain-built tree verified in-circuit).
  Resolves the §9.1 sponge-convention decision (adopt halo2-base end-to-end).
  See `docs/axiom-backend-migration.md` §12.
- `19a01cc` — **Phase 3 step 4: K<n range proof + 4 negatives** — the §5a
  TRAP closed; full claim circuit now rejects wrong-root / wrong-nullifier /
  zero-recipient / K≥n. **Phase 3 circuit work complete.**
- `c2c1e57` — **Phase 3 step 2: Merkle + nullifier axiom ports + address
  bridge** — all gadgets ported; `keccak(pubkey)→address` proven end-to-end.
- `2aca3cb` — **Phase 3 step 1: Keccak port** — bit-level Keccak-f[1600] on
  halo2-base; verified vs tiny_keccak + privkey=1 vector.
- `06cdfe4` — **Phase 2: secp + pubkey byte-bridge** (`halo2-ecc`).
- `5d5a882` — **Phase 1 cont.: Poseidon port** — hand-rolled Poseidon replaced
  with `halo2_base::poseidon::PoseidonChip`; verified in
  `circuits/tests/poseidon_axiom.rs` (params byte-match light-poseidon; chip
  matches native sponge). See `docs/axiom-backend-migration.md` §9.
- `2ab90f4` — **Phase 1 complete**: axiom stack (`halo2-base` + `halo2-ecc`)
  builds and runs in this repo. Foundation test
  (`circuits/tests/axiom_stack_foundation.rs`) PASSES.
- `f63baea` — migration scope doc (`docs/axiom-backend-migration.md`).

### Deps added (coexist with PSE — no conflict)
```toml
halo2-base = "=0.5.0"   # Context/RangeChip eDSL + PoseidonChip, on halo2-axiom
halo2-ecc  = "=0.5.0"   # audited secp256k1 (EccChip, fixed_base_scalar_mult)
# dev-dep: native Poseidon reference (raw Grain-LFSR constants + dense MDS)
poseidon-primitives = "0.2"
```

### What to do next (productionize — Phase 4)

1. **✅ DONE — Poseidon port** (`halo2_base::poseidon::PoseidonChip`).
2. **✅ DONE — secp + pubkey byte-bridge** (`halo2-ecc`).
3. **✅ DONE — Keccak port** (bit-level Keccak-f[1600], `keccak_axiom.rs`).
4. **✅ DONE — Merkle + nullifier axiom ports** (`merkle_axiom.rs`,
   `nullifier_axiom.rs`).
5. **✅ DONE — address bridge** (`tests/address_bridge_axiom.rs`).
6. **✅ DONE — claim circuit + full soundness** (`claim_axiom.rs` +
   `tests/claim_axiom.rs`): happy path + 4 negatives (wrong root, wrong
   nullifier, zero recipient, K≥n), all §5/§5a bindings incl. the K<n range proof.
   **The axiom circuit is complete and sound (MockProver-verified).**
7. **TODO — productionize (Phase 4):**
   (a) ✅ off-chain tree → halo2-base convention (done, §12);
   (b) optionally a lookup-table χ for Keccak to bring the circuit from k≈21
     back toward the k=18 target (~1 GiB proving);
   (c) port `cli/src/halo2_prover.rs` to the axiom backend; regenerate the
     on-chain verifier; real-KZG round-trip; testnet deploy.
8. **External audit** of the (now much smaller) integration + Keccak port.

**Soundness note:** the circuit is MockProver-verified sound (positive + 4
negatives). The new unaudited integration surface is the K<n range proof, the
byte-bridge, and the in-circuit Keccak (the audited libs are halo2-ecc /
halo2-base). Real-KZG + on-chain round-trip has never been exercised
(production blocker #2) — Phase 4.

## Reference branches (do NOT merge — investigation records)

| Branch | What | Key finding |
|---|---|---|
| `phase-b-halo2wrong-rewiring` | 68-bit rewiring + root-cause test | mul correct (point matches G·K); `native()` of Fp is wrong; CRT limbs aren't byte-extractable |
| `phase-b-halo2ecc` | halo2-ecc investigation (reverted) | Requires axiom halo2 stack (halo2curves-axiom ≠ PSE) |
| `halo2wrong-72bit-spike` | 72-bit mul spike | mul PASSES at 72-bit; per-limb binding still fails (CRT issue) |

## Key technical facts (don't re-discover these)

- **halo2wrong's CRT limbs ≠ byte-slices.** The limbs are residues mod coprime
  moduli (Chinese Remainder Theorem). You cannot byte-extract them. This is the
  fundamental reason halo2wrong can't bridge to Keccak — not a limb-size issue.
- **halo2-ecc CAN extract pubkey bytes.** PSE's `zkevm-circuits` does
  `keccak(pub_key_bytes)` "where pub_key_bytes is built from the pub_key" —
  halo2-ecc's FpChip supports this (halo2wrong's doesn't).
- **halo2curves-axiom ≠ halo2curves.** Different Fr types. Cannot mix. The axiom
  migration is all-or-nothing per circuit.
- **`base_test().k(k).lookup_bits(bits).run(|ctx, range| -> Fr { ... })`** — the
  axiom test harness. `ctx: &mut Context<Fr>`, `range: &RangeChip<Fr>`.
- **Phase 0 passes at k=23** — the hand-rolled circuit IS sound (MockProver-
  verified). The issue is k=23 → ~25 GiB real-KZG, not soundness.
- **`AssignedValue<F>` = `AssignedCell<F,F>`** (halo2-base type alias). In
  halo2wrong, same alias. In halo2-ecc, `AssignedValue` is halo2-base's.
- **The secp256k1 circuit's binding** (Finding 1/2/3) is documented in
  `docs/secp256k1-migration-plan.md` §5/§5a. The three pillars: leaf↔address,
  nullifier↔scalar, recipient↔uint160. Read §5a for the re-derivation logic.

## How to resume (for the fresh session)

```bash
cd ~/zkmist
git checkout axiom-backend-migration
cat docs/axiom-backend-migration.md   # scope/plan (§9 Poseidon, §10 secp, §11 Keccak/gadgets/bridge)
cat docs/secp256k1-migration-plan.md  # the investigation history (§5/§5a bindings)
cargo test -p zkmist-circuits --test claim_axiom            # happy path + 4 negatives
cargo test -p zkmist-circuits --test address_bridge_axiom    # secp+keccak crux
cargo test -p zkmist-circuits --test keccak_axiom            # Keccak port
cargo test -p zkmist-circuits --test secp_axiom              # secp byte-bridge + K<n
cargo test -p zkmist-circuits --test poseidon_axiom          # Poseidon port
cargo test -p zkmist-circuits --lib -- merkle_axiom nullifier_axiom
```

**Phase 3 circuit work is complete.** Next is Phase 4 (productionize): port
`zkmist-merkle-tree` to halo2-base Poseidon, optionally optimize Keccak's χ
(k≈21 → k≈18), port the prover to axiom, regen the verifier, real-KZG round-
trip, testnet deploy.

## Suggested first message for the fresh session

> "Read `docs/SESSION_HANDOFF.md`. We're on the `axiom-backend-migration`
> branch. Phases 1–3 are done — the full axiom claim circuit is MockProver-
> verified sound (happy path + 4 negatives, all §5/§5a bindings incl. the K<n
> range proof). Continue with Phase 4: port `zkmist-merkle-tree` to the
> halo2-base Poseidon convention so a real eligibility root verifies, then
> port the prover / regen the verifier / do a real-KZG round-trip. Decide
> whether to optimize Keccak's χ (k≈21→18) first. Commit and push each verified
> step."

## Other production blockers (unchanged, for reference)

1. **External audit** — the hand-rolled secp256k1 (or the axiom migration's
   integration) needs professional review. Human work.
2. **Real-KZG → on-chain round-trip** — never exercised end-to-end. At k=23
   needs ~25 GiB (OOMs here); at k=18 (after migration) ~1 GiB (fits here).
3. **SRS provenance** — the pinned SRS hash is set but its lineage to the PSE
   ceremony's published transcript is unconfirmed. Investigation, no compute.
4. **`AIRDROP_CONTRACT`** — placeholder (`0x…dEaD`); fill after mainnet deploy.
5. **Testnet deployment** — not yet done on Base Sepolia.
