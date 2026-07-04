# Session Handoff — ZKMist Production Readiness & Axiom Migration

> **Read this first in a fresh session.** It captures everything needed to
> continue the work without re-discovering it. Last updated 2026-07-03.

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

**This is where to continue.** Two commits:
- `f63baea` — migration scope doc (`docs/axiom-backend-migration.md`).
- `2ab90f4` — **Phase 1 complete**: axiom stack (`halo2-base` + `halo2-ecc`)
  builds and runs in this repo. Foundation test
  (`circuits/tests/axiom_stack_foundation.rs`) PASSES.

### Deps added (coexist with PSE — no conflict)
```toml
halo2-base = "=0.5.0"   # Context/RangeChip eDSL + PoseidonChip, on halo2-axiom
halo2-ecc  = "=0.5.0"   # audited secp256k1 (EccChip, fixed_base_scalar_mult)
```

### What to do next (Phase 1 cont. → Phase 2)

1. **Port Poseidon to `halo2_base::poseidon::PoseidonChip`** — the project's
   hand-rolled `circuits/src/poseidon.rs` gets replaced. Write an integration
   test (like `axiom_stack_foundation.rs`) that hashes via halo2-base's chip
   and verifies. The PoseidonChip API:
   `PoseidonChip::new(ctx, OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>(), range)`.
   Must match the project's circom params (t=2 for leaf, t=3 for interior;
   R_F=8, R_P from light-poseidon). halo2-base re-exports halo2curves via
   `halo2_base::halo2_proofs::halo2curves`.

2. **halo2-ecc secp256k1 scalar·G** — use
   `EccChip::fixed_base_scalar_mult(ctx, &Secp256k1Affine::generator(), scalar_limbs, 256, 4)`.
   Extract pubkey bytes (halo2-ecc supports this — see PSE zkevm-circuits'
   `sig_circuit.rs` / `pk_bytes_le`). Feed to Keccak for the address bridge.

3. **Then Phase 3-4** per `docs/axiom-backend-migration.md`.

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
cat docs/axiom-backend-migration.md   # the scope/plan
cat docs/secp256k1-migration-plan.md  # the investigation history
cargo test -p zkmist-circuits --test axiom_stack_foundation -- --nocapture  # verify Phase 1
```

Then continue with the Poseidon port (step 1 above).

## Suggested first message for the fresh session

> "Read `docs/SESSION_HANDOFF.md`. We're on the `axiom-backend-migration` branch.
> Phase 1 (axiom stack foundation) is done. Continue with the Poseidon port:
> replace the hand-rolled Poseidon gadget with `halo2_base::poseidon::PoseidonChip`,
> write an integration test proving it works, then commit and push."

## Other production blockers (unchanged, for reference)

1. **External audit** — the hand-rolled secp256k1 (or the axiom migration's
   integration) needs professional review. Human work.
2. **Real-KZG → on-chain round-trip** — never exercised end-to-end. At k=23
   needs ~25 GiB (OOMs here); at k=18 (after migration) ~1 GiB (fits here).
3. **SRS provenance** — the pinned SRS hash is set but its lineage to the PSE
   ceremony's published transcript is unconfirmed. Investigation, no compute.
4. **`AIRDROP_CONTRACT`** — placeholder (`0x…dEaD`); fill after mainnet deploy.
5. **Testnet deployment** — not yet done on Base Sepolia.
