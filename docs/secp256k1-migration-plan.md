# Replace the hand-rolled secp256k1 gadget with `halo2wrong`

> **Status:** DESIGN / SCOPE — not yet implemented. This is the production track
> for both (a) removing the #1 audit blocker and (b) potentially halving the
> proving RAM by reaching k=22.
>
> **Originates from the 2026-07-03 production-readiness review.** The preflight
> recalibration (commit `40e439b`) made the *symptom* (silent OOM-crash) loud;
> this document addresses the *root cause* (the circuit is too big for k=22).

## 1. Why

Two independent reasons, each sufficient on its own:

1. **Soundness.** `circuits/src/secp256k1.rs` (3707 lines) is hand-rolled
   non-native field arithmetic — the single largest *unaudited* surface in the
   project and the explicit #1 blocker in `SECURITY.md`. The 2026-07-01
   bug-hunt closed a systemic "free constant cell" class there; an audit is
   still required, and an audit of a reimplementation is poor use of budget
   when audited alternatives exist.

2. **RAM.** Proving peak is driven by `k` (the witness grid + KZG commitment
   matrices are allocated over the full `2^k` domain regardless of rows used).
   The circuit is at k=23 (8.03M rows); real-KZG peaks ≳26–28 GiB, which a
   32 GiB machine cannot hold. Reaching k=22 (4.19M-row domain) roughly
   **halves** the RAM (→ ~14 GiB), which would fit a 26 GiB WSL2 box. That
   requires a ~48% row cut, and secp256k1 — the dominant gadget, using a naive
   256-step double-and-add with **no GLV** — is where the rows are.

## 2. Current state

`scalar_mul` (`circuits/src/secp256k1.rs:2135`) is a naive 255-iteration
double-and-add (`point_double` + `point_add_mixed` + `conditional_select_point`
per bit). The `point_add_mixed` optimization (16→11 `field_mul`/step) is what
brought k 24→23. **GLV was designed (`docs/glv-secp256k1-design.md`) but never
implemented** — that doc itself says *"DESIGN SKETCH, not implemented."*

The file tangles two concerns that must be separated before any swap:

| Concern | Methods | Fate |
|---|---|---|
| **(a) EC engine** — the row hog / audit risk | `scalar_mul`, `field_mul`, `field_add_carried`, `field_sub`, `point_*`, `carry_chain_columns`, `reduce_canonical_mod_p`, `check_on_curve`, `constrain_affine`, `check_limb_ranges` | **Replaced** by halo2wrong |
| **(b) ZKMist binding glue** — *not* EC-specific | `accumulate_weighted_bits` (4 call sites), `assert_nonzero`, `assign_field_constant`, `fixed_const` | **Retained** (extracted to `gadgets/`) |
| **(c) Native helpers** — witness gen, used by CLI/tests | `NativePoint`, `NativeSecpField`, `native_derive_address`, `decompose_key_to_bits`, `SECP_P/N`, `G_X/Y` | **Retained** |

## 3. Target: halo2wrong

PSE's own `halo2wrong` (`integer` + `ecc` + `secp256k1` modules): audited,
GLV-accelerated, fixed-base lookup tables. Same ecosystem as the PSE halo2
fork this project already uses → least version friction.

Alternatives if version alignment fails (see §6 risk 1): `scroll-tech/halo2-secp256k1`
(most efficient, heavier integration).

## 4. Method mapping

| Current | halo2wrong equivalent | Notes |
|---|---|---|
| `Secp256k1Config::configure` | `EccChip::<Fq, Secp256k1Affine>::construct` | New gate/table layout → regenerates VK + `Halo2Verifier.sol` |
| `scalar_mul(bits, G)` (256-step) | `ecc.mul_fixed(&generator, &scalar_fe)` | **GLV + fixed-base lookups** — the row/RAM win |
| `assign_affine_constant(G)` | `ecc.load_fixed_point(generator)` | |
| `constrain_affine(P, x, y)` | `assert_equal(P, assigned_pubkey)` | halo2wrong points are on-curve by construction → `check_on_curve` + `check_limb_ranges` become unnecessary |
| `assign_scalar_bits(256 bools)` | `field_chip.assign_fe(scalar)` | scalar as non-native `Fe<Fq>`, **not** 256 bits |

## 5. The soundness-critical re-derivation (the hard part)

The three-pillar binding currently works by **sharing 256 boolean bit cells**
between `scalar_mul` and the nullifier/address accumulators. halo2wrong takes
the scalar as a non-native `Fe<Fq>`, not as bits — so the binding must be
re-derived:

```
Current:  scalar_bits ─┬─► scalar_mul ──► pubkey ──► Keccak ──► address ──► leaf
                       └─► accumulate ──► key_cell ──► nullifier

New:      scalar Fe<Fq> ─┬─► ecc.mul_fixed(G) ──► pubkey ──► Keccak ──► address ──► leaf
                        │                        (constrain pubkey.x/y Fe<Fp> bytes == Keccak input)
                        └─► field_chip.to_native ──► constrain_equal ──► nullifier key (Fr)
```

Two new soundness-critical constraints appear:

1. **Nullifier binding** — the `Fe<Fq>` scalar fed to `mul_fixed` must equal
   the `Fr` key fed to Poseidon. halo2wrong's `FieldChip` exposes the native
   value for an equality proof `Fq == Fr-as-Fq`.
2. **Address binding** — the pubkey's `Fe<Fp>` x/y must equal the 64 bytes fed
   into Keccak (re-point the existing `bind_limb_to_inputs` logic at halo2wrong's
   limb cells).

These are *cleaner* than the current 256-bit accumulation (element equality vs.
a 256-term weighted sum), but they are **new code that itself needs audit**.
The non-native arithmetic becomes audited (halo2wrong); the *integration
wiring* does not.

## 5a. Concrete re-derivation (API-confirmed, 2026-07-03)

Phase B step 1 confirmed the halo2wrong API. The two bindings re-derive as
follows — each must land as its own MockProver-verified increment.

### Nullifier ↔ scalar (replaces Finding 2)

Today the 256 boolean scalar bit-cells are shared between `scalar_mul` and the
nullifier accumulator. halo2wrong's `mul` takes the scalar as a non-native
`Fe<Fq>`, so the binding is re-derived via its **native representation**:

```
key K (32 bytes, K < n enforced — see TRAP below)
  ├─ assign_integer(K as Fe<Fq>)  ─► assigned_scalar         ─► mul(G, ·) ─► pubkey
  │                                  └─ assigned_scalar.native()  (Fr cell, halo2wrong
  │                                       constrains it = Σ limbs[i]·2^(68·i) mod p_BN254)
  └─ constrain_equal(assigned_scalar.native(), key_cell_fr)   ◄── THE NEW BINDING
        where key_cell_fr = K mod p_BN254, fed to poseidon(·, domain) = nullifier
```

API: `AssignedInteger::native() -> &AssignedValue<N>` (integer/src/lib.rs:167)
and `AssignedInteger::limbs() -> &[AssignedLimb<N>; N]` (lib.rs:162). Bind the
two native Fr cells with halo2wrong's `MainGate` equality (or expose both to
the instance for MockProver during development).

> **The K vs K mod n divergence — handled for free by `native()==key_cell`.**
> `mul` reduces the scalar mod the secp256k1 order `n`; the nullifier uses the
> *raw* key `K`. The binding `constrain_equal(scalar.native(), key_cell)` is
> satisfiable ONLY when `(K mod n) mod p_BN254 == K mod p_BN254`. That requires
> `floor(K/n)·n ≡ 0 (mod p_BN254)`; with `gcd(n, p_BN254)=1`, `K < 2^256 < 2n`
> (so `floor(K/n) ∈ {0,1}`), and `n ≢ 0 (mod p_BN254)`, **no `K ≥ n` satisfies
> the constraint** — including the `K+n` alias (which would otherwise allow two
> claims for one address with nullifiers `poseidon(K)` and `poseidon(K+n)`).
> So the equality binding soundly enforces `K < n` and **no separate
> `scalar < n` range proof is needed** (an earlier draft of this spec called
> for one; the argument above shows it is redundant). Verified analytically
> 2026-07-03.

### Leaf ↔ Keccak address (replaces Finding 3)

`mul` returns an `AssignedPoint` whose x/y are `AssignedInteger<Fp>` (the
secp256k1 *base* field). The 64 Keccak input bytes are re-bound from those
limbs:

```
for coord in [pubkey.x(), pubkey.y()]:           // AssignedInteger<Fp>
    limbs = coord.limbs()                          // 4 Fr cells, each < 2^68
    bind_limb_to_inputs(keccak_input_bytes, start_byte, limbs[i])  // re-pointed
```

`bind_limb_to_inputs` (lib.rs) already accumulates byte-bits weighted into a
limb cell; it currently consumes the hand-rolled `AssignedFieldElement.limbs`,
and is re-pointed at halo2wrong's `AssignedLimb` native cells unchanged. Each
halo2wrong limb is range-checked `[0, 2^68)` by its `IntegerChip`, so the
binding stays sound.

### What drops entirely

`check_on_curve`, `check_limb_ranges`, and `constrain_affine` become
unnecessary — halo2wrong points are on-curve by construction, and
`ecc_chip.assert_equal(result, assigned_pubkey)` replaces the k·G == pubkey
check. (`assign_affine_constant` for G/P255 is replaced by halo2wrong
fixed-point assignment.)

### Implementation order (each step MockProver-verified before the next)

1. Add `GeneralEccChip` config alongside the existing `Secp256k1Config` in
   `ZKMistV2ClaimConfig`; load aux; swap `scalar_mul` → `mul` + `assert_equal`.
   Run the E2E MockProver — expect the nullifier/address bindings to FAIL
   (they still point at hand-rolled cells).
2. Re-point Finding 3 (address) at halo2wrong's `AssignedInteger<Fp>` limbs.
   Re-run; E2E should pass, negatives should reject.
3. Re-derive Finding 2 (nullifier) via `constrain_equal(scalar.native(),
   key_cell)` — which soundly enforces `K < n` by itself (see the trap note in
   §5a; no separate range proof needed). Re-run all Phase 0; add a negative
   test `test_key_above_n` confirming `K ≥ n` is rejected (the equality
   constraint rejects it).
4. `test_measure_circuit_rows` → learn k. Regenerate VK + `Halo2Verifier.sol`
   via `gen-production-verifier` **on a ≥36 GiB box** (keygen OOMs here).

The digest moves at step 1 and the committed `Halo2VerifyingKey.sol` is
invalid until step 4 — so steps 1–4 land as one reviewed sequence, not piecemeal
on `master`.

## 6. k=22 feasibility (the RAM prize)

halo2wrong's GLV + fixed-base lookups make secp256k1 dramatically smaller —
production secp256k1-verify circuits (Scroll, Axiom) land at ~0.3–1M rows with
lookups vs. ~5M+ for this naive double-and-add. If secp256k1 drops ~5M → ~0.7M,
total goes 8.0M → ~3.5M → **fits k=22 (4.19M)** → real-KZG RAM ~14 GiB.

⚠️ **Not guaranteed.** Depends on (i) halo2wrong's lookup mode engaging,
(ii) Keccak/Poseidon not becoming the new floor, (iii) Fq↔Fr conversion
overhead. Measure with `test_measure_circuit_rows` after integration.

## 7. Phased plan

| Phase | Work | Effort | Risk |
|---|---|---|---|
| **A. Dep + extraction** | Add halo2wrong to `circuits/Cargo.toml`; extract concern (b) to `circuits/src/gadgets/field_accumulator.rs` | 1–2 days | 🔴 halo2wrong vs PSE-halo2-v0.3.0 **version alignment** (see spike below) |
| **B. Chip swap** | Re-implement `Secp256k1Chip` over halo2wrong; re-derive the two bindings (§5) | 3–5 days | 🟠 the binding re-derivation is soundness-critical |
| **C. Measure + regenerate** | `test_measure_circuit_rows` → if <4.19M set `CIRCUIT_K=22`; regen VK + `Halo2Verifier.sol` via `gen-production-verifier` | 1 day | 🟡 k=22 not guaranteed |
| **D. Test + audit prep** | New soundness tests for the integration; re-run Phase 0; audit-scope doc | ongoing | new surface |

**Progress (2026-07-03):**
- ✅ Phase A done (commit `c095fe9`): halo2wrong dep + binding glue extracted.
- ✅ Phase B step 1 done: deps extended to `ecc`/`integer`/`maingate` (the umbrella
  `halo2wrong` crate alone *cannot* do EC arithmetic); the integration test
  `circuits/tests/halo2wrong_integration.rs` verifies halo2wrong's audited
  `GeneralEccChip` computes `scalar · G` on secp256k1 correctly (MockProver PASS).
  The real API is confirmed: `GeneralEccChip::<Secp256k1Affine, Fr, 4, 68>`, then
  `assign_aux_generator` + `assign_aux(ctx, window=4, number_of_pairs=1)` +
  `mul(ctx, &base, &scalar, window=4)` + `assert_equal`. The main circuit digest
  is unchanged (`b8022d1afb857964`) — this step touches no production circuit.
- ⬜ Phase B remainder: rewire `ZKMistV2Claim` to use the chip (changes the
  digest → regen VK) + re-derive the nullifier/address bindings (soundness-critical).

**Total: ~1–2 weeks focused engineering, then audit.**

## 8. Phase A dependency spike — result (2026-07-03)

**✅ PASS — version alignment risk cleared.** `halo2wrong v2024_01_31` pins the
*identical* PSE halo2 fork this project uses:

```toml
# halo2wrong/halo2wrong/Cargo.toml @ v2024_01_31
halo2 = { package = "halo2_proofs",
         git = "https://github.com/privacy-scaling-explorations/halo2", tag = "v0.3.0" }
# ...same git URL + tag as this project's workspace [dependencies].
```

Live verification: added `halo2wrong = { git = "...", tag = "v2024_01_31" }` to
`circuits/Cargo.toml`, ran `cargo fetch`, and `cargo tree -i halo2_proofs`
shows a **single unified `halo2_proofs v0.3.0`** (commit `73408a14`) serving
both `halo2_solidity_verifier` and `halo2wrong` — every entry carries the `(*)`
"already unified" marker; no second halo2_proofs version. (`cargo tree -d` shows
harmless coexisting versions of utility crates like `sha3`/`itertools`/
`num-integer`; none affect the prover or verifier.) The probe was then reverted
— no code change committed.

**Implication:** Phase A is viable as-written — no halo2wrong fork required.
This removes the highest-severity risk listed in §9.

## 9. Risks

1. ~~**Version alignment (highest).**~~ **CLEARED (2026-07-03 spike, §8):**
   halo2wrong `v2024_01_31` pins the same PSE halo2 `v0.3.0` fork; cargo unifies
   to one `halo2_proofs`. Pin halo2wrong to `v2024_01_31` (or a newer tag that
   keeps the same halo2 pin) when adding it in Phase A.
2. **Lookup support.** halo2wrong's efficiency relies on lookup arguments; the
   circuit's `configure()` must enable them (PSE halo2 supports lookups, but
   the gate/table layout changes the VK).
3. **Binding re-derivation.** The Fq→Fr conversion (nullifier) and Fp→bytes
   (Keccak) are new soundness-critical code — constrain + test carefully.
4. **k=22 not guaranteed.** Must measure; if it lands at k=23 you still get
   the audit win but not the RAM win.

## 10. Sequencing recommendation

- **Do NOT block the real-KZG fixture (blocker #2) on this.** It's 1–2 weeks.
  Generate the fixture on a ≥36 GiB cloud instance (~$0.50, 30 min) to clear
  blocker #2 now.
- Run this migration in parallel as the proper production track. The preflight
  recalibration (`40e439b`) means any box that can't hold it now fails loudly
  with guidance rather than silently crashing.
