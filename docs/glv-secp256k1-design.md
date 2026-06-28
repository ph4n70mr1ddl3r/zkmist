# GLV acceleration for the secp256k1 gadget — design sketch

> **Outcome (2026):** ✅ **IMPLEMENTED & SHIPPED.** The `point_add_mixed`
> optimization (Tier 1 of this sketch) halved the secp256k1 witness and dropped
> the full circuit from `k=24` (which OOM-killed 32 GiB hosts at ~30 GiB RSS)
> back to **`k=23`** (~15 GiB RSS → fits comfortably). The E2E MockProver and
> all four negative tests now pass at k=23. The GLV endomorphism shortcut
> (Tier 2/3) was NOT needed; Tier 1 alone closed the gap. The text below is
> preserved as the original design sketch.

> **Status:** DESIGN SKETCH, not implemented. The goal is to drop the full
> circuit from `k=24` (2²⁴ ≈ 16.7 M rows, ~30 GiB RSS → OOM-kills a 32 GiB host)
> to `k=23` (2²³ ≈ 8.4 M rows, ~15 GiB RSS → fits comfortably). The row budget
> is dominated by `Secp256k1Chip::scalar_mul`
> (`circuits/src/secp256k1.rs`), which is the only reason the circuit cannot fit
> at `k=23` today. This document sketches the Gallant–Lambert–Vanstone (GLV)
> endomorphism shortcut for that gadget.
>
> **Not a soundness change to the core.** GLV reorganizes *which* point
> operations are performed; it does not alter the non-native field arithmetic,
> carry chains, or canonical reductions (`field_mul`, `reduce_canonical_mod_p`,
> `carry_chain_columns`) that make the existing gadget sound. Those are reused
> verbatim. The only new soundness claim is the decomposition relation
> `k ≡ k1 + k2·λ (mod n)`, which must be proven in-circuit (§4).

---

## 0. TL;DR

- secp256k1 has an efficiently-computable endomorphism φ with `φ(P) = λ·P` for a
  fixed scalar λ, computable as `φ(x, y) = (β·x mod p, y)` — a single field mul
  by a constant. This lets us split any scalar `k` into two ~128-bit signed
  halves `k1, k2` with `k ≡ k1 + k2·λ (mod n)`, so `k·G = k1·G + k2·βG`.
- **Tier 1 — GLV + Shamir 2-scalar (no lookups):** shares one doubling chain of
  length ~128 across both halves instead of one chain of length ~255. Roughly a
  **~19% row reduction** over the current (post-mixed-add) `scalar_mul`.
  *Borderline for k=23 on its own* — depends on how far over 2²³ the gadget
  currently sits (measure first).
- **Tier 2 — GLV + fixed-base lookup tables:** replaces the per-step point adds
  with halo2 lookups into precomputed tables of `G` and `βG` multiples. ~10×
  reduction; **the definitive path to k=23 and below**, at the cost of real
  engineering (lookup tables, windowed scheduling).
- **Recommendation:** measure the exact current row count (cheap
  `SimpleFloorPlanner` measurement test, no 2²⁴ grid), then if Tier 1 alone
  clears 2²³, ship Tier 1; otherwise go to Tier 2. Either way, GLV is the right
  structural lever (vs. swap, which is a band-aid).

---

## 1. Why the gadget is the bottleneck

`scalar_mul` (msb-first double-and-add over 255 bits + MSB correction) calls,
per bit: `point_double` (≈7 `field_mul`) **and** `point_add_mixed` (≈11
`field_mul` after the mixed-add optimization already landed). Halo2's
`SimpleFloorPlanner` cannot have variable-length regions, so the add is computed
**unconditionally every step** and the bit only selects between the doubled and
added results (`conditional_select_point`). Consequently:

```
current scalar_mul ≈ 255·(7 + 11) + 11 (correction) ≈ 4 601 field_mul
                  + check_on_curve + constrain_affine + periodic range checks
```

Each `field_mul` is expensive (~schoolbook 16 + wide accumulation + carry chain
+ `reduce_canonical_mod_p` with a witnessed quotient and a `< p` proof + ~15
range checks), so the gadget lands between 2²³ and 2²⁴ rows — too big for k=23,
barely fits k=24. Two structural facts drive this cost:

1. **256 doublings** — one per scalar bit. GLV halves this.
2. **One add per step**, paid every step regardless of the bit. GLV with fixed
   tables turns these into cheap lookups.

---

## 2. The secp256k1 endomorphism

secp256k1 has CM discriminant −3, so it admits an order-3 automorphism. With the
curve over `F_p`, `p = 2²⁵⁶ − 2³² − 977`:

- **β** — a non-trivial cube root of unity mod `p` (root of `x² + x + 1 ≡ 0 (mod p)`):
  ```
  β = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
  ```
- **λ** — the corresponding eigenvalue mod `n` (group order), root of
  `x² + x + 1 ≡ 0 (mod n)`:
  ```
  λ = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
  ```

The endomorphism `φ : E → E` is
```
φ(x, y) = (β · x mod p, y)
```
and it is an efficiently-computable group endomorphism satisfying
`φ(P) = λ · P` for every `P ∈ E`. In particular `φ(G) = λ·G =: G'`, and `G'` is
a fixed point whose affine coordinates we precompute once (it equals `(β·Gx mod p, Gy)`).

> These two constants are universally cited (see e.g. libsecp256k1, the original
> GLV paper). They are *not* secret and can be cross-checked by verifying
> `β² + β + 1 ≡ 0 (mod p)`, `λ² + λ + 1 ≡ 0 (mod n)`, and `(β·Gx mod p, Gy) =
> λ·G` natively.

---

## 3. Scalar decomposition: `k ≡ k1 + k2·λ (mod n)`

Given `k ∈ [0, n)`, find signed `k1, k2` with `|k1|, |k2| ≤ ~2¹²⁸` and
`k ≡ k1 + k2·λ (mod n)`. Then:

```
k·G = (k1 + k2·λ)·G = k1·G + k2·(λ·G) = k1·G + k2·G'
```

Two half-width scalar multiplications instead of one full-width one.

### 3.1 Algorithm (lattice / Babai rounding)

Decomposition is performed over the **integers** (out-of-circuit, to produce the
witness) using a reduced basis `{v1, v2}` of the lattice
`{(a, b) : a + b·λ ≡ 0 (mod n)}`. The standard reduced basis for secp256k1 is
(the values below match libsecp256k1; **re-verify against that reference before
implementing** — a wrong constant silently breaks soundness):

```
v1 = ( a1,  b1)   a1 = 0x3086d221a7d46bcde86c90e49284eb15
                    b1 = 0xe4437ed6010e88286f547fa90abfe4c3   (used as −b1 below)
v2 = ( a2,  b2)   a2 = 0x114ca50f7a8e2f3f657c1108d9d44cfd8
                    b2 = 0x3086d221a7d46bcde86c90e49284eb15
```

Given `k`, compute (all integer arithmetic):
```
c1 = round( k · b2  / 2¹²⁸ )
c2 = round( k · (−b1) / 2¹²⁸ )     // note the sign
k1 = k − c1·a1 − c2·a2
k2 =      − c1·b1 − c2·b2
```
Then `k1, k2 ∈ [−2¹²⁸, 2¹²⁸]` (roughly ±1.15·2¹²⁸) and
`k ≡ k1 + k2·λ (mod n)` exactly. (The rounding constants come from
`2¹²⁸ ≈ √n`, which is the lattice determinant scale.)

The out-of-circuit side is a few big-integer multiplies — trivial. The
in-circuit side only needs to **prove the relation** (§4), not perform the
reduction.

### 3.2 Signed halves

`k1, k2` can be negative. Handle signs by negating the *base point*:
`k2·G' = (−k2)·(−G')` where `−G' = (G'x, p − G'y)`. So witness `k1, k2` as
non-negative magnitudes plus two sign bits, and precompute four affine bases:
`{±G, ±G'}`. The sign bit picks which via `conditional_select_point` (already
implemented). This keeps every per-step add a **mixed** add (affine second
operand), preserving the 11-`field_mul` cost from the mixed-add optimization.

---

## 4. In-circuit constraint: prove `k ≡ k1 + k2·λ (mod n)`

This is the **only new soundness claim** GLV introduces, and it must be proven
under the existing non-native framework (BN254 `Fr` cells, carry chains,
witnessed quotients). Everything else reuses `field_mul` / `point_double` /
`point_add_mixed` unchanged.

### 4.1 What is already constrained today

Finding 2 (`lib.rs` nullifier-key binding) already accumulates the **256 scalar
bits** into the BN254 field element `k mod p_BN254` via
`accumulate_weighted_bits` and constrains it equal to the cell fed to the
nullifier Poseidon hash. So the circuit already holds a canonical cell `Kcell`
with value `k mod p_BN254`. GLV must additionally prove that the `(k1, k2)`
**used by the two half-multiplications** satisfy `k1 + k2·λ ≡ k (mod n)`.

### 4.2 The constraint

Witness `k1, k2` (as ≤ 129-bit non-negative magnitudes, plus the two sign bits
handled at the point level). Prove, over the integers with a witnessed
quotient `q`:

```
k1 + k2·λ  =  k  +  q · n
```

as a **BN254 identity** (all operands are well below `p_BN254` after splitting
into limbs, so BN254 field arithmetic coincides with integer arithmetic and the
identity is exact). Concretely:

1. Compute `t = k1 + k2·λ` as a wide multi-limb integer (schoolbook: `k2` is
   ~129-bit → 3 limbs of 64-bit; `λ` is 256-bit → 4 limbs; product is ~7 limbs;
   add `k1`'s 3 limbs → ~7 limbs). This is a small schoolbook `s_mul_fixed`
   block (the `λ` limbs are fixed-column constants, exactly like `SECP_P` is
   today in `reduce_canonical_mod_p`'s `q·p` block) plus a carry chain.
2. Witness `q` (a few limbs; bound: `|t − k| ≤ |k1| + |k2|·λ < ~2¹²⁸ + 2¹²⁸·n
   ≈ 2¹²⁸·n`, so `q` fits in ~129 bits → 3 limbs) and compute `k + q·n` the same
   way (fixed `n` limbs).
3. Constrain `t = k + q·n` limb-by-limb with a carry chain and a zero top carry,
   reusing `carry_chain_columns` verbatim.
4. Range-check `k1`, `k2`, and `q` limbs to `[0, 2⁶⁴)` with the existing
   `check_single_limb`, and range-check the sign bits boolean.

**Cost:** ~3 fixed-schoolbook blocks (~3–4 `s_mul_fixed` rows each) + 2–3 carry
chains + a handful of range checks. Order of ~10–20 `field_mul`-equivalents,
executed **once** — negligible next to the ~3700 from the mul itself.

> This is exactly the same shape as the existing, already-audited
> `reduce_canonical_mod_p` (witness quotient, multiply by fixed modulus, carry
> chain, range checks). No new cryptographic technique is introduced.

### 4.3 Preserving the Finding-2 nullifier binding

The nullifier is sound today because the 256 bits feeding `scalar_mul` are the
*same* cells accumulated into the nullifier key. With GLV, `scalar_mul` consumes
`(k1, k2)`, not the bits directly. The chain remains sound as long as:

```
bits  →  Kcell (accumulate_weighted_bits, unchanged)
Kcell ≡ k1 + k2·λ (mod n)   (§4.2 — the new constraint)
k1, k2 drive the two half-multiplications
```

So the nullifier key is still cryptographically bound to the scalar actually
multiplied. The binding test `test_binding_weight_math` should be extended with
the `k1 + k2·λ ≡ k (mod n)` check.

---

## 5. The two-scalar multiplication (Shamir's trick)

Process `k1` and `k2` MSB-first in a **single shared doubling chain** of ~128
steps. Per step (all operands affine → mixed adds):

```
acc_d  = point_double(acc)
acc_g  = point_add_mixed(acc_d,  s1 · G)     // s1 = sign-magnitude bit of k1 at this position
acc_gg = point_add_mixed(acc_g,  s2 · G')    // s2 = sign-magnitude bit of k2 at this position
acc    = acc_gg
```

with the sign bits selecting among `{±G}`, `{±G'}` (or the identity when the bit
is 0, realized via `conditional_select_point` against `acc_d` / `acc_g`). A
MSB-correction step analogous to the existing one cancels the implicit top bit
(see `scalar_mul`'s MSB-correction comment — same idea, now applied to two
half-scalars).

Because every second operand is affine, **all adds are `point_add_mixed`** (11
`field_mul`), and `point_double` (7) is unchanged.

### 5.1 Tier 1 cost (no lookups)

```
~128 steps × (1 double + 2 mixed adds) = 128 · (7 + 11 + 11) ≈ 3 712 field_mul
+ §4 decomposition proof                         ≈    15 field_mul
+ MSB correction (≤ 2 mixed adds)                ≈    22 field_mul
+ check_on_curve + constrain_affine              ≈    10 field_mul
                                                ≈ 3 759 field_mul
```

vs current (post-mixed-add) ≈ 4 601. **~18% fewer `field_mul` → ~18% fewer
rows.** Whether that clears 2²³ depends on the exact current count:

| If secp256k1 is at | Tier 1 brings it to | Fits k=23 (2²³)? |
|---|---|---|
| 9.0 M rows | ~7.4 M | ✅ yes |
| 10.0 M rows | ~8.2 M | ❌ marginal (just over) |
| 12.0 M rows | ~9.8 M | ❌ no |

→ **Measure first** (§7). Tier 1 is cheap to implement and is the right first
move regardless; if it doesn't quite clear 2²³, Tier 2 will.

### 5.2 Tier 2 cost (fixed-base lookup tables)

The two adds per step are the remaining cost. Since both bases are **fixed and
public** (`G`, `G'`, and their sign-negations), precompute windowed tables and
replace each add with a halo2 lookup. With window `w`:

- Precompute, in fixed columns, tables of `j·G` and `j·G'` for `j ∈ [0, 2ʷ)` in
  affine coordinates (and their `−`-negations, or store full Jacobian and negate
  via a conditional Y-flip). Each table entry is 2 field elements (affine).
- Per step: `1 point_double` + `2 lookups` (one into each table) + `2 mixed
  adds` from the looked-up affine points. With `w = 4`: 128/4 = **32 steps**.

```
~32 steps × (7 (double) + 2 × 11 (mixed adds)) ≈ 928 field_mul
+ lookup table load (fixed columns: ~2·2ʷ entries, one-time) 
+ §4 decomposition proof                      ≈   15 field_mul
                                             ≈  943 field_mul
```

vs current ~4 601 → **~5× fewer `field_mul`**, comfortably below 2²³ and likely
fitting k=22 or lower. Lookups themselves are cheap (the range-check /
`TableColumn` machinery is already used by Keccak and `range_check`).

The engineering cost is real: designing the windowing schedule, building the
fixed-column tables, handling the sign bits through the table indexing, and
re-deriving `EXPECTED_CS_DIGEST` + regenerating `Halo2VerifyingKey.sol`.

---

## 6. What does NOT change

- **Soundness core:** `field_mul`, `field_add_carried`, `field_sub`,
  `carry_chain_columns`, `reduce_canonical_mod_p`, `check_on_curve`,
  `constrain_affine`, `check_limb_ranges` — all reused unchanged.
- **`point_double` / `point_add_mixed`** — reused unchanged (Tier 1) or with
  looked-up affine operands (Tier 2).
- **Finding-1 (Keccak↔address) and Finding-3 (scalar-mul↔Keccak-input)
  bindings** — unaffected; they operate on the public key / address, not on the
  scalar decomposition.
- **`test_secp256k1_mock_prover`** stays the validation gate (still `#[ignore]`,
  still k=24 until the re-measure confirms 2²³ fits, at which point drop its `k`
  and un-ignore alongside the E2E test).

## 7. Validation plan (in order, all cheap until the last)

1. **Measure the exact current secp256k1 row count** with a
   `SimpleFloorPlanner`-measurement-only test (synthesize into `RegionShape`s —
   records max rows-per-region **without** allocating the 2²⁴ grid; runs in
   seconds, no memory risk). This tells us whether Tier 1 alone clears 2²³
   (§5.1 table).
2. **Implement the native decomposition** (§3.1) as a Rust function returning
   `(k1, k2, q)` and unit-test it against `k ≡ k1 + k2·λ (mod n)` for the PRD
   test key and many random keys. Cheap, pure native.
3. **Implement §4.2 as an isolated chip method** + a `MockProver` test at small
   `k` (like `test_accumulate_weighted_bits_primitive`, k≈12) proving the
   constraint is satisfiable for an honest witness and rejects a wrong `(k1,k2)`.
4. **Implement Tier 1 `scalar_mul_glv`**; gate the full `scalar_mul` behind a
   feature/const so the old path is one revert away. Re-run the native
   equivalence approach (`test_jacobian_*`-style) comparing GLV vs the current
   path over the full trajectory for the PRD key.
5. **Re-measure rows** (step 1's harness). If ≤ 2²³, flip `CIRCUIT_K` to 23,
   regenerate the VK (`gen-production-verifier --k 23`), recompute
   `EXPECTED_CS_DIGEST`, and run `test_secp256k1_mock_prover` /
   `test_circuit_merkle_nullifier_e2e` once each (now affordable at k=23).
6. If step 5 shows we are still over 2²³, proceed to **Tier 2** (lookups).

---

## 8. Risks

- **Decomposition constants.** A wrong `(a1,b1,a2,b2)` or `λ`/`β` silently breaks
  correctness (the mul computes the wrong point → `constrain_affine` fails, so
  it fails *safe*, but no honest proof is possible). Mitigation: pin every
  constant with a native test asserting `β²+β+1≡0 (mod p)`, `λ²+λ+1≡0 (mod n)`,
  and `φ(G)=λ·G`; cross-check the basis against libsecp256k1.
- **Sign handling.** Mishandling a negative `k1`/`k2` produces the wrong point
  (again fails *safe* at `constrain_affine`). Mitigation: the
  full-trajectory native equivalence test (step 4).
- **Soundness of the decomposition proof (§4.2).** Same shape as the existing
  audited `reduce_canonical_mod_p`; reuse its witnessed-quotient + carry-chain +
  canonical-range pattern verbatim. The quotient bound `q < ~2¹²⁹` must be
  range-checked.
- **VK / digest churn.** Any `configure()`-level change moves
  `EXPECTED_CS_DIGEST` and requires regenerating `Halo2VerifyingKey.sol`. This
  is expected and already tooled (`gen-production-verifier`).
- **No regression in the k=24 fallback.** Keep the old `scalar_mul` reachable
  until Tier 1/2 is validated end-to-end, so a GLV bug never blocks the known-
  good (if heavy) k=24 path.

## 9. Recommendation

GLV is the correct structural fix (vs. relying on swap). Concretely:

1. Land the **measurement harness** (§7.1) first — it removes all guesswork and
   is zero-risk.
2. Land **Tier 1** (GLV + Shamir, no lookups). It is a contained change that
   reuses only existing primitives, is fully testable at small `k`, and delivers
   ~18%. If the measurement says that clears 2²³ — done.
3. If not, escalate to **Tier 2** (fixed-base lookups), which clears 2²³ with
   large margin and likely unlocks k=22.

Mixed-add (already implemented) and GLV are **independent and stack**: mixed-add
makes every per-step add 11 instead of 16 `field_mul`, and GLV halves the
doubling chain — together they are the realistic path to k=23 on this hardware.
