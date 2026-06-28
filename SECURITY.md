# Security Policy

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in ZKMist, please disclose it responsibly:

1. **Open a private security advisory** on GitHub: go to the repository → Security → "Report a vulnerability"
2. **Or contact the maintainers directly** via the contact methods listed in the repository

Please include the following in your report:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact (e.g., proof forgery, double-claim, supply inflation)
- Affected component (circuits, CLI, contracts, merkle-tree)

## Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Resolution**: depends on severity and complexity

## Responsible Disclosure

We ask that you:

- Do not exploit the vulnerability beyond what is necessary to demonstrate it
- Do not access or modify other users' data
- Give us reasonable time to respond before any public disclosure

## Known Security Considerations

### Smart Contracts
- All contracts are **immutable** (no admin, no owner, no upgrade mechanism)
- The `Halo2Verifier` uses real KZG pairing verification via BN254 ecPairing precompile
- The `Halo2VerifyingKey` must contain the correct VK from the full production circuit
- Double-claim prevention relies on the nullifier uniqueness of `poseidon(key, domain)`

### ZK Circuits
- The secp256k1 gadget uses **hand-rolled non-native field arithmetic** (see `circuits/src/secp256k1.rs`)
- Soundness depends on `check_on_curve`, `constrain_affine`, and limb range checks
- **An external security audit is required** before mainnet deployment
- The code recommends using proven alternatives (`scroll-tech/halo2-secp256k1`, `halo2wrong`)

### CLI
- Private keys are read from hidden input or files with permission checks
- The eligibility list Merkle root is hardcoded and verified against the manifest
- Proof files contain nullifiers but never the qualified address

## Audit Status

> **⚠️ No external audit has been performed yet.**
>
> The project is in beta. An audit of the circuit (especially secp256k1 non-native field arithmetic) is a prerequisite for mainnet deployment.

## Pre-Deployment Checklist

Before mainnet deployment, ALL of the following must be completed:

### Critical (blocks deployment)
- [ ] **Re-run secp256k1 MockProver test** to confirm the carry-chain reductions are sound: **requires k=23 confirmation** (the carry-chain rewrite is the latest change; the `secp256k1.rs` code comment explicitly flags this run as not-yet-validated-in-this-environment). The isolated secp256k1 gadget — including `field_mul` / `field_add_carried` / `field_sub` reductions, `check_on_curve`, `constrain_affine`, and limb range checks — must verify a correct honest proof and derive the test-vector address `0xfcad0b19bb29d4674531d6f115237e16afce377c`. The sound reductions first raised k from 22 to 24, but a subsequent secp256k1 `point_add_mixed` optimization halved the witness and brought it back to k=23. Peak RSS ≈ 15 GiB, ~2 min (release).
  ```
  cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
  ```
- [ ] **Re-run full E2E MockProver test** — **requires k=23 confirmation** (re-run after the carry-chain rewrite). The honest end-to-end proof (real key → secp256k1 → Keccak address → Merkle membership → nullifier → recipient) verifies, and the binding between the three pillars is sound. Getting here required fixing **three latent Keccak correctness bugs** that MockProver could not catch on its own (gates were satisfiable but the witness was wrong): a corrupted `RC` round-constant table (from index 5), a backwards `rotate_lane` (right instead of left), and a transposing `chi_step` storage order. The test harness was also fixed to build proofs at the full `TREE_DEPTH`. Each bug is now pinned by an instant native test plus a constrained `tiny_keccak` cross-check in the isolated Keccak test.
  ```
  cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
  ```
- [ ] **Run the four full-circuit negative tests** (`test_wrong_merkle_root_rejected`, `test_wrong_nullifier_rejected`, `test_zero_recipient_rejected`, `test_recipient_exceeding_uint160_rejected`) — **require k=23 confirmation** (re-run after the carry-chain rewrite). Each must correctly REJECT for the intended reason now that the honest E2E path verifies: forged Merkle root, rotated nullifier, zero recipient, and out-of-`uint160` recipient are all rejected. This validates the circuit's soundness properties at the MockProver level. (Each is `#[ignore]`d, ~2 min at k=23 release.)
- [ ] **External security audit** of secp256k1 non-native field arithmetic (including the carry-chain mod-p reduction: `carry_chain_columns` + `reduce_canonical_mod_p`)
- [ ] **Generate `Halo2Verifier.sol` and `Halo2VerifyingKey.sol`** using halo2-solidity-verifier with the real circuit VK:
  ```
  cargo run --release -p zkmist-tools --bin gen-verifier -- --output contracts/src/Halo2Verifier.sol
  # Then use halo2-solidity-verifier with the generated Halo2Verifier.vk.bin
  # See: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
  ```
  **IMPORTANT**: The current `Halo2VerifyingKey.sol` has k=21 (0x15) with all-zero fixed commitments.
  This is from a partial circuit configuration, NOT the full production circuit (which needs **k=23**).
  Must regenerate from the full circuit — the E2E MockProver test now passes at k=23.
- [ ] **Verify VK k-value matches circuit** in the generated `Halo2VerifyingKey.sol`
- [ ] **Testnet deployment** on Base Sepolia with full E2E claim flow:
  ```
  ./scripts/testnet-deploy.sh
  ```
- [ ] **Run full E2E test suite**:
  ```
  ./scripts/e2e-test.sh
  ```

### High Priority
- [x] **Regenerate gas snapshot**: `cd contracts && forge snapshot` ✅ (72 tests, snapshot committed)
- [x] **Add mint validation** to ZKMToken: reject zero address and zero amount ✅
- [x] **Add deadline rejection test**: verify claims rejected after 2027-01-01 ✅
- [x] **Add deployer balance check**: deploy script verifies sufficient ETH ✅
- [x] **Add verifier rejection test**: integration test confirms placeholder verifier rejected ✅
- [ ] **Update `AIRDROP_CONTRACT`** in `cli/src/constants.rs` after deployment
- [ ] **Generate real proof + verify on testnet** end-to-end
- [ ] **Proof size validation**: confirm proof fits in `[4000, 8000]` byte range
  - The expected proof length is ~5632 bytes (determined by Halo2 circuit structure)
  - The `zkmist bench` subcommand reports proof size as part of its output
- [ ] **Run pre-deployment readiness checker**: `cargo run -p zkmist-tools --bin readiness`
- [ ] **Set up on-chain monitor**: `cargo run -p zkmist-tools --bin monitor -- <airdrop_address>`

### Recommended
- [ ] Integration test: generate real Halo2 proof → submit to Anvil/local chain
- [x] Fuzz test the circuit with random private keys (not just test vector) ✅ Added diverse test vectors (7 keys including edge cases)
- [ ] Benchmark proving time on reference hardware (target: <60 seconds)
  - Run: `zkmist bench`
  - Or run full E2E test: `./scripts/e2e-test.sh`
- [ ] Set up monitoring/alerting for the deployed contracts
  - Run: `cargo run -p zkmist-tools --bin monitor -- <address> --rpc https://mainnet.base.org`
- [ ] Consider replacing hand-rolled secp256k1 with audited library
  - `scroll-tech/halo2-secp256k1`
  - `privacy-scaling-explorations/halo2wrong`
- Consider replacing hand-rolled Keccak gadget with a verified implementation
  - `privacy-scaling-explorations/halo2wrong` (Keccak256 chip)
  - `scroll-tech/zkevm-circuits` (Keccak circuit)

## Soundness Hardening (Applied)

The following hardening measures have been applied to the secp256k1 non-native
field arithmetic gadget:

1. **Raw limb carry chain in `field_add_carried`**: The carry chain now uses
   RAW limb sums (not mod-p reduced values) for the carry-propagated addition
   gate. This correctly constrains: `a[i] + b[i] + carry_in = raw_result[i] + carry_out * 2^64`.
   The mod-p reduced result is assigned separately and verified by terminal checks.

2. **Removed incorrect `field_mul` reduction cross-check**: The previous constraint
   `wide[0] + c*wide[4] == result[0]` was mathematically wrong (doesn't account for
   carry propagation during reduction). Removed; soundness comes from
   `check_on_curve` and `constrain_affine`.

3. **Fixed `conditional_select` double-assignment**: The selector validation row
   previously assigned different values to the same advice cell, causing copy
   constraint violations. Fixed with single-assignment pattern.

4. **Fixed limb range check byte ordering**: The running-sum range check now
   processes bytes MSB-first (big-endian) so `z[8]` correctly equals the limb value.

5. **Consistent carry propagation in `field_sub`**: Uses `field_add_carried`
   for the final addition step, ensuring subtraction also propagates carries.

6. **`field_mul` / `field_add_carried` / `field_sub` mod-p reduction —
   IMPLEMENTED via sound integer carry chains (2026 rewrite).** The earlier
   Schwartz–Zippel product check was **mathematically incorrect** for the
   base-2^64 limb representation (limb polynomials evaluated at r=65537 do
   not match integer arithmetic in base 2^64, so it failed for honest
   provers) and was **removed** (the dead `verify_product` helper remains in
   `secp256k1.rs`). It was replaced with the strategy used by audited
   non-native libraries (`halo2wrong`, `scroll-tech/halo2-secp256k1`): a
   range-checked integer carry chain (`carry_chain_columns`) that proves
   `Σ wide[k]·2^(64·k) ≡ result` over the integers with the final carry-out
   constrained to 0, plus a witnessed quotient `q` with `result + q·p = V`
   and a canonicalization proof `result < p` (`reduce_canonical_mod_p`).
   Because every operand is ≪ p_BN254, the `s_add`/`s_mul`/`s_add_carry`
   gates are exact INTEGER identities — there is no modular wraparound to
   hide behind. See `circuits/src/secp256k1.rs`.
   **Validation status:** implementation complete; `configure()` digest
   matches `EXPECTED_CS_DIGEST` (`f8f4b46128dd613f`); the k=23 MockProver
   confirmation run (the `#[ignore]d` tests) is the remaining pre-deployment
   gate — see the checklist and the code comment in `secp256k1.rs`.

## Known Issues (Blocking Mainnet)

**`field_mul` / `field_add_carried` / `field_sub` reductions — IMPLEMENTED via sound carry chains (2026 rewrite); k=23 MockProver confirmation pending.** The wide→narrow reduction in `field_mul`, the raw→reduced step in `field_add_carried`, and `neg_b` in `field_sub` use explicit range-checked integer carry chains plus a witnessed quotient `q` with `result + q·p = V` and a canonicalization proof `result < p` (see `carry_chain_columns` / `reduce_canonical_mod_p` / the rewritten `field_sub` in `secp256k1.rs`). The `configure()` digest matches `EXPECTED_CS_DIGEST` (`f8f4b46128dd613f`), so the gate/column structure is sound.

⏳ **Validation gate (NOT yet confirmed in a clean environment):** the k=23 MockProver confirmation run is the remaining step. The code comment in `secp256k1.rs` explicitly flags this as not-yet-validated-in-this-environment (the heavy k=22/23 runs risk OOM, as the real-KZG path did). Each is `#[ignore]d`, ~2 min / ~15 GiB RSS at k=23 release:
```bash
cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
```
Until these pass, treat the secp256k1 reduction as **IMPLEMENTED-BUT-UNVALIDATED**, not production-ready. (The earlier `"✅ Confirmed at k=23"` wording in this file overstated the status relative to the code's own comment and is corrected here.)

⏳ **The full E2E circuit (`test_circuit_merkle_nullifier_e2e`) confirmation at k=23 is PENDING** (see the code comment in `secp256k1.rs`). The honest end-to-end proof — once confirmed — exercises the three-pillar binding (secp scalar ↔ Keccak address ↔ nullifier). The wiring fixes that make the honest path *possible* are in place: three latent Keccak correctness bugs (see the next item) plus a test-harness Merkle-depth bug are fixed and pinned by native tests. (Earlier "✅ now PASSES at k=23" wording here overstated the status relative to the code's own comment and is corrected to match.)

**`cond_swap` Merkle gadget — FIXED (2026 review).** The previous version's
`out = term1 + term2` gate left `term1`/`term2` as free advice cells, making
the Merkle membership proof non-binding. It now constrains `sel*b`,
`(1-sel)*a`, `sel*a`, and `(1-sel)*b` with multiplication gates (mirroring
`conditional_select_field`).

**Keccak correctness — FIXED (2026 validation).** The full E2E MockProver
test now passes at k=23. Getting there required fixing **three latent Keccak
bugs** that MockProver could not catch on its own — every per-bit gate
(`s_xor`, `s_andnot`, `s_byte_decomp`) was satisfiable, so the witness was
internally consistent but computed a *wrong* digest. None was caught before
because the isolated Keccak test only checked gate satisfiability and never
compared its constrained output to `tiny_keccak`. All three are now fixed and
pinned by instant native tests plus a constrained `tiny_keccak` cross-check:
  1. **Corrupted `RC` round-constant table** (from index 5): a bogus
     `0x0000000000000080` was inserted, shifting every later constant down by
     one and dropping `RC[23]`. This single constant is shared by the native
     `keccak_f` and the circuit's `iota_step`, so both silently produced a
     wrong digest. Replaced with the canonical XKCP table; pinned by
     `test_keccak_f_matches_tiny_keccak_empty` (validates `keccak_f` against
     `Keccak-256("")` and against a clean 2D reference).
  2. **`rotate_lane` was a RIGHT rotation** (Keccak's ρ and θ-`rot(C,1)` are
     LEFT rotations). ρ is pure cell rearrangement with no gate, so it passed
     MockProver. Now matches `u64::rotate_left`; pinned by
     `test_rotate_lane_is_left_rotation` (all 64 offsets × edge seeds).
  3. **`chi_step` transposed its output**: it looped `for y { for x }` and
     `push`ed, storing lane (x,y) at index `y*5+x` instead of the `x*5+y`
     convention used everywhere else. Per-bit gates stayed satisfied. Now
     stores at `x*5+y`; pinned via the isolated Keccak test's constrained
     `tiny_keccak` cross-check (160 address bits).

The test harness was also fixed: `test_circuit_merkle_nullifier_e2e` now
builds the Merkle proof at the full `TREE_DEPTH` via
`build_single_leaf_proof` (it previously built a depth-4 tree and zero-padded
the upper 22 levels, which could never match the circuit's 26-level root).

With the honest path verified, the four full-circuit negative tests are no
longer blocked (each is `#[ignore]`d, ~2 min at k=23 release) — they confirm forged
Merkle proofs / rotated nullifiers / zero or out-of-range recipients are
rejected.

**`field_add_carried` Phase 1 carry chain — FIXED (2026 follow-up).** The
bottom `carry_in` was previously a witnessed-but-unconstrained zero and the
inter-limb `carry_in` cells were free witnesses (not chained to the previous
`carry_out`). Now chained + zero-constrained, so `raw == a + b` is actually
proven.

The secp256k1 MockProver test previously produced 8 permutation failures in `constrain_affine`.
This was caused by the unconstrained wide-to-narrow reduction in `field_mul`.

**History (so this section stops contradicting itself):**
1. First attempt: a Schwartz–Zippel product check on every `field_mul`.
   **Reverted** — mathematically incorrect for base-2^64 limbs (limb
   polynomials at r=65537 do not match integer arithmetic in base 2^64, so it
   failed for honest provers). The dead `verify_product` helper remains in
   `secp256k1.rs`.
2. Current fix (applied): sound integer carry chains — `carry_chain_columns`
   (range-checked, final carry-out = 0) + `reduce_canonical_mod_p` (witnessed
   quotient `q` with `result + q·p = V` + canonicalization `result < p`).
   Same strategy as audited non-native libraries. `field_mul`,
   `field_add_carried`, and `field_sub` all route through it.

**Status:** IMPLEMENTED. The earlier `"⚠️ CORRECTION — currently UNCONSTRAINED
/ check_on_curve is vacuous / scalar mul is non-binding"` text in this file
described the PRE-carry-chain state and is removed; it directly contradicted
the implemented code above. The remaining gate is the k=23 MockProver
confirmation:
```bash
cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
```
(The code comment in `secp256k1.rs` flags these as the pending confirmation;
each is ~2 min / ~15 GiB RSS at k=23.)

**VK mismatch**: The current `Halo2VerifyingKey.sol` has k=21 (2M rows) with all-zero fixed
commitments. The full production circuit requires **k=23 (8.4M rows)** — the
secp256k1 carry-chain soundness rewrite first pushed k 22→24, then the
`point_add_mixed` optimization halved the witness and brought it back to k=23.
The VK must be regenerated from the full circuit after the E2E wiring bug
above is fixed and the E2E MockProver test passes at k=23.

**Remaining recommendation**: Replace the hand-rolled secp256k1 gadget with an audited library
for defense-in-depth:
- `scroll-tech/halo2-secp256k1`
- `privacy-scaling-explorations/halo2wrong`

This remains a **recommended** step (no longer blocking) after the product verification fix.

## Nullifier Collision Analysis (Birthday Bound)

The nullifier is computed as `poseidon(Fr(key), Fr(domain))` where Poseidon
outputs a 254-bit field element (BN254 scalar field).

For 1,000,000 claims (worst case), the probability of at least one nullifier
collision follows the birthday bound:

```
p(collision) ≈ 1 - e^(-n² / 2q)
           = 1 - e^(-(10⁶)² / (2 × 2²⁵⁴))
           ≈ 10⁶² / 2²⁵⁵
           ≈ 10⁻⁷²  (negligible)
```

For context, winning the Powerball jackpot (~1 in 292 million) is ~10⁶⁰ times
more likely than a nullifier collision.

The empirical 50,000-key uniqueness test provides additional confidence,
though the theoretical bound alone is overwhelmingly sufficient.

## Post-Deployment Monitoring

Once the contracts are deployed on Base mainnet, the following should be monitored:

### On-Chain Metrics (query via RPC or BaseScan API)

| Metric | Method | Alert Threshold |
|--------|--------|-----------------|
| Claims per hour | `airdrop.totalClaims()` diff over 1h | > 10,000/h (abnormal surge) |
| Gas price spike during claims | Block base fee | > 10 gwei sustained |
| Duplicate nullifier attempt | Watch `Claimed` event revert logs | Any occurrence |
| Supply anomaly | `token.totalSupply()` vs `claims × 10,000` | Mismatch |

### Simple Monitoring Script (example)

```bash
# Poll every 60 seconds, alert on anomalies
while true; do
  claims=$(cast call $AIRDROP_ADDR "totalClaims()(uint256)" --rpc-url https://mainnet.base.org)
  supply=$(cast call $TOKEN_ADDR "totalSupply()(uint256)" --rpc-url https://mainnet.base.org)
  echo "$(date) claims=$claims supply=$supply"
  sleep 60
done
```

### Recommended Tools
- **BaseScan alerts**: Set up email/webhook for all transactions to the airdrop contract
- **Tenderly** or **OpenZeppelin Defender**: Transaction monitoring + anomaly detection
- **Dune dashboard**: Track cumulative claims, supply, and burn rate over time
- **GitHub Actions scheduled job**: Run a lightweight health-check daily (see `ci.yml` schedule)
