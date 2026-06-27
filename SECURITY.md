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
- [ ] **Re-run secp256k1 MockProver test** to confirm product verification fix:
  ```
  cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
  ```
- [ ] **Re-run full E2E MockProver test** with the fix:
  ```
  cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
  ```
- [ ] **External security audit** of secp256k1 non-native field arithmetic (including new Schwartz–Zippel verification)
- [ ] **Generate `Halo2Verifier.sol` and `Halo2VerifyingKey.sol`** using halo2-solidity-verifier with the real circuit VK:
  ```
  cargo run --release -p zkmist-tools --bin gen-verifier -- --output contracts/src/Halo2Verifier.sol
  # Then use halo2-solidity-verifier with the generated Halo2Verifier.vk.bin
  # See: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
  ```
  **IMPORTANT**: The current `Halo2VerifyingKey.sol` has k=21 with all-zero fixed commitments.
  This is from a partial circuit configuration, NOT the full production circuit (which needs k=23).
  Must regenerate from the full circuit after MockProver tests pass.
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

6. **⚠️ SUPERSEDED — `field_mul` reduction is NOT constrained.**
   A Schwartz–Zippel product verification was attempted on every `field_mul`
   call, but it was **mathematically incorrect** for the base-2^64 limb
   representation (evaluating limb polynomials at r=65537 does not match
   integer arithmetic in base 2^64, so it failed for honest provers) and was
   **removed** (the dead `verify_product` helper remains in `secp256k1.rs`).
   As of the 2026 review the wide→narrow reduction in `field_mul` assigns its
   result limbs as **free witnesses**, and `field_add_carried`'s reduction is
   likewise disconnected from its constrained raw sum. Because the secp256k1
   prime (≈2^256) is close to the BN254 scalar prime (≈2^254), the reduction
   **cannot** be soundly checked at the BN254 level alone — it requires a full
   integer carry/borrow chain, as provided by audited non-native field
   libraries. **The terminal `check_on_curve` / `constrain_affine` checks do
   NOT compensate, because they are themselves built on `field_mul` and are
   therefore vacuous.** Until this is fixed (carry-chain rewrite or library
   swap), the secp256k1 scalar multiplication is non-binding. The `cond_swap`
   Merkle gadget WAS fixed (see below).

## Known Issues (Blocking Mainnet)

**`field_mul` / `field_add_carried` / `field_sub` reductions — CONSTRAINED
but UNVALIDATED (2026 follow-up).** The wide→narrow reduction in `field_mul`,
the raw→reduced step in `field_add_carried`, and `neg_b` in `field_sub` are no
longer witness-trusted: they now use explicit range-checked integer carry
chains plus a witnessed quotient `q` with `result + q·p = V` and a
canonicalization proof `result < p` (see `carry_chain_columns` /
`reduce_canonical_mod_p` / the rewritten `field_sub` in `secp256k1.rs`).

⚠️ This code has NOT yet been validated by MockProver in this environment
(running the heavy k=22/23 tests risks crashing it, as the real-KZG path did).
It compiles cleanly (`cargo check -p zkmist-circuits`) and all native
arithmetic tests pass, but it MUST be confirmed before any reliance:
```
cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
```
These tests will likely need HIGHER k than before (the sound reductions add
many rows per field op); if k=23 no longer fits, raise k or adopt an optimized
audited non-native library. After MockProver passes, regenerate
`EXPECTED_CS_DIGEST` (circuits/src/lib.rs + gen-production-verifier) since the
constraint system changed.

**`cond_swap` Merkle gadget — FIXED (2026 review).** The previous version's
`out = term1 + term2` gate left `term1`/`term2` as free advice cells, making
the Merkle membership proof non-binding. It now constrains `sel*b`,
`(1-sel)*a`, `sel*a`, and `(1-sel)*b` with multiplication gates (mirroring
`conditional_select_field`).

**`field_add_carried` Phase 1 carry chain — FIXED (2026 follow-up).** The
bottom `carry_in` was previously a witnessed-but-unconstrained zero and the
inter-limb `carry_in` cells were free witnesses (not chained to the previous
`carry_out`). Now chained + zero-constrained, so `raw == a + b` is actually
proven.

The secp256k1 MockProver test previously produced 8 permutation failures in `constrain_affine`.
This was caused by the unconstrained wide-to-narrow reduction in `field_mul`.

**Fix applied**: Schwartz–Zippel product verification has been added to every `field_mul` call.
This constrains the product correctness with negligible soundness error (≤ 6/p_BN254).

**⚠️ CORRECTION (2026 review)**: the above fix was **reverted** because it was
mathematically incorrect for base-2^64 limbs (see item 6 above). The `field_mul`
reduction is currently UNCONSTRAINED. The real fix is an integer carry-chain
reduction or an audited library swap.

**Resolution**: The `#[ignore]`d MockProver tests need to be re-run to confirm the fix resolves
all permutation failures:
```bash
cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
```

**VK mismatch**: The current `Halo2VerifyingKey.sol` has k=21 (2M rows) with all-zero fixed
commitments. The full production circuit requires k=23 (8M rows). The VK must be regenerated
from the full circuit after the MockProver tests pass.

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
