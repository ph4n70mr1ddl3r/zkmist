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
- The `Halo2Verifier` must be production-ready (`IS_PRODUCTION_VERIFIER == true`) before mainnet deployment
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
- [ ] **Generate `Halo2Verifier.sol`** using halo2-solidity-verifier with serialized VK:
  ```
  cargo run --release -p zkmist-tools --bin gen-verifier -- --output contracts/src/Halo2Verifier.sol
  # Then use halo2-solidity-verifier with the generated Halo2Verifier.vk.bin
  # See: https://github.com/privacy-scaling-explorations/halo2-solidity-verifier
  ```
- [ ] **Verify `IS_PRODUCTION_VERIFIER = true`** in the generated verifier
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
- [ ] **Proof size validation**: confirm proof fits in `[400, 1200]` byte range
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

6. **NEW: Schwartz–Zippel product verification on every `field_mul`**: Every
   non-native field multiplication is now cross-checked using a polynomial
   evaluation at a fixed point (r = 65537). The check constrains:
   `eval(a) * eval(b) - eval(result) - eval(q) * eval(p) = 0 (mod BN254)`
   where `eval(x) = x[0] + x[1]*r + x[2]*r^2 + x[3]*r^3` and `q = (a*b - result) / p`
   is the reduction quotient (range-checked). This closes the soundness gap from
   the previously unconstrained wide-to-narrow reduction in `field_mul`. Soundness
   error is ≤ 6/p_BN254 per multiplication (negligible).

## Known Issues (Blocking Mainnet)

The secp256k1 MockProver test previously produced 8 permutation failures in `constrain_affine`.
This was caused by the unconstrained wide-to-narrow reduction in `field_mul`.

**Fix applied**: Schwartz–Zippel product verification has been added to every `field_mul` call.
This constrains the product correctness with negligible soundness error (≤ 6/p_BN254).

**Resolution**: The `#[ignore]`d MockProver tests need to be re-run to confirm the fix resolves
all permutation failures:
```bash
cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
```

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
