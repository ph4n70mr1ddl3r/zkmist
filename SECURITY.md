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
- [ ] **External security audit** of secp256k1 non-native field arithmetic
- [ ] **Regenerate `Halo2Verifier.sol`** with full KZG pairing verification via `snark-verifier`:
  ```
  cargo run --release -p zkmist-tools --bin gen-verifier --features v2 -- --output contracts/src/Halo2Verifier.sol
  ```
- [ ] **Verify `IS_PRODUCTION_VERIFIER = true`** in the generated verifier
- [ ] **Run full E2E MockProver test** (previously `#[ignore]`d):
  ```
  cargo test -p zkmist-circuits test_circuit_merkle_nullifier_e2e -- --ignored --nocapture
  ```
- [ ] **Run isolated secp256k1 MockProver test**:
  ```
  cargo test -p zkmist-circuits test_secp256k1_mock_prover -- --ignored --nocapture
  ```
- [ ] **Testnet deployment** on Base Sepolia with full E2E claim flow

### High Priority
- [x] **Regenerate gas snapshot**: `cd contracts && forge snapshot` ✅ (53 tests, snapshot committed)
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
- [ ] Set up monitoring/alerting for the deployed contracts
  - Run: `cargo run -p zkmist-tools --bin monitor -- <address> --rpc https://mainnet.base.org`

## Soundness Hardening (Applied)

The following hardening measures have been applied to the secp256k1 non-native
field arithmetic gadget:

1. **Carry-propagated addition everywhere**: `field_double` now uses
   `field_add_carried` (carry-propagated) instead of basic `field_add`.
   This ensures ALL additions in EC double-and-add scalar multiplication
   propagate carry chains consistently.

2. **Linked carry constraints**: The boolean constraint on carry values in
   `field_add_carried` now applies copy-constraints linking the gate's
   carry cells to the boolean-check cells. Previously these were independently
   assigned, allowing a theoretical disconnect.

3. **Corrected reduction cross-check in `field_mul`**: Replaced the incorrect
   `wide[0] == result[0]` assertion (which was wrong for most multiplications)
   with a constrained reduction check: `s_mul(c, wide[4])` +
   `s_add(wide[0], c*wide[4]) = result[0]`, which properly verifies the
   first step of the wide-to-narrow reduction using the secp256k1 identity
   `2^256 ≡ 2^32 + 977 (mod p)`.

4. **Consistent carry propagation in `field_sub`**: Uses `field_add_carried`
   for the final addition step, ensuring subtraction also propagates carries.

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
