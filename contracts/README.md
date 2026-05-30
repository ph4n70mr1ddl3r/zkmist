# ZKMist Smart Contracts

Privacy-preserving, community-owned ZKM token airdrop on Base.

## Contracts

| Contract | Description |
|----------|-------------|
| `ZKMToken.sol` | ERC-20 with max supply (10B), mintable only by airdrop, burnable by holders |
| `ZKMAirdrop.sol` | Immutable claim contract — verify Halo2-KZG proof + mint tokens |
| `Halo2Verifier.sol` | Auto-generated Halo2-KZG proof verifier |

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test          # Unit tests
forge test -vv      # With gas reports
forge test --match-contract ZKME2E  # End-to-end integration tests
```

### Deploy

Set environment variables:
```shell
export PRIVATE_KEY=0x...         # Deployer key with ETH on Base
```

```shell
forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast
```

## Architecture

- **Fully immutable**: No admin, no owner, no pause, no upgrade
- **100% community-owned**: All tokens minted on claim, zero team allocation
- **Privacy-preserving**: ZK proofs hide the qualified address from the recipient
- **Gas-efficient**: ~350-400K gas per claim via Halo2-KZG proof verification
- **Proof system**: Halo2-KZG using BN254 (ecPairing precompile)

## Claim ABI

The claim function takes a Halo2-KZG proof, nullifier, and recipient:

```solidity
function claim(bytes calldata proof, bytes32 nullifier, address recipient)
```

Public inputs are passed directly as calldata — no journal parsing needed.
