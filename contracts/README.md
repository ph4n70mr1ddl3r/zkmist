# ZKMist Smart Contracts

Privacy-preserving, community-owned ZKM token airdrop on Base.

## Contracts

| Contract | Description |
|----------|-------------|
| `ZKMToken.sol` | ERC-20 with max supply (10B), mintable only by airdrop, burnable by holders |
| `ZKMAirdrop.sol` | Immutable claim contract — verify ZK proof + mint tokens |
| `IRiscZeroVerifier.sol` | RISC Zero Groth16 verifier interface |

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test          # Unit tests (33 tests)
forge test -vv      # With gas reports
forge test --match-contract ZKME2E  # End-to-end integration tests (7 tests)
```

### Deploy

Set environment variables:
```shell
export VERIFIER_ADDRESS=0x...   # RISC Zero Groth16 verifier on Base
export IMAGE_ID=0x...           # Guest program image ID (bytes32)
export MERKLE_ROOT=0x...        # Merkle root of eligibility tree (bytes32)
```

```shell
forge script script/Deploy.s.sol --rpc-url $BASE_RPC_URL --broadcast
```

## Architecture

- **Fully immutable**: No admin, no owner, no pause, no upgrade
- **100% community-owned**: All tokens minted on claim, zero team allocation
- **Privacy-preserving**: ZK proofs hide the qualified address from the recipient
- **Gas-efficient**: ~510K gas per claim via Groth16 proof compression

## Journal Layout (84 bytes)

The ZK proof journal is sliced directly by the contract:
```
[0:32]   merkleRoot   (bytes32)
[32:64]  nullifier    (bytes32)
[64:84]  recipient    (address, 20 bytes)
```
