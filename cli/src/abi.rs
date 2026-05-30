//! ABI bindings for ZKMist smart contracts.
//!
//! alloy's sol! macro computes selectors, handles offset/padding for dynamic
//! types, and generates type-safe call/response structs.

alloy::sol! {
    /// Claim ABI: claim(bytes proof, bytes32 nullifier, address recipient)
    /// Public inputs are passed directly as calldata — no journal needed.
    function claim(bytes calldata proof, bytes32 nullifier, address recipient);

    interface IZKMAirdrop {
        function token() external view returns (address);
        function totalClaims() external view returns (uint256);
        function claimsRemaining() external view returns (uint256);
        function isClaimWindowOpen() external view returns (bool);
        function isClaimed(bytes32 nullifier) external view returns (bool);
        function CLAIM_AMOUNT() external view returns (uint256);
        function MAX_CLAIMS() external view returns (uint256);
        function CLAIM_DEADLINE() external view returns (uint256);
        function merkleRoot() external view returns (bytes32);
        function verifier() external view returns (address);
    }

    interface IZKMToken {
        function totalSupply() external view returns (uint256);
        function MAX_SUPPLY() external view returns (uint256);
    }
}
