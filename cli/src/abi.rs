//! ABI bindings for ZKMist smart contracts.
//!
//! alloy's sol! macro computes selectors, handles offset/padding for dynamic
//! types, and generates type-safe call/response structs — eliminating a class
//! of encoding bugs and fragile raw storage-slot reads.

alloy::sol! {
    function claim(bytes calldata _proof, bytes calldata _journal, bytes32 _nullifier, address _recipient);

    /// V2 claim ABI: claim(bytes proof, bytes32 nullifier, address recipient)
    /// No journal — public inputs are passed directly as calldata.
    function claimV2(bytes calldata proof, bytes32 nullifier, address recipient);

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
        function imageId() external view returns (bytes32);
    }

    interface IZKMToken {
        function totalSupply() external view returns (uint256);
        function MAX_SUPPLY() external view returns (uint256);
    }
}
