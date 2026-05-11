// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/// @title ZKMist (ZKM) Token
/// @notice ERC-20 with max supply, mintable only by the airdrop contract, burnable by holders.
/// @dev No owner, no admin functions. Immutable minter set at construction.
contract ZKMToken is ERC20 {
    uint256 public constant MAX_SUPPLY = 10_000_000_000e18; // 10 billion ZKM
    address public immutable minter;

    constructor(address _minter) ERC20("ZKMist", "ZKM") {
        minter = _minter;
    }

    /// @notice Mint tokens. Only callable by the airdrop contract.
    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Only airdrop contract");
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }

    /// @notice Burn tokens from the caller's balance. Permanently reduces total supply.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from an approved address. Permanently reduces total supply.
    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
