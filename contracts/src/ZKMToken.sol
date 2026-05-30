// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title ZKMToken — ERC-20 token for ZKMist (Halo2-KZG)
/// @notice Mintable only by the airdrop contract. Burnable by holders.
///         Immutable minter — no admin, no owner, no upgrade.
contract ZKMToken is ERC20 {
    uint256 public constant MAX_SUPPLY = 10_000_000_000e18;
    address public immutable minter;

    constructor(address _minter) ERC20("ZKMist", "ZKM") {
        minter = _minter;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Only airdrop contract");
        require(to != address(0), "Mint to zero address");
        require(amount > 0, "Amount must be positive");
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
