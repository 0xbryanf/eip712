// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./EIP712Domain.sol";

contract TransferOrder is EIP712Domain {
    string internal constant EIP712_TRANSFER_ORDER_SCHEMA = "Transfer(address spender,uint256 amount,bytes32 data,uint256 expiration)";
    bytes32 public constant EIP712_TRANSFER_ORDER_SCHEMA_HASH = keccak256(
        abi.encodePacked(EIP712_TRANSFER_ORDER_SCHEMA)
    );

    struct Transfer {
        address spender;
        uint256 amount;
        bytes32 data;
        uint256 expiration;
    }

    constructor(string memory name, string memory version) EIP712Domain(name, version) {}

    function getTransferHash(address spender, uint256 amount, bytes32 data, uint256 expiration) public view virtual returns(bytes32 result) {
        result = hashEIP712Message(hashTransfer(spender, amount, data, expiration));
        return result;
    }

    function hashTransfer(
        address spender,
        uint256 amount,
        bytes32 data,
        uint256 expiration
    ) internal pure returns (bytes32 result) {
        bytes32 schemaHash = EIP712_TRANSFER_ORDER_SCHEMA_HASH;

        return keccak256(abi.encode(
            schemaHash,
            spender,
            amount,
            data,
            expiration
        ));
    }
}