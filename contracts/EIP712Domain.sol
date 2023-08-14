// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

library MessageHashUtils {
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}

contract EIP712Domain {
    bytes32 private constant EIP712_DOMAIN_TYPE_HASH = keccak256(abi.encode("EIP712Domain(string name, string version, uint256 chainId, address verifyingContract)"));
    
    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedVerifyingAddress;
    bytes32 private immutable _domainName;
    bytes32 private immutable _domainVersion;

    string private _name;
    string private _version;

    constructor(string memory name, string memory version) {
        _name = name;
        _version = version;

        _domainName = keccak256(bytes(name));
        _domainVersion = keccak256(bytes(version));
        _cachedChainId = block.chainid;
        _cachedVerifyingAddress = address(this);
        _cachedDomainSeparator = _buildDomainSeparator();
    }

    function _domainSeparatorV4() public view returns (bytes32) {
        if (address(this) == _cachedVerifyingAddress && block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        } else {
            return _buildDomainSeparator();
        }
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPE_HASH, 
            _domainName, 
            _domainVersion, 
            block.chainid, 
            address(this)
        ));
    }

    function hashEIP712Message(bytes32 hashStruct) internal view virtual returns (bytes32 result) {
        result = MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), hashStruct);
        return result;
    }

    function eip712Domain() public view virtual returns (bytes1, string memory, string memory, uint256, address) {
        return (
            hex"0f",
            _EIP712Name(),
            _EIP712Version(),
            block.chainid,
            address(this)
        );
    }

    function _EIP712Name() internal view returns (string memory) {
        return _name;
    }

    function _EIP712Version() internal view returns (string memory) {
        return _version;
    }

    function verify(bytes32 hash, bytes memory signature, address signer) public pure returns (address result) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length != 65) {
            return address(0);
        }

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := and(mload(add(signature, 65)), 255)
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return address(0x0);
        }

        result = ecrecover(hash, v, r, s);

        require(result == signer, 'Invalid signer');
        require(result != address(0), 'Error in ecrecover');
    }
}