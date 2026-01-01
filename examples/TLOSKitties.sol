// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "solmate/tokens/ERC721.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOSKitties - NFT Mystery Box with Hidden Trait Generation
/// @notice Demonstration of TLOS for hiding NFT trait generation logic
/// @dev This example shows how to use a shared TLOS circuit to generate
///      hidden traits for an NFT collection. The circuit maps entropy to
///      traits in a way that is verifiable but unpredictable.
///
///      Key concepts:
///      - circuitDataPointer: SSTORE2 pointer to shared obfuscated circuit data
///      - evaluateTLOS: Evaluates the circuit to get trait output
///      - decodeTraits: Extracts individual traits from circuit output
///
///      Security: With visible trait logic, minters could simulate which
///      (blockhash, sender, tokenId) combinations yield rare traits.
///      TLOS hides this mapping: deterministic and verifiable, but attackers
///      cannot predict which inputs produce legendary traits.
///
///      NOTE: This is a simplified demonstration example, not production code.
///      A production deployment would include the full LWE evaluation logic
///      from TLOS.sol or TLOSWithPuzzleV3.sol.
contract TLOSKitties is ERC721 {
    uint256 public constant Q = 65521;
    uint256 public constant LBLO_N = 128;
    uint256 public constant THRESHOLD = Q / 4;

    address public immutable circuitDataPointer;
    uint8 public immutable numWires;
    uint32 public immutable numGates;
    bytes32 public immutable circuitSeed;

    uint256 public totalMinted;

    struct Traits {
        uint8 fur;       // 0-15: common to legendary
        uint8 eyes;      // 0-7: patterns
        uint8 accessory; // 0-31: items
    }

    mapping(uint256 => Traits) public kittyTraits;

    uint256 private constant CT_SIZE = 258;
    uint256 private constant GATE_SIZE = 1035;

    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _circuitSeed
    ) ERC721("TLOS Kitties", "KITTY") {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitDataPointer != address(0), "Invalid pointer");

        circuitDataPointer = _circuitDataPointer;
        numWires = _numWires;
        numGates = _numGates;
        circuitSeed = _circuitSeed;
    }

    function mint() external returns (uint256) {
        uint256 tokenId = ++totalMinted;

        bytes32 entropy = keccak256(abi.encode(
            blockhash(block.number - 1),
            msg.sender,
            tokenId
        ));

        uint256 output = _evaluateTLOS(entropy);
        kittyTraits[tokenId] = _decodeTraits(output);

        _mint(msg.sender, tokenId);
        return tokenId;
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(ownerOf(tokenId) != address(0), "NOT_MINTED");
        Traits memory t = kittyTraits[tokenId];
        return string(abi.encodePacked(
            "data:application/json,{\"fur\":", _uint8ToString(t.fur),
            ",\"eyes\":", _uint8ToString(t.eyes),
            ",\"accessory\":", _uint8ToString(t.accessory), "}"
        ));
    }

    function getTraits(uint256 tokenId) external view returns (Traits memory) {
        require(ownerOf(tokenId) != address(0), "NOT_MINTED");
        return kittyTraits[tokenId];
    }

    function _decodeTraits(uint256 output) internal pure returns (Traits memory) {
        return Traits({
            fur: uint8(output & 0xF),
            eyes: uint8((output >> 4) & 0x7),
            accessory: uint8((output >> 7) & 0x1F)
        });
    }

    function _evaluateTLOS(bytes32 input) internal view returns (uint256) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);

        uint256[8] memory s = _deriveSecret128Array(input);

        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;

        assembly {
            let sPtr := s
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, mul(gateCount, 1035))

            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 1035) } {
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)

                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                let ttIdx := or(c1Val, shl(1, c2Val))

                let ctPtr := add(dataPtr, add(3, mul(ttIdx, 258)))

                let innerProd := 0

                for { let wordIdx := 0 } lt(wordIdx, 8) { wordIdx := add(wordIdx, 1) } {
                    let a := mload(add(ctPtr, mul(wordIdx, 32)))
                    let sv := mload(add(sPtr, mul(wordIdx, 32)))

                    innerProd := add(innerProd, mul(and(shr(240, a), 0xFFFF), and(shr(240, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(224, a), 0xFFFF), and(shr(224, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(208, a), 0xFFFF), and(shr(208, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(192, a), 0xFFFF), and(shr(192, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(176, a), 0xFFFF), and(shr(176, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(160, a), 0xFFFF), and(shr(160, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(144, a), 0xFFFF), and(shr(144, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(128, a), 0xFFFF), and(shr(128, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(112, a), 0xFFFF), and(shr(112, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(96, a), 0xFFFF), and(shr(96, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(80, a), 0xFFFF), and(shr(80, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(64, a), 0xFFFF), and(shr(64, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(48, a), 0xFFFF), and(shr(48, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(32, a), 0xFFFF), and(shr(32, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(shr(16, a), 0xFFFF), and(shr(16, sv), 0xFFFF)))
                    innerProd := add(innerProd, mul(and(a, 0xFFFF), and(sv, 0xFFFF)))
                }

                let bWord := mload(add(ctPtr, 256))
                let b := and(shr(240, bWord), 0xFFFF)

                innerProd := mod(innerProd, q)

                let diff := mod(add(sub(b, innerProd), q), q)
                let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))

                let newVal := xor(and(shr(active, wires), 1), cfBit)
                let bitMask := shl(active, 1)
                wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
            }
        }

        return wires;
    }

    function _deriveSecret128Array(bytes32 input) internal pure returns (uint256[8] memory s) {
        bytes32[8] memory h;
        h[0] = keccak256(abi.encodePacked(input, uint256(0)));
        h[1] = keccak256(abi.encodePacked(input, uint256(1)));
        h[2] = keccak256(abi.encodePacked(input, uint256(2)));
        h[3] = keccak256(abi.encodePacked(input, uint256(3)));
        h[4] = keccak256(abi.encodePacked(input, uint256(4)));
        h[5] = keccak256(abi.encodePacked(input, uint256(5)));
        h[6] = keccak256(abi.encodePacked(input, uint256(6)));
        h[7] = keccak256(abi.encodePacked(input, uint256(7)));
        uint256 q = Q;

        assembly {
            let sPtr := s
            let hPtr := h
            for { let j := 0 } lt(j, 8) { j := add(j, 1) } {
                let hVal := mload(add(hPtr, mul(j, 32)))
                let sVal := 0
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    sVal := or(sVal, shl(shift, mod(and(shr(shift, hVal), 0xFFFF), q)))
                }
                mstore(add(sPtr, mul(j, 32)), sVal)
            }
        }
    }

    function _uint8ToString(uint8 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint8 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint8(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
