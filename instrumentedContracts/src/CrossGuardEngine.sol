// SPDX-License-Identifier: UNLICENSED
// (c) Zhiyang Chen 2024

pragma solidity ^0.8.17;




contract CrossGuardEngine {

    // @dev: This is the constructor of the contract.
    constructor() {
        admins[msg.sender] = true;
        operators[msg.sender] = true;
    }

    mapping(address => bool) public operators; // operators are the contracts inside the same protocol
    mapping(address => bool) public admins; // approved senders are the contracts that can call the validate functions
    mapping(uint216 => bool) internal _allowedPatterns;

    // show always be transient storage
    // a sum is a summation
    // when a function enters, it adds +X
    // when a function exits, it subtracts X
    // so the sum should be 0, when a new invocation starts

    // Transient storage slots for pattern, sum, depth, and isRAWDependent
    bytes32 private constant SLOT_PATTERN = keccak256("CrossGuardEngine.pattern");
    bytes32 private constant SLOT_SUM = keccak256("CrossGuardEngine.sum");
    bytes32 private constant SLOT_DEPTH = keccak256("CrossGuardEngine.depth");
    bytes32 private constant SLOT_ISRAWDEPENDENT = keccak256("CrossGuardEngine.isRAWDependent");

    // Function to Tload from transient storage
    function Tload(bytes32 slot) internal view returns (bytes32 result) {
        assembly {
            result := tload(slot)
        }
    }

    // Function to Tstore into transient storage
    function Tstore(bytes32 slot, bytes32 value) internal {
        assembly {
            tstore(slot, value)
        }
    }

    function addOperator(address operator) external onlyAdmin {
        operators[operator] = true;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "CrossGuard error: operator required");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "CrossGuard error: admin required");
        _;
    }

    function configureRules(uint216 _pattern) external onlyAdmin {
        _allowedPatterns[_pattern] = true;
    }


    function getSum() external returns (uint256) {
        return uint256(Tload(SLOT_SUM));
    }


    function getSum1() external returns (uint256) {
        Tstore(SLOT_SUM, bytes32(uint(1)));
        return uint256(Tload(SLOT_SUM));
    }


    function getSum2() external returns (uint256) {
        Tstore(SLOT_SUM, bytes32(uint(2)));
        return uint256(Tload(SLOT_SUM));
    }


    function setSum(uint256 sum) external  {
        Tstore(SLOT_SUM, bytes32(sum));
    }

    function ValidatePre_Transient(uint256 num)
        external
        
        returns (uint times)
    {
        // Load pattern using Tload
        uint216 pattern = uint216(uint(Tload(SLOT_PATTERN)));
        pattern = uint216(bytes27(keccak256(abi.encode(num, pattern))));
        // Store the updated pattern using Tstore
        Tstore(SLOT_PATTERN, bytes32(uint(pattern)));

        // Load sum using Tload
        uint256 sum = uint256(Tload(SLOT_SUM));
        sum += num;
        // Store the updated sum using Tstore
        Tstore(SLOT_SUM, bytes32(uint(1)));

        if (sum - num == 0) {
            // Load depth using Tload
            uint depth = uint(Tload(SLOT_DEPTH));
            depth += 1;
            // Store the updated depth using Tstore
            Tstore(SLOT_DEPTH, bytes32(depth));
            return depth - 1;
        }
        return uint(Tload(SLOT_DEPTH)) - 1;

    }


    function ValidatePost_Transient(uint256 num, bool RAW)
        external
        onlyOperator
    {
        // Load pattern using Tload
        uint216 pattern = uint216(uint(Tload(SLOT_PATTERN)));
        pattern = uint216(bytes27(keccak256(abi.encode(num, pattern))));
        // Store the updated pattern using Tstore
        Tstore(SLOT_PATTERN, bytes32(uint(pattern)));
        // Load isRAWDependent using Tload
        bool isRAWDependent = uint(Tload(SLOT_ISRAWDEPENDENT)) != 0;
        if (RAW && !isRAWDependent) {
            // Store the updated isRAWDependent using Tstore
            Tstore(SLOT_ISRAWDEPENDENT, bytes32(uint(1)));
        }
        if (!_allowedPatterns[pattern] && isRAWDependent) {
            revert("Unsafe pattern detected");
        }
        // Load sum using Tload
        uint256 sum = uint256(Tload(SLOT_SUM));
        // sum -= num;
        // Store the updated sum using Tstore
        Tstore(SLOT_SUM, bytes32(sum));
    }




    // function ValidatePre(uint256 num)
    //     external
    //     onlyOperator
    //     returns (uint times)
    // {
    //     pattern = uint216(bytes27(keccak256(abi.encode(num, pattern))));
    //     sum += num;
    //     if(sum - num == 0) {
    //         depth += 1;
    //         return depth - 1;
    //     }
    //     return depth - 1;
    // }


    // function ValidatePost(uint256 num, bool RAW)
    //     external
    //     onlyOperator
    // {
    //     pattern = uint216(bytes27(keccak256(abi.encode(num, pattern))));

    //     if (RAW && !isRAWDependent) {
    //         isRAWDependent = true;
    //     }

    //     if( !_allowedPatterns[pattern] && isRAWDependent) {
    //         revert("Unsafe pattern detected");
    //     }

    //     sum -= num;
    // }



}
    

