// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
pragma abicoder v2;

/// @notice A fork of Multicall2 specifically tailored for the Uniswap Interface
contract UniswapInterfaceMulticall {
    uint256 storedTimestamp;
    uint256 storedBlockNumber;
    mapping(address => bool) public operators; // operators are the contracts inside the same protocol
    modifier onlyOperator() {
        require(operators[msg.sender], "CrossGuard error: operator required");
        _;
    }
    struct Call {
        address target;
        uint256 gasLimit;
        bytes callData;
    }

    struct Result {
        bool success;
        uint256 gasUsed;
        bytes returnData;
    }


    // Base slots for mappings
    bytes32 private constant SLOT_STORAGE_WRITES = keccak256("CrossGuardEngine.storageWrites");
    bytes32 private constant SLOT_TEMP_STORAGE_READS = keccak256("CrossGuardEngine.tempStorageReads");
    bytes32 private constant SLOT_TEMP_STORAGE_WRITES = keccak256("CrossGuardEngine.tempStorageWrites");
    bytes32 private constant SLOT_CURRENT_INVOCATION = keccak256("CrossGuardEngine.currentInvocation");

    function getCurrentInvocation() internal view returns (uint256) {
        return uint256(Tload(SLOT_CURRENT_INVOCATION));
    }

    function setCurrentInvocation(uint256 value) internal {
        Tstore(SLOT_CURRENT_INVOCATION, bytes32(value));
    }

    // Helper function to calculate the storage slot for a single key mapping
    function getMappingSlot(bytes32 baseSlot, uint256 key) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(key, baseSlot));
    }

    // Helper function to calculate the storage slot for a nested mapping
    function getNestedMappingSlot(bytes32 baseSlot, uint256 outerKey, uint256 innerKey) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(innerKey, keccak256(abi.encodePacked(outerKey, baseSlot))));
    }

    // ********** storageWrites (mapping(uint256 => mapping(uint256 => bool))) **********

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
    // Set value in storageWrites mapping
    function setStorageWrites(uint256 slot, uint256 times, bool value) internal {
        bytes32 storageSlot = getNestedMappingSlot(SLOT_STORAGE_WRITES, slot, times);
        Tstore(storageSlot, bytes32(uint256(value ? 1 : 0)));  // Store boolean as 0 or 1
    }

    // Get value from storageWrites mapping
    function getStorageWrites(uint256 slot, uint256 times) internal view returns (bool) {
        bytes32 storageSlot = getNestedMappingSlot(SLOT_STORAGE_WRITES, slot, times);
        return uint256(Tload(storageSlot)) != 0;  // Return true if non-zero, false otherwise
    }

    // ********** tempStorageReads (mapping(uint256 => uint256)) **********

    // Set value in tempStorageReads mapping
    function setTempStorageReads(uint256 key, uint256 value) internal {
        bytes32 storageSlot = getMappingSlot(SLOT_TEMP_STORAGE_READS, key);
        Tstore(storageSlot, bytes32(value));
    }

    // Get value from tempStorageReads mapping
    function getTempStorageReads(uint256 key) internal view returns (uint256) {
        bytes32 storageSlot = getMappingSlot(SLOT_TEMP_STORAGE_READS, key);
        return uint256(Tload(storageSlot));
    }

    // ********** tempStorageWrites (mapping(uint256 => uint256)) **********

    // Set value in tempStorageWrites mapping
    function setTempStorageWrites(uint256 key, uint256 value) internal {
        bytes32 storageSlot = getMappingSlot(SLOT_TEMP_STORAGE_WRITES, key);
        Tstore(storageSlot, bytes32(value));
    }

    // Get value from tempStorageWrites mapping
    function getTempStorageWrites(uint256 key) internal view returns (uint256) {
        bytes32 storageSlot = getMappingSlot(SLOT_TEMP_STORAGE_WRITES, key);
        return uint256(Tload(storageSlot));
    }





    // 2 versions:


    // version 1: invoked from some contract/EOA that is unknown
    //            ==> need to call CrossGuardEngine

    // version 2: directly invoke from another contract of the same protcol
    //            ==> no need to call CrossGuardEngine
    //            ==> instead, reporting isReadOnly & RAW dependency back to the msg.sender
    //            checking isReadOnly: can completely be done memory-side
    //            checking RAW dependency: need to be done transient storage-side 

    function updateCurrentTimestampCF(uint times) public returns (bool, bool) {
        // ********** define the read and write sets **********
        uint256[] memory readElements = new uint256[](100);
        uint256[] memory writeElements = new uint256[](100);
        uint readElementsIndex = 0;
        uint writeElementsIndex = 0;


        // ********** every sload instrumentation **********
        if (getTempStorageWrites(0) == 0 && getTempStorageReads(0) == 0) {
            setTempStorageReads(0, block.timestamp);
            readElements[readElementsIndex] = 1; // 0 represents the address
            readElementsIndex ++;
        }
        
        // ********** every sstore instrumentation **********
        setTempStorageWrites(0, block.timestamp);
        writeElements[writeElementsIndex] = 1; // 0 represents the address
        writeElementsIndex ++;


        // ================= original code start =================
        storedTimestamp = storedTimestamp + block.timestamp;
        // ================= original code end ===================


        // ********** check runtime read only **********
        bool isReadOnly = true;
        for (uint256 i = 0; i < writeElementsIndex; i++) {
            uint slot = writeElements[i];
            // ********** check if it's a cached **********
            if ( getTempStorageWrites(slot) != getTempStorageReads(slot)) {
                // it is a cache, used for RAW analysis but does not count towards readOnly
                setStorageWrites(slot, times, true);
                isReadOnly = false;
            } else {
                // fake write 
            }
        }

        // ********** check RAW dependency **********
        bool hasRAWDependency = false;
        for (uint256 i = 0; i < readElementsIndex; i++) {
            uint slot = readElements[i];
            for (uint256 j = 0; j < times; j++) {
                if (getStorageWrites(slot, j)) {
                    hasRAWDependency = true;
                    break;
                }
            }
        }
        return (isReadOnly, hasRAWDependency);
    }



    function updateCurrentTimestampTopDown(uint times) public returns (bool, bool) {
        // ********** define the read and write sets **********
        uint256[] memory readElements = new uint256[](100);
        uint256[] memory writeElements = new uint256[](100);
        uint readElementsIndex = 0;
        uint writeElementsIndex = 0;


        // ================= original code start =================
        storedTimestamp = storedTimestamp + block.timestamp;
        // ================= original code end ===================


        // ********** check runtime read only **********
        bool isReadOnly = true;
        for (uint256 i = 0; i < writeElementsIndex; i++) {
            uint slot = writeElements[i];
            // ********** check if it's a cached **********
            if ( getTempStorageWrites(slot) != getTempStorageReads(slot)) {
                // it is a cache, used for RAW analysis but does not count towards readOnly
                setStorageWrites(slot, times, true);
                isReadOnly = false;
            } else {
                // fake write 
            }
        }

        // ********** check RAW dependency **********
        bool hasRAWDependency = false;
        for (uint256 i = 0; i < readElementsIndex; i++) {
            uint slot = readElements[i];
            for (uint256 j = 0; j < times; j++) {
                if (getStorageWrites(slot, j)) {
                    hasRAWDependency = true;
                    break;
                }
            }
        }
        return (isReadOnly, hasRAWDependency);
    }


    function updateCurrentTimestampTopDownSload(uint times) public returns (bool, bool) {
        // ********** define the read and write sets **********
        uint256[] memory readElements = new uint256[](100);
        uint256[] memory writeElements = new uint256[](100);
        uint readElementsIndex = 0;
        uint writeElementsIndex = 0;


        // ********** every sload instrumentation **********
        if (getTempStorageWrites(0) == 0 && getTempStorageReads(0) == 0) {
            setTempStorageReads(0, block.timestamp);
            readElements[readElementsIndex] = 1; // 0 represents the address
            readElementsIndex ++;
        }
        
        // ================= original code start =================
        storedTimestamp = storedTimestamp + block.timestamp;
        // ================= original code end ===================


        // ********** check runtime read only **********
        bool isReadOnly = true;
        for (uint256 i = 0; i < writeElementsIndex; i++) {
            uint slot = writeElements[i];
            // ********** check if it's a cached **********
            if ( getTempStorageWrites(slot) != getTempStorageReads(slot)) {
                // it is a cache, used for RAW analysis but does not count towards readOnly
                setStorageWrites(slot, times, true);
                isReadOnly = false;
            } else {
                // fake write 
            }
        }

        // ********** check RAW dependency **********
        bool hasRAWDependency = false;
        for (uint256 i = 0; i < readElementsIndex; i++) {
            uint slot = readElements[i];
            for (uint256 j = 0; j < times; j++) {
                if (getStorageWrites(slot, j)) {
                    hasRAWDependency = true;
                    break;
                }
            }
        }
        return (isReadOnly, hasRAWDependency);
    }

    function updateCurrentTimestampTopDownSstore(uint times) public returns (bool, bool) {
        // ********** define the read and write sets **********
        uint256[] memory readElements = new uint256[](100);
        uint256[] memory writeElements = new uint256[](100);
        uint readElementsIndex = 0;
        uint writeElementsIndex = 0;
        
        // ********** every sstore instrumentation **********
        setTempStorageWrites(0, block.timestamp);
        writeElements[writeElementsIndex] = 1; // 0 represents the address
        writeElementsIndex ++;



        // ================= original code start =================
        storedTimestamp = storedTimestamp + block.timestamp;
        // ================= original code end ===================


        // ********** check runtime read only **********
        bool isReadOnly = true;
        for (uint256 i = 0; i < writeElementsIndex; i++) {
            uint slot = writeElements[i];
            // ********** check if it's a cached **********
            if ( getTempStorageWrites(slot) != getTempStorageReads(slot)) {
                // it is a cache, used for RAW analysis but does not count towards readOnly
                setStorageWrites(slot, times, true);
                isReadOnly = false;
            } else {
                // fake write 
            }
        }

        // ********** check RAW dependency **********
        bool hasRAWDependency = false;
        for (uint256 i = 0; i < readElementsIndex; i++) {
            uint slot = readElements[i];
            for (uint256 j = 0; j < times; j++) {
                if (getStorageWrites(slot, j)) {
                    hasRAWDependency = true;
                    break;
                }
            }
        }
        return (isReadOnly, hasRAWDependency);
    }



    function updateCurrentTimestampBare(uint times) public returns (bool, bool) {

        // ================= original code start =================
        storedTimestamp = storedTimestamp + block.timestamp;
        // ================= original code end ===================

        return (true, true);
    }




    // the following two functions should not exist in the final version,
    // they are only for a purpose of comparisng gas consumption
    function updateCurrentTimestamp() public {
        storedTimestamp = block.timestamp;
    }


}