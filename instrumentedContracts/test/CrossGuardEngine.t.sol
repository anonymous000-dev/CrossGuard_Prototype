// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CrossGuardEngine} from "../src/CrossGuardEngine.sol";







contract CrossGuardEngineTest is Test {
    CrossGuardEngine public crossGuardEngine;

    function setUp() public {
        crossGuardEngine = new CrossGuardEngine();
    }

    function help() public {
        uint num = 1;
        crossGuardEngine.ValidatePre_Transient(num);
        crossGuardEngine.ValidatePost_Transient(num, false);

        num = 2;
        crossGuardEngine.ValidatePre_Transient(num);
        crossGuardEngine.ValidatePost_Transient(num, false);


        num = 3;
        crossGuardEngine.ValidatePre_Transient(num);
        crossGuardEngine.ValidatePost_Transient(num, false);

        num = 4;
        crossGuardEngine.ValidatePre_Transient(num);
        crossGuardEngine.ValidatePost_Transient(num, false);

      

    }

    function test_Validate2() public {

        help();


    }





}