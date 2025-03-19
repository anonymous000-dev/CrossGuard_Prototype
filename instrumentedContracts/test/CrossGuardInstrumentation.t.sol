// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {UniswapInterfaceMulticall} from "../src/CrossGuardInstrumentation.sol";


contract UniswapInterfaceMulticallTest is Test {
    UniswapInterfaceMulticall public uniswapInterfaceMulticall1;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall2;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall3;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall4;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall5;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall6;
    UniswapInterfaceMulticall public uniswapInterfaceMulticall7;

    function setUp() public {
        uniswapInterfaceMulticall1 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall2 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall3 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall4 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall5 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall6 = new UniswapInterfaceMulticall();
        uniswapInterfaceMulticall7 = new UniswapInterfaceMulticall();
    }

    function test_updateCurrentTimestampCF() public {
            

            
            uint times = 4;
            
            for (uint i = 0; i < 5; i++) {

                uniswapInterfaceMulticall1.updateCurrentTimestampBare(times);
                times ++;

                uniswapInterfaceMulticall2.updateCurrentTimestampCF(times);
                times ++;

                uniswapInterfaceMulticall3.updateCurrentTimestampTopDown(times);
                times ++;

                uniswapInterfaceMulticall4.updateCurrentTimestampTopDownSload(times);
                times ++;

                uniswapInterfaceMulticall5.updateCurrentTimestampTopDownSstore(times);
                times ++;
            }
            
          
    
            
    }



}
