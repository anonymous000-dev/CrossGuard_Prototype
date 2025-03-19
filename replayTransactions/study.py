import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from crawlPackage.crawlEtherscan import *
from utilsPackage.compressor import *
from constraintPackage.macros import *
from constraintPackage.utils import *
import multiprocessing
import matplotlib.pyplot as plt
from parserPackage.parser import analyzeOneTxGlobal
from staticAnalyzer.analyzer import Analyzer
import copy
from labelPackage.readLabels import Labeler
from constraintPackage.complementary import complementary, reEntrancyGuard, revertedTransactions, arbitrary_external_call
from constraintPackage.RAWTree import RAWTree
from constraintPackage.txLabeler import txLabeler

import numpy as np
import pandas as pd




pruneReadOnly = False
pruneERC20 = False
pruneTrivialControlFlow = False


class recorder:
    def __init__(self, targetContracts):
        self.targetContracts = targetContracts
        self.functionAccess = []
        self.benchmark = None
        self.tx = None
        self.block = None
        self.tokenTransfers = []
        self.tokens = []
        self.storageAccesses = {}

    def reset(self, tx = None, block = None):
        self.tx = tx
        self.block = block
        self.functionAccess = []
        self.tokenTransfers = []

    def getStorageAccesses(self, tree, parentAddrList, delegateCallList, depth):
        if depth == 0:
            self.storageAccesses = {}
            if "type" in tree.info and tree.info["type"] == "delegatecall":
                return []
        counter = 0
        if "type" in tree.info and tree.info["type"] == "delegatecall":
            counter += 1
            for delegateCall in delegateCallList[::-1]:
                if delegateCall:
                    counter += 1
                else:
                    break
        contract = tree.info["addr"]
        if counter > 0:
            contract = parentAddrList[- counter]

        if "sload/sstore_decoded" in tree.info:
            if contract not in self.storageAccesses:
                self.storageAccesses[contract] = tree.info["sload/sstore_decoded"]
            else:
                self.storageAccesses[contract] += tree.info["sload/sstore_decoded"]
        elif "sload/sstore" in tree.info:
            if contract not in self.storageAccesses:
                self.storageAccesses[contract] = tree.info["sload/sstore"]
            else:
                self.storageAccesses[contract] += tree.info["sload/sstore"]
        
        
        isDelegateCall = False
        if "type" in tree.info and tree.info["type"] == "delegatecall":
            isDelegateCall = True
        for internalCall in tree.internalCalls:
            self.getStorageAccesses(internalCall, parentAddrList + [contract], delegateCallList + [isDelegateCall], depth + 1)
        return self.storageAccesses



    def traverseTree(self, tree, parentAddrList, delegateCallList):
        if "meta" in tree.info:
            for internalCall in tree.internalCalls:
                self.traverseTree(internalCall, parentAddrList, delegateCallList)
            return
        else:
            contract = tree.info["addr"]
            if contract in self.targetContracts:
                node = None
                if tree.info["type"] == "create" or tree.info["type"] == "create2":

                    storageAccesses = self.getStorageAccesses(tree, parentAddrList, delegateCallList, 0)
                    node = (contract, "constructor", "complete", tree.info["structLogsStart"], tree.info["structLogsEnd"], tree.info["type"].lower(), storageAccesses)
                    self.functionAccess.append( node )

                elif "call" in tree.info["type"].lower():
                    # Step 1: get selector
                    selector = ""
                    if "Raw calldata" in tree.info and tree.info["Raw calldata"] != "" and "type" in tree.info and tree.info["type"] != "firstCall":
                        calldata = tree.info["Raw calldata"]
                        # remove 0x prefix from calldata if exists
                        if calldata[:2] == "0x":
                            calldata = calldata[2:]
                        selector = '0x' + calldata[:8]
                    elif "calldata" in tree.info and tree.info["calldata"] != "":
                        calldata = tree.info["calldata"]
                        # remove 0x prefix from calldata if exists
                        if calldata[:2] == "0x":
                            calldata = calldata[2:]
                        selector = '0x' + calldata[:8]
                    else:
                        selector = tree.info["Selector"] if "Selector" in tree.info else ''

                    status = "complete"
                    if "gasless" in tree.info and tree.info["gasless"] :
                        status = "gasless"

                    if len(selector) != 10 and selector != "0x" and selector != "":
                        sys.exit("selector length is not 10: {}".format(selector))
                    
                    
                    # Step 1.1: get storage accesses:
                    storageAccesses = []
                    if "type" in tree.info and tree.info["type"] != "delegatecall":
                        storageAccesses = self.getStorageAccesses(tree, parentAddrList, delegateCallList, 0)

                    # Step 2: handle fallback
                    if selector == "0x" or selector == "":
                        # Step 2.1: handle staticcall to fallback
                        if tree.info["type"] == "staticcall" and "Raw returnvalue" in tree.info and tree.info["Raw returnvalue"] != "":
                            self.functionAccess.append( (contract, "fallback", status, tree.info["structLogsStart"], tree.info["structLogsEnd"], tree.info["type"].lower(), storageAccesses) )
                        elif tree.info["type"] == "staticcall" and "Raw returnvalue" in tree.info and tree.info["Raw returnvalue"] == "":
                            sys.exit("empty return value for a staticcall")

                        # Step 2.2: handle call to fallback
                        if 'msg.value' not in tree.info and "type" in tree.info and tree.info["type"] != "staticcall":
                            print(tree.info)
                            sys.exit("msg.value not found")
                        else:
                            msgValue = int(tree.info['msg.value'], 16) if 'msg.value' in tree.info else 0
                            self.functionAccess.append( (contract, "fallback", status, tree.info["structLogsStart"], tree.info["structLogsEnd"], tree.info["type"].lower(), storageAccesses) )
                            # if msgValue > 0:
                            #     self.functionAccess.append( (contract, "fallback", msgValue) )

                    # step 3: handle normal function call
                    else:
                        # funcName = self.contractSelector2functions[contract][selector]
                        # print(funcName)
                        self.functionAccess.append( (contract, selector, status, tree.info["structLogsStart"], tree.info["structLogsEnd"], tree.info["type"].lower(), storageAccesses) )
                        # pass

                else:
                    print("unknown type: {}".format(tree.info["type"]))
                    sys.exit("unknown type: {}".format(tree.info["type"]))

            counter = 0
            if "type" in tree.info and tree.info["type"] == "delegatecall":
                counter += 1
                for delegateCall in delegateCallList[::-1]:
                    if delegateCall:
                        counter += 1
                    else:
                        break
            if counter > 0:
                contract = parentAddrList[- counter]

            isDelegateCall = False
            if "type" in tree.info and tree.info["type"] == "delegatecall":
                isDelegateCall = True

            for internalCall in tree.internalCalls:
                self.traverseTree(internalCall, parentAddrList + [contract], delegateCallList + [isDelegateCall])
            return


    def getRealSender(self, tree, parentAddrList, delegateCallList):
        sender2 = None
        for ii in range(-1, -5, -1):
            if not delegateCallList[ii]:
                sender2 = parentAddrList[ii]
                break
        # if sender1 != sender2:
        #     sys.exit("sender1 != sender2")
        return sender2
    
    def decodeTransferFrom(self, calldata):
        if not calldata.startswith("23b872dd"):
            sys.exit("calldata not start with 23b872dd")
        # Remove the function selector (first 4 bytes)
        data = calldata[8:]
        # Decode the data
        from_address = ('0x' + data[24:64])
        to_address = ('0x' + data[88:128])
        amount = int(data[128:], 16)
        return (from_address, to_address, amount)
    
    def decodeTransfer(self, calldata):
        if not calldata.startswith("a9059cbb"):
            sys.exit("calldata not start with a9059cbb")
        # Remove the function selector (first 4 bytes)
        data = calldata[8:]
        # Decode the data
        to_address = ('0x' + data[24:64])
        amount = int(data[64:], 16)
        return (to_address, amount)

    def traverseTreeToken(self, tree, parentAddrList, delegateCallList):
        if "meta" in tree.info:
            for internalCall in tree.internalCalls:
                self.traverseTreeToken(internalCall, parentAddrList, delegateCallList)
            return
        else:
            contract = tree.info["addr"]
            
            if "msg.value" in tree.info and int(tree.info["msg.value"], 16) != 0:
                receiver = contract
                # if "type" in tree.info and tree.info["type"] == "delegatecall":
                #     print("interesting! delegatecall with msg.value != 0")
                    # sys.exit(1)
                sender = parentAddrList[-1]
                if "type" in tree.info and tree.info["type"] == "delegatecall":
                    sender = self.getRealSender(tree, parentAddrList, delegateCallList)
                
                if sender in self.targetContracts or receiver in self.targetContracts:
                    self.tokenTransfers.append( ("ether", sender, receiver, int(tree.info["msg.value"], 16)) )
            
            # if contract in self.targetContracts:

            # There are cases that the proxy is one of our targetContract but the implementation is not
            for internalCall in tree.internalCalls:
                if "Selector" in internalCall.info:
                    tokenAddr = internalCall.info["addr"]

                    if internalCall.info["Raw calldata"][0:8] == "a9059cbb": # transfer(address,uint256)
                        calldata = internalCall.info["Raw calldata"]
                        (to_address, amount) = self.decodeTransfer(calldata)
                        sender = contract
                        if "type" in tree.info and tree.info["type"] == "delegatecall":
                            sender = parentAddrList[-1]
                        
                        if sender in self.targetContracts or to_address in self.targetContracts:
                            self.tokenTransfers.append( (tokenAddr, sender, to_address, amount) )

                    elif internalCall.info["Raw calldata"][0:8] == "23b872dd": # transferFrom(address,address,uint256)
                        calldata = internalCall.info["Raw calldata"]
                        (from_address, to_address, amount) = self.decodeTransferFrom(calldata)

                        if from_address in self.targetContracts or to_address in self.targetContracts:
                            self.tokenTransfers.append( (tokenAddr, from_address, to_address, amount) )
                
                 
            counter = 0
            if "type" in tree.info and tree.info["type"] == "delegatecall":
                counter += 1
                for delegateCall in delegateCallList[::-1]:
                    if delegateCall:
                        counter += 1
                    else:
                        break
            if counter > 0:
                contract = parentAddrList[- counter]

            isDelegateCall = False
            if "type" in tree.info and tree.info["type"] == "delegatecall":
                isDelegateCall = True

            for internalCall in tree.internalCalls:
                self.traverseTreeToken(internalCall, parentAddrList + [contract], delegateCallList + [isDelegateCall])
            return






def main(benchmark):
    # preparation
    ce = CrawlEtherscan()
    targetContracts = benchmark2targetContracts[benchmark]
    aRecorder = recorder(targetContracts)
    ce = CrawlEtherscan()
    txList = []
    filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract_study/{}/combined.txt".format(benchmark)
    with open (filePath, 'r') as f:
        for line in f:
            entries = line.split(" ")
            Tx = entries[0]
            contracts = entries[1:]
            txList.append(Tx)

    

    countNotCollected = 0
    for ii in range(len(txList)):
        if ii % 100 == 0:
            print("processing {}/{}".format(ii, len(txList)))
        tx = txList[ii]


        block = ce.Tx2Block(tx)
        cachePath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
        # create folder if not exists
        if not os.path.exists(os.path.dirname(cachePath)):
            os.makedirs(os.path.dirname(cachePath))
        cache = {}
        if os.path.exists(cachePath):
            try:
                cache = readJson(cachePath)
            except Exception as e:
                cache = {}
            # if isinstance(cache, dict) and tx in cache:
            #     # print(tx)
            #     # print(cache[tx])
            #     continue
                
            

        jsonGzPath = SCRIPT_DIR + "/../parserPackage/cache/{}_decoded/{}.json.gz".format(benchmark, block)
        if not os.path.exists(jsonGzPath):
            countNotCollected += 1
            # print("{} not exists".format(jsonGzPath))
            # print(tx)
            continue
        else:
            print("exist")
        
        currentTxMapping = {}
        try:
            currentTxMapping = readCompressedJson(jsonGzPath)
        except Exception as e:
            countNotCollected += 1
            print(e)
            continue


        if tx not in currentTxMapping:
            print("tx not in currentTxMapping")
            countNotCollected += 1
            continue
            # # print(tx)
            # sys.exit("tx not in currentTxMapping")
            
        traceTree = currentTxMapping[tx]
        receipt = ce.Tx2Receipt(tx)
        if "status" in receipt:
            status = receipt["status"]
            if not isinstance(status, int):
                status = int(status, 16)
            if status == 0:
                cache[tx] = []
                writeJson(cachePath, cache)
                continue
                
        receipt = ce.Tx2Receipt(tx)
        # print(tx)
        aRecorder.reset()
        aRecorder.benchmark = benchmark
        aRecorder.tx = tx
        aRecorder.block = block
        aRecorder.traverseTree(traceTree, [receipt["from"]], [False])
        aRecorder.traverseTreeToken(traceTree, [receipt["from"]], [False])

        # try:
        #     aRecorder.traverseTree(traceTree, [receipt["from"]], [False])
        #     aRecorder.traverseTreeToken(traceTree, [receipt["from"]], [False])
        # except Exception as e:
        #     print(e)
        #     continue

        for node in aRecorder.functionAccess:
            if len(node) == 2:
                # print(node)
                sys.exit("len(node) == 2")

        cache[tx] = (aRecorder.functionAccess, aRecorder.tokenTransfers)
        writeJson(cachePath, cache)

    print("Overall, {} txs are not collected".format(countNotCollected))




def extract_name(callnode):
    """Extract the name from the callnode tuple."""
    contract, funcName, status, structLogsStart, structLogsEnd, type, storageAccesses = callnode
    return contract[0:6] + "-" + funcName


class callTree:
    def __init__(self, node) -> None:
        self.node = node
        self.children = []
        self.isReEntrancy = False
    
    def addChildren(self, child, depth = 0):
        if depth == 0:
            self.children.append(child)
        else:
            self.children[-1].addChildren(child, depth - 1)

    def add_child(self, child):
        self.children.append(child)

    def toResult(self):
        results = []
        for child in self.children:
            results.append(child.__str__())
        return results

    def toResultStorage(self):
        results = []    
        for child in self.children:
            results.append(child.node[6])
        return results
    
    def __str__(self) -> str:
        returnStr = ""
        returnStr += " <" + extract_name(self.node) + "-start,"
        returnStr += extract_name(self.node) + "-end> "
        return returnStr
    

    

def insert_node(root, node):
    # Try to insert the node in the subtree of root
    inserted = False
    for child in root.children:
        if can_be_parent(child, node):
            if isinstance(node, callTree):
                insert_node(child, node )
            else:
                insert_node(child, callTree(node) )
            inserted = True
            break
    if not inserted:
        # If not inserted in any child, check if it should be a child of root
        if can_be_parent(root, node):
            root.add_child(node)
            # check whether your storageAccesses is a subset of the parent's storageAccesses
            if root.node is not None and root.node[5] != "delegatecall" and root.node[6] != None and node.node[6] != None:
                for contract in node.node[6]:
                    if contract not in root.node[6]:
                        sys.exit("storageAccesses is not a subset of the parent's storageAccesses")
                    for key in node.node[6][contract]:
                        if key not in root.node[6][contract]:
                            sys.exit("storageAccesses is not a subset of the parent's storageAccesses")
                        

        else:
            # Else, it is a sibling of root, to be handled by the caller
            return False
    return True



def can_be_parent(parent, child):
    if parent.node == None:
        return True
    a1, a2 = parent.node[3], parent.node[4]
    b1, b2 = child.node[3], child.node[4]
    return a1 < b1 and a2 > b2



staticcall_functions = []

def sort_callnodes(callnodes):
    """Sort callnodes based on the structLogsStart and structLogsEnd values and handle nested inclusions."""
    sorted_nodes = sorted(callnodes, key=lambda x: (x[3], -x[4]))  # Sort by structLogsStart and descending structLogsEnd for nested inclusions
    root = callTree(None)
    for ii, node in enumerate(sorted_nodes):
        if ii == 0:
            root.addChildren(callTree(node))
            continue
        if not insert_node(root, callTree(node) ):
            new_root = callTree(node)
            if can_be_parent(new_root, root):
                new_root.addChildren(root)
                root = new_root
            else:
                sys.exit("root node is not parent of the new node")
    for child in root.children:
        if child.node[5] == "staticcall":
            key =  [child.node[0], child.node[1]] 
            if key not in staticcall_functions:
                staticcall_functions.append( key )


    # filter out delegateCall
    if pruneReadOnly:
        root.children = [child for child in root.children if child.node[5] != "staticcall"]

    root.children = [child for child in root.children if child.node[5] != "delegatecall"]

    if pruneERC20:
        # if any selector in commonERC20FunctionSelectors in the results, we need to delete that entry
        root.children = [child for child in root.children if child.node[1] not in  commonERC20FunctionSelectors]
    
    return root.toResult(), root.toResultStorage()
            




commonERC20Functions = ["transfer", "transferFrom", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance"]

commonERC20FunctionSelectors = [
    "0xa9059cbb", "0x23b872dd", "0x36c78516", "0x095ea7b3", "0x39509351", "0xa457c2d7"
]



NOTCOLLECTED = -1
REVERTED = -1
NOFUNCACCESS = 0
DEPLOYER = 1
SIMPLE = 2
OTHERDEFI = 3
MEV = 4
USERASSISTED = 5
HACK = 6



def readAndAnalyze(benchmark):
    # iterate all tx in txList:
    txList = []

    filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract_study/{}/combined2.txt".format(benchmark)
    
    isPopular = True
    if "AAVE" not in benchmark and "Lido" not in benchmark and "Uniswap" not in benchmark:
        filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract/{}/combined2.txt".format(benchmark)
        isPopular = False

    studyStartThreshold = 0
    studyEndThreshold = 9999999999999
    uniqueCFWithinRange = []
    if isPopular:
        if benchmark == "AAVE2":
            studyStartThreshold = 19900000
            studyEndThreshold = 999999999999
        elif benchmark == "Lido2":
            studyStartThreshold = 20000000
            studyEndThreshold = 999999999999
        elif benchmark == "Uniswap2":
            studyStartThreshold = 20024000
            studyEndThreshold = 999999999999

            

    with open (filePath, 'r') as f:
        for line in f:
            entries = line.split(" ")
            Tx = entries[0]
            block = entries[1]
            contracts = entries[2:]
            txList.append( (block, Tx) )

    if isPopular:
        txList = txList[-100000: ]

    ce = CrawlEtherscan()

    numberOfContracts = len(benchmark2targetContracts[benchmark])

    targetContracts = benchmark2targetContracts[benchmark]
    deployers = []
    deployedBlocks = []
    for contract in targetContracts:
        deployers.append(ce.Contract2Deployer(contract).lower())
        deployTx = ce.Contract2DeployTx(contract)
        deployBlock = ce.Tx2Block(deployTx)
        deployedBlocks.append(deployBlock)
    
    priviledgedTxs = []
    callFlowMapsForPriviledgedTxs = {}
    simpleTxs = []
    callFlowMapsForSimpleTxs = {}
    anotherProtocolTxs = []
    callFlowMapsForAnotherProtocolTxs = {}
    userTxs = []
    callFlowMapsForUserTxs = {}
    isHackUniqueCF = False

    txlabeler = txLabeler(benchmark)
    
    CFAddedLastestBlocks = 0

    todos = []

    pairs = []

    callFlowMaps = {}
    # collect all control flows:
    for kk, (block, tx) in enumerate(txList):
        tx_category = None
        if True:
            tx_category = txlabeler.label(tx)
            if tx_category == DEPLOYER:
                priviledgedTxs.append(tx)
            elif tx_category == SIMPLE:
                simpleTxs.append(tx)
            elif tx_category == OTHERDEFI:
                anotherProtocolTxs.append(tx)
            elif tx_category == MEV or tx_category == USERASSISTED or tx_category == HACK:
                userTxs.append(tx)

        # print("processing {}/{}".format(kk, len(txList)))            
        block = ce.Tx2Block(tx)
        jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
        if not os.path.exists(jsonGzPath):
            # print("{} not exists".format(jsonGzPath))
            continue
        txResultMapping = readJson(jsonGzPath)
        functionAccess = []
        for txHash in txResultMapping:
            if txHash == tx:
                if len(txResultMapping[txHash]) == 0:
                    functionAccess = []
                else:
                    functionAccess = txResultMapping[txHash][0]
                break

        results, resultStorages = sort_callnodes(functionAccess)

        if pruneReadOnly:
            # remove results that only read but never write
            indexes2Remove = []
            for i in range(len(resultStorages)):
                resultStorage = resultStorages[i]
                isWrite = False
                for contract in resultStorage:
                    for storageAccess in resultStorage[contract]:
                        if storageAccess[0] == "sstore":
                            isWrite = True
                            break
                if not isWrite:
                    indexes2Remove.append(i)
            
            results = [results[i] for i in range(len(results)) if i not in indexes2Remove]
            resultStorages = [resultStorages[i] for i in range(len(resultStorages)) if i not in indexes2Remove]
        
        # if tx in priviledgedTxs:
        #     print("priviledge:", tx, ":", str(results))

        # print(str(results))
        if str(results) == "[]":
            continue

        if pruneTrivialControlFlow:
            if len(results) == 1:
                continue
        
        if not isPopular and tx == benchmark2hack[benchmark]:
            if str(results) not in callFlowMaps:
                isHackUniqueCF = True
                print("hack CF: ", str(results))

        if str(results) not in callFlowMaps:
            if isPopular and int(block) >= studyStartThreshold and int(block) <= studyEndThreshold:
                uniqueCFWithinRange.append( (block,  len(callFlowMaps.keys()) )  )

            pairs.append( (block,  len(callFlowMaps.keys()) )  )
            callFlowMaps[str(results)] = [tx]
        else:
            callFlowMaps[str(results)].append(tx)

        if True:
            if tx in priviledgedTxs:

                if str(results) not in callFlowMapsForPriviledgedTxs:
                    callFlowMapsForPriviledgedTxs[str(results)] = [tx]
                else:
                    callFlowMapsForPriviledgedTxs[str(results)].append(tx)
            elif tx in simpleTxs:
                if str(results) not in callFlowMapsForSimpleTxs:
                    callFlowMapsForSimpleTxs[str(results)] = [tx]
                else:
                    callFlowMapsForSimpleTxs[str(results)].append(tx)
            elif tx in anotherProtocolTxs:
                if str(results) not in callFlowMapsForAnotherProtocolTxs:
                    callFlowMapsForAnotherProtocolTxs[str(results)] = [tx]
                else:
                    callFlowMapsForAnotherProtocolTxs[str(results)].append(tx)
            elif tx in userTxs:
                if str(results) not in callFlowMapsForUserTxs:
                    callFlowMapsForUserTxs[str(results)] = [tx]
                else:
                    callFlowMapsForUserTxs[str(results)].append(tx)


    
        
    
    # sort the callFlowMaps
    sortedCallFlowMaps = sorted(callFlowMaps.items(), key=lambda x: len(x[1]), reverse=True)

    noFunctionCallCount = 0
    simpleFunctionCallCount = 0 
    complicatedFunctionCallCount = 0

    uniqueTraceCount = len(sortedCallFlowMaps)
    uniqueComplicatedTrace = {}
    for key, value in sortedCallFlowMaps:
        if key.count("-start") < 1 and key.count("-end") < 1:
            noFunctionCallCount += len(value)

        elif key.count("-start") == 1 and key.count("-end") == 1:
            simpleFunctionCallCount += len(value)

        elif key.count("-start") > 1 and key.count("-end") > 1:
            complicatedFunctionCallCount += len(value)
            for tx in value:
                receipt = ce.Tx2Receipt(tx)
                to = receipt["to"]
                # if to not in tos:
                #     tos.append(to)
                if tx not in todos:
                    todos.append(tx)
        else:
            sys.exit("unknown key: {}".format(key))


    print("============== Summary ==============")
    print("txs with no Function Call Count (with ERC20 function removed): ", noFunctionCallCount)
    print("txs with 1 simple Function Call Count (with ERC20 function removed): ", simpleFunctionCallCount)
    print("txs with more than 1 Function Call Count: ", complicatedFunctionCallCount)
    print("# unique control flow: ", uniqueTraceCount)
    # print("# unique control flow with more than 1 function call: ", len(uniqueComplicatedTrace.keys()))
    print("=====================================")

    if isPopular:
        print("====== Study Stats ======")
        print("from block {} to block {}".format(studyStartThreshold, uniqueCFWithinRange[-1][0]))
        print("unique control flows within the range: ", len(uniqueCFWithinRange))
    
    # priviledgedTxs = []
    # callFlowMapsForPriviledgedTxs = {}
    # simpleTxs = []
    # callFlowMapsForSimpleTxs = {}
    # anotherProtocolTxs = []
    # callFlowMapsForAnotherProtocolTxs = {}
    # userTxs = []
    # callFlowMapsForUserTxs = {}

    hackMark = "\\cmark" if isHackUniqueCF else "\\xmark" 

    stats = [  numberOfContracts, min(deployedBlocks), max(deployedBlocks), len(txList), len(callFlowMaps.keys()), \
                len(priviledgedTxs), len(callFlowMapsForPriviledgedTxs.keys()), \
                len(simpleTxs), len(callFlowMapsForSimpleTxs.keys()), \
                len(anotherProtocolTxs), len(callFlowMapsForAnotherProtocolTxs.keys()), \
                len(userTxs), len(callFlowMapsForUserTxs.keys()), hackMark ]

    return pairs, sortedCallFlowMaps, stats

# Also return stats:
# # Contracts, Block Range, # Txs, 
# # Priviledged Txs, # Control Flow, 
# # Another Protocol, # Control Flow,  
# # User Tx, # Control Flow
    # numberOfContracts
    # deployedBlocks


    # directly from deployers
    # a router contract of same protocol
    # MEV transactions
        



def plot_pareto_chart(event_dict, file_path, benchmark):
    # Convert the dictionary to a pandas DataFrame
    df = pd.DataFrame(list(event_dict.items()), columns=['Event', 'Frequency'])
    # Sort the DataFrame by frequency in descending order
    df = df.sort_values('Frequency', ascending=False)
    # Calculate the cumulative percentage
    df['Cumulative Percentage'] = df['Frequency'].cumsum() / df['Frequency'].sum() * 100
    # Convert indices to a numpy array for plotting
    indices = np.arange(len(df))
    # Prepare the plot with the same height as save_plot
    fig, ax1 = plt.subplots(figsize=(8, 4))  # Width 8, Height 4 (same as save_plot)
    # Determine which bars to highlight
    highlight_keys = []
    for key in event_dict:
        if key.count("-start") <= 1 and key.count("-end") <= 1:
            highlight_keys.append(key)
    # Highlight colors
    bar_colors = ['C0' if event not in highlight_keys else 'C1' for event in df['Event']]
    # Bar plot for frequencies with exponential y-axis
    ax1.bar(df.index, df['Frequency'], color=bar_colors)
    ax1.set_ylabel('Frequency', color='C0')
    ax1.set_yscale('log')  # Set the y-axis to logarithmic scale
    ax1.tick_params(axis='y', labelcolor='C0')
    # Line plot for cumulative percentage
    ax2 = ax1.twinx()
    # Adjusted marker size and color (smaller and using 'C3')
    ax2.plot(indices, df['Cumulative Percentage'].values, color='C3', marker='o', linestyle='--', markersize=4)
    ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}%'))
    ax2.set_ylabel('Cumulative Percentage', color='C3')
    ax2.tick_params(axis='y', labelcolor='C3')
    # Remove x-axis labels
    ax1.set_xticks(indices)
    ax1.set_xticklabels([])
    # Show a grid for the cumulative percentage plot
    ax2.grid(False)
    # Update the title
    plt.title('Pareto Chart of Control Flow Frequency for {}'.format(benchmark))
    # Increase the font sizes for labels and title to match the other plot
    ax1.set_ylabel('Frequency', fontsize=12)
    ax2.set_ylabel('Cumulative Percentage', fontsize=12)
    plt.title('Pareto Chart of Control Flow Frequency for {}'.format(benchmark), fontsize=14)
    plt.tight_layout()
    # Save the plot to the specified file path
    plt.savefig(file_path.replace('.png', '.pdf'), bbox_inches='tight', format='pdf')
    plt.close()



def save_plot(pairs, file_path, benchmark):
    # Unzip the list of pairs into two separate lists: x and y
    x, y = zip(*pairs)
    # Create a scatter plot for all points with smaller markers and blue color
    plt.scatter(x, y, color='blue', marker='o', s=20)
    # Connect data points with lines
    plt.plot(x, y, color='blue', linewidth=1)
    # Label the axes
    # plt.xlabel('blocks', fontsize=12, horizontalalignment='right')  # Adjust label alignment
    plt.ylabel('Cumulative # Unqiue Control Flows', fontsize=12)
    # Set a title for the plot
    plt.title('Cumulative # Unique Control Flows vs. Blocks for {}'.format(benchmark), fontsize=14)
    # Adjust the figure to be more rectangular
    plt.gcf().set_size_inches(8, 4)  # Width 8, Height 4
    # Disable scientific notation on the x-axis
    plt.ticklabel_format(style='plain', axis='x')
    # # Add a legend
    # plt.legend()
    # Save the plot to the specified file path
    plt.savefig(file_path.replace('.png', '.pdf'), bbox_inches='tight', format='pdf')
    # Close the plot to release resources
    plt.close()




if __name__ == "__main__":

    pruneReadOnly = True
    pruneERC20 = True

    # ifPrint = True when working on None(originally RQ1 before ICSE), when we set pruneTrivialControlFlow = False
    # ifPrint = False when working on RQ2(originally RQ3), when we set pruneTrivialControlFlow = True

    pruneTrivialControlFlow = True
    isPrint = False

    todoss = []
    listBenchmark = [
        # "bZx2",        
        # "Warp_interface",
        # "CheeseBank_1",
        # "InverseFi",
        # "CreamFi1_1",
        # "CreamFi2_4",
        # "RariCapital1",
        # "RariCapital2_3",
        # "XCarnival",
        # "Harvest1_fUSDT",
        # "ValueDeFi",
        # "Yearn1_interface",
        # "VisorFi",
        # "UmbrellaNetwork",
        # "PickleFi",
        # "Eminence",
        # "Opyn",
        # "IndexFi",
        # "RevestFi",
        # "DODO",
        # "Punk_1",
        # "BeanstalkFarms_interface",


        "DoughFina",  
        "Bedrock_DeFi",  
        "OnyxDAO",
        "BlueberryProtocol",
        "PrismaFi",
        "PikeFinance",
        "GFOX", 
        "UwULend",


        # "AAVE2", \
        # "Lido2", \
        # "Uniswap2"
    ]

    temp = []
    # "AAVE2": 44 txs not collected or somehow corrupted
    # "Lido2": 134 txs not collected or somehow corrupted
    # "Uniswap2": 1 txs not collected or somehow corrupted
    for benchmark in listBenchmark:
        print("benchmark: ", benchmark)
        # main(benchmark)
        pairs, sortedCallFlowMaps, stats = readAndAnalyze(benchmark)
        temp.append( (benchmark, stats) )

        if isPrint:
            SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
            folderPath = SCRIPT_DIR + "/figures11_finalized_0103/"
            if not os.path.exists(folderPath):
                os.makedirs(folderPath)
            filePath = folderPath + "{}.png".format(benchmark)
            if len(pairs) > 0:
                save_plot(pairs, filePath, benchmark[:-1])
                
            filePath = folderPath + "{}_pareto.png".format(benchmark)
            event_dict = {}
            for key, value in sortedCallFlowMaps:
                if key != "[]":
                    event_dict[key] = len(value)

            if len(event_dict) > 0:
                # print top 10
                for key, value in list(event_dict.items())[:10]:
                    print(key, value)
                plot_pareto_chart(event_dict, filePath, benchmark[:-1])



    # stats = [  numberOfContracts, min(deployedBlocks), max(deployedBlocks), len(txList), len(callFlowMaps.keys()), \
    #             len(priviledgedTxs), len(callFlowMapsForPriviledgedTxs.keys()), \
    #             len(simpleTxs), len(callFlowMapsForSimpleTxs.keys()), \
    #             len(anotherProtocolTxs), len(callFlowMapsForAnotherProtocolTxs.keys()), \
    #             len(userTxs), len(callFlowMapsForUserTxs.keys()), hackMark ]
    
    for entry in temp:
        print(entry[0], ";", end = "")
        print(entry[1][0], ";", entry[1][1], "-", entry[1][2], ";", entry[1][3], ";", end = "")
        
        for ii in range(4, len(entry[1])):
            print(entry[1][ii], ";", end = "")

        print("")