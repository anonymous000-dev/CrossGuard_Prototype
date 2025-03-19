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



def extract_name(callnode):
    """Extract the name from the callnode tuple."""
    contract, funcName, status, structLogsStart, structLogsEnd, type, storageAccesses = callnode
    return contract[0:6] + "-" + funcName


reEntrancyName = ["flashBorrowToken", "flashLoan", \
    "0xd065-borrow", "0xeb7e-borrow", "0x2db6-borrow", \
    "0x77f9-0x66fa576f", "0xc9f2-deposit"]

delagateContracts = [
    "0x7d8bb0dcfb4f20115883050f45b517459735181b",
    "0xb849daff8045fc295af2f6b4e27874914b5911c6",
    "0x9b3be0cc5dd26fd0254088d03d8206792715588b",
    "0x5bd628141c62a901e0a83e630ce5fafa95bbdee4",
]


reEntrancyFunctions = []

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
    
    def toResultGas(self):
        results = []
        for child in self.children:
            results.append(child.estimateExtraGas())
        return results
    
    def toResultStorage(self):
        results = []    
        for child in self.children:
            results.append(child.node[6])
        return results
    
    
    def __str__(self) -> str:
        returnStr = ""
        isReEntrancy = False
        for name in reEntrancyName:
            if name in extract_name(self.node):
                isReEntrancy = True
                self.isReEntrancy = True

                key = [self.node[0], self.node[1]]
                if key not in reEntrancyFunctions:
                    reEntrancyFunctions.append(key)
                break

        returnStr += " <" + extract_name(self.node) + "-start,"
        if isReEntrancy:
            for child in self.children:
                func = child.node[0] + "-" + child.node[1]

                func0 = self.node[0] + "-" + self.node[1]
                if func0 in arbitrary_external_call and func in arbitrary_external_call[func0]:
                    pass
                else:
                    returnStr += str(child)

        returnStr += extract_name(self.node) + "-end> "

        return returnStr
    
    def estimateExtraGas(self):
        extraGas = 0
        isReEntrancy = False
        for name in reEntrancyName:
            if name in extract_name(self.node):
                isReEntrancy = True
                break
        extraGas += gasConsumption["functionEntry"] + gasConsumption["functionExit"]
        if isReEntrancy:
            for child in self.children:
                extraGas += child.estimateExtraGas()

        return extraGas
    
def can_be_parent(parent, child):
    if parent.node == None:
        return True
    a1, a2 = parent.node[3], parent.node[4]
    b1, b2 = child.node[3], child.node[4]
    return a1 < b1 and a2 > b2

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
        if "sload/sstore" in tree.info:
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





knownTxsNotCollected = [
    "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec",
    "0x52a0541deff2373e1098881998b60af4175d75c410d67c86fcee850b23e61fc2",
    "0xca13006944e6eba2ccee0b2d96a131204491641014622ef2a3df3db3e6939062",
    "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec",
    "0x9ef7a35012286fef17da12624aa124ebc785d9e7621e1fd538550d1209eb9f7d",
    "0xd770356649f1e60e7342713d483bd8946f967e544db639bd056dfccc8d534d8e",
    "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec"
]

commonERC20Functions = ["transfer", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance"]

def main(benchmark):
    # preparation
    ce = CrawlEtherscan()
    targetContracts = benchmark2targetContracts[benchmark]
    aRecorder = recorder(targetContracts)
    ce = CrawlEtherscan()
    txList = []
    filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract/{}/combined.txt".format(benchmark)

    isPopular = False
    if "AAVE" in benchmark or "Lido" in benchmark or "Uniswap" in benchmark:
        filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract_study/{}/combined2.txt".format(benchmark)
        isPopular = True

    with open (filePath, 'r') as f:
        for line in f:
            entries = line.split(" ")
            Tx = entries[0]
            contracts = entries[1:]
            txList.append(Tx)

    if isPopular:
        txList = txList[-100000: ]
        
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
            if isinstance(cache, dict) and tx in cache:
                continue

        jsonGzPath = SCRIPT_DIR + "/../parserPackage/cache/{}/{}.json.gz".format(benchmark, block)
        if not os.path.exists(jsonGzPath):
            if tx in knownTxsNotCollected:
                continue
            else:
                print("{} not exists".format(jsonGzPath))
                print(tx)
                continue
        currentTxMapping = readCompressedJson(jsonGzPath)

        if tx not in currentTxMapping:
            # print(tx)
            print("tx not in currentTxMapping")
            continue
            
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






staticcall_functions = []

complementary_functions_nonReadOnly2ReadOnly = []

complementary_functions_close_source = []

complementary_functions_readOnlySideEffect = []


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

    len1 = len(root.children)

    for child in root.children:
        if child.node[5] == "staticcall":
            key =  [child.node[0], child.node[1]] 
            if key not in staticcall_functions:
                staticcall_functions.append( key )
        

    # filter out staticcalls
    root.children = [child for child in root.children if child.node[5] != "staticcall"]

    len2 = len(root.children)
    # root.children = [child for child in root.children if child.node[0] not in delagateContracts]
    # len3 = len(root.children)
    root.children = [child for child in root.children if child.node[5] != "delegatecall" and child.node[0] not in delagateContracts]
    len4 = len(root.children)
    # if len3 != len4:
    #     print("delegatecall is removed")

    return root.toResult(), root.toResultGas(), root.toResultStorage()
            
     



# a few macro labels: 
# 0: potential arbitrary external call
# 1: read-only [in Solidity code] x, this part we can ignore, it is the most correct one
# 2. read-only, by reasoning about the bytecode (no sstore)
# 3. read-only like, one branch is read-only, the other is not 
#           (for these functions we also need to check their runtime behavior)
#           Assumption: one branch with only read operations, another branch with write operations, we can simply insert guard on read operations.
#           Assumption: not all executions will collect interest
#           
# 4. which two functions are behaving having RAW dependency and which functions are bahaving without 
# 5. common ERC20 operations ... this is ignored ... very hard to say ... how to make sense of this?
#    ==> the way to make sense of it: 


potential_reentrancy_guard = []

read_after_write_no_dependency_functions = {}

simple_txs_to_simple_function = {}

ERC20Functions = []

def readAndAnalyze(benchmark):
    ##########################################################################
    ################### Step 1: Classification 
    ##########################################################################
    c = classifier()
    # preparation
    ce = CrawlEtherscan()
    targetContracts = benchmark2targetContracts[benchmark]
    hack = benchmark2hack[benchmark]
    # categories given by the classifier
    # -1 represents not collected
    categoryCounts = {-1: [], 0: [], 1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
    # collect deployers of the target contracts
    # Whitelist Policy 1: txs initiated by deployers can be considered as benign
    deployers = set()
    for contract in targetContracts:
        deployer = ce.Contract2Deployer(contract)
        deployers.add(deployer)
    # iterate all tx in txList:
    txList = []
    filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract/{}/combined.txt".format(benchmark)
    with open (filePath, 'r') as f:
        for line in f:
            entries = line.split(" ")
            Tx = entries[0]
            contracts = entries[1:]
            txList.append(Tx)

    
    an = Analyzer()
    contractSelector2functions = {}

    for tx in txList:
        block = ce.Tx2Block(tx)
        receipt = ce.Tx2Receipt(tx)
        to = receipt["to"]
        status = receipt["status"]
        if not isinstance(status, int):
            status = int(status, 16)
        if status == 0:
            categoryCounts[-1].append(tx)
            tx_category = -1
            continue

        if to is None:
            to = receipt["contractAddress"]
        if to is None:
            sys.exit("to is None")
        tx_category = None

        # Category -1: Reverted
        if tx in revertedTransactions:
            categoryCounts[-1].append(tx)
            tx_category = -1
            continue
        
        # Category 2: Simple Transactions, directly sent from one of the functions of router contracts
        if to in targetContracts:
            tx_category = 2

        # Category X: if we have classified the contract
        category = c.benchmark_contract2Category(benchmark, to)
        if category != None:
            if category.lower() == "hack":
                tx_category = 6
            else:
                tx_category = int(category)
        
        if tx_category == 2 and receipt["to"] != None:
            _selector = receipt["input"][0:10]
            _contract = receipt["to"]
            if _contract not in contractSelector2functions:
                contractSelector2functions[_contract] = an.contract2funcSigMap(_contract)

            sig = None
            if _selector in contractSelector2functions[_contract]:
                sig = contractSelector2functions[_contract][_selector]
            else:
                sig = ""

            key = _contract + "-" + _selector + "-" + str(sig)
            
            if key not in simple_txs_to_simple_function:
                simple_txs_to_simple_function[key] = [ tx ]
            else:
                simple_txs_to_simple_function[key].append(tx)

        
        # Category 1: Transactions from deployers
        details = ce.Tx2Details(tx)
        if "from" in details and details["from"] in deployers:
            tx_category = 1
        if tx == hack:
            tx_category = 6

        jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
        if not os.path.exists(jsonGzPath):
            if tx in knownTxsNotCollected:
                categoryCounts[-1].append(tx)
                continue
            else:
                print("{} not exists".format(jsonGzPath))
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

        if len(functionAccess) == 0:
            tx_category = 0

        if tx_category == None:
            print(functionAccess)
            print("tx_category is None for tx ", tx)
            continue
        categoryCounts[tx_category].append(tx)

    print("Category Counts: ")
    print("No Func Access: ", len(categoryCounts[0]))
    print("Deployer Transaction: ", len(categoryCounts[1]))
    print("Simple Txs to Simple Protocol: ", len(categoryCounts[2]))
    print("Another Famous DeFi Protocol: ", len(categoryCounts[3]))
    print("User-assisted Contract (4 + 5 + 6): ", len(categoryCounts[4]) + len(categoryCounts[5]) + len(categoryCounts[6]))
    print("all classified tx: ", sum(len(v) for v in categoryCounts.values()), "/", len(txList))




    ##########################################################################
    ################### Step 2: Call Flow Analysis
    ##########################################################################

    # Above we have classified the tx, now we need to do the call flow analysis
    an = Analyzer()
    for contract in targetContracts:
        funcSigMap2 = an.contract2funcSigMap(contract)
        contractSelector2functions[contract] = funcSigMap2

    # # For complementary functions
    # for contract in complementary:
    #     for selector in complementary[contract]:
    #         if contract not in contractSelector2functions:
    #             contractSelector2functions[contract] = {}
    #         contractSelector2functions[contract][selector] = complementary[contract][selector]

    temp = []

    callFlowMap = {0: {}, 1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {}}
    callFlowExampleMaps = {0: {}, 1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {}}
    for tx_category in categoryCounts:
        if tx_category == -1 or tx_category == 0 or tx_category == 1 or tx_category == 2:
            continue
        
        for tx in categoryCounts[tx_category]:

            block = ce.Tx2Block(tx)
            jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
            if not os.path.exists(jsonGzPath):
                if tx in knownTxsNotCollected:
                    categoryCounts[-1].append(tx)
                    continue
                else:
                    print("{} not exists".format(jsonGzPath))
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

            functionAccess2 = []

            # convert selector to function name
            for node in functionAccess:
                contract = node[0]
                selector = node[1]

                if len(node) == 2:
                    sys.exit("len(node) == 2")

                funcName = selector

                isReadOnly = False
                if funcName.startswith("0x"):
                    if contract in complementary and selector in complementary[contract] and len(complementary[contract][selector]) == 3:
                        node[1] = complementary[contract][selector][0] + "-" + selector
                        funcName = complementary[contract][selector][0]
                        key = [contract, funcName, selector]
                        complementary_functions_readOnlySideEffect.append(key)
                        isReadOnly = True
                        ifPrint = False
                        # check sstore
                        for address in node[6]:
                            # delete re-entrancy sload and sstore from node[6]
                            temp = []
                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]
                                if address in reEntrancyGuard and slot in reEntrancyGuard[address]:
                                    continue
                                else:
                                    temp.append(node[6][address][ii])
                            node[6][address] = temp

                            set0x0 = []
                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]
                                if opcode == "sstore" and value == "0x0":
                                    set0x0.append(slot)
                                if opcode == "sstore" and value == "0x1":
                                    if slot in set0x0 and address not in potential_reentrancy_guard:
                                        print("Potential re-entrancy guard", key, "in", tx)
                                        potential_reentrancy_guard.append(address)
                                        break
                                
                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]
                                isReadOnly = False
                                # if opcode == "sstore" and not (address in reEntrancyGuard and slot in reEntrancyGuard[address]):
                                #     isReadOnly = False
                                #     if not ifPrint:
                                #         print("Encounter one read-only alike function", key, "in", tx)
                                #         ifPrint = True
                                #     print("\t", opcode, address, slot, value)


                        isAllAllMatches = True
                        numberOfSstores = 0
                        for address in node[6]:
                            # search for the obvious re-entrancy pattern
                            # contains two sstore, one set it to 0x0 and later set it to 0x1
                            firstSloads = {}
                            lastSstores = {}

                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]
                                if opcode == "sload" and slot not in firstSloads:
                                    firstSloads[slot] = value
                                elif opcode == "sstore":
                                    lastSstores[slot] = value
                                    numberOfSstores += 1
                                
                            # check whether all lastSstores are in firstSloads and be equal 
                            for slot in lastSstores:                                    
                                if slot not in firstSloads or firstSloads[slot] != lastSstores[slot]:
                                    isAllAllMatches = False
                        
                        if isAllAllMatches and not isReadOnly:
                            isReadOnly = True

   

                    elif contract in contractSelector2functions and selector not in contractSelector2functions[contract] and contract in complementary and selector not in complementary[contract]:
                        node[1] = selector
                        funcName = selector

                        if node[5] == "staticcall":
                            print("a potential staticcall function")
                            print("contract: ", contract)
                            print("selector: ", selector)

                        # node[1] = complementary[contract][selector][0] + "-" + selector
                        # funcName = complementary[contract][selector][0]
                        key = [contract, funcName, selector]
                        complementary_functions_readOnlySideEffect.append(key)
                        isReadOnly = True
                        # check sstore
                        for address in node[6]:
                            # delete re-entrancy sload and sstore from node[6]
                            temp = []
                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]
                                if address in reEntrancyGuard and slot in reEntrancyGuard[address]:
                                    continue
                                else:
                                    temp.append(node[6][address][ii])
                            node[6][address] = temp
                                
                            for ii in range(len(node[6][address])):
                                opcode = node[6][address][ii][0]
                                slot = node[6][address][ii][1]
                                value = node[6][address][ii][2]

                                isReadOnly = False

                                # if opcode == "sstore" and not (address in reEntrancyGuard and slot in reEntrancyGuard[address]):
                                #     isReadOnly = False
                                #     if not ifPrint:
                                #         print("Encounter one read-only alike function", key, "in", tx)
                                #         ifPrint = True
                                #     print("\t", opcode, address, slot, value)

                                    



                    elif contract in contractSelector2functions and selector not in contractSelector2functions[contract] and contract in complementary and selector not in complementary[contract]:
                        node[1] = selector
                        funcName = selector
                        # these functions are not that important, as they 
                        # are not the first function called, instead, they are internal function calls
                        # key = [contract, funcName, selector]
                        # if key not in temp:
                        #     temp.append(key)
                        #     print("contract in contractSelector2functions and selector not in contractSelector2functions[contract]")
                        #     print("tx: ", tx)
                        #     print("contract: ", contract)
                        #     print("selector: ", selector
                    elif contract in contractSelector2functions and selector in contractSelector2functions[contract] and contract in complementary and selector in complementary[contract]:
                        node[1] = complementary[contract][selector][0] + "-" + selector
                        funcName = complementary[contract][selector][0]
                        if complementary[contract][selector][3]:
                            isReadOnly = True

                        if complementary[contract][selector][3] != contractSelector2functions[contract][selector][3]:
                            if  complementary[contract][selector][3] and not contractSelector2functions[contract][selector][3]:
                                # normal
                                key = [contract, funcName, selector, complementary[contract][selector][3]]
                                if key not in complementary_functions_nonReadOnly2ReadOnly:
                                    complementary_functions_nonReadOnly2ReadOnly.append(key)
                            else:
                                sys.exit("complementary[contract][selector][3] != contractSelector2functions[contract][3]")
                    
                    elif contract in contractSelector2functions and selector not in contractSelector2functions[contract] and contract in complementary and selector in complementary[contract]:
                        node[1] = complementary[contract][selector][0] + "-" + selector
                        funcName = complementary[contract][selector][0]
                        if complementary[contract][selector][3]:
                            isReadOnly = True                        
                        
                        key = [contract, funcName, selector, complementary[contract][selector][3]]
                        if key not in complementary_functions_close_source:
                            complementary_functions_close_source.append(key)
                    else:
                        if contract not in contractSelector2functions or selector not in contractSelector2functions[contract]:
                            print("tx: ", tx)
                            print("contract: ", contract)
                            print("selector: ", selector)
                        else:
                            node[1] = contractSelector2functions[contract][selector][0] + "-" + selector
                            funcName = contractSelector2functions[contract][selector][0]
                            if contractSelector2functions[contract][selector][3]:
                                isReadOnly = True



                elif funcName == "fallback":
                    selector = "0x552079dc"
                    if contract in contractSelector2functions and selector in contractSelector2functions[contract]:
                        if contractSelector2functions[contract][selector][3]:
                            isReadOnly = True
                    elif contract in complementary and selector in complementary[contract]:
                        if complementary[contract][selector][3]:
                            isReadOnly = True

                        key = [contract, "fallback", "0x", complementary[contract][selector][3]]
                        complementary_functions_close_source.append(key)
                    else:
                        sys.exit("fallback not in contractSelector2functions[contract] and not in complementary[contract]")
                    

                # prune 1: discard the read-only functions
                # prune 2: discard the common ERC20 functions
                if not isReadOnly:
                    if funcName not in commonERC20Functions:
                        functionAccess2.append(node)
                    else:
                        contract = node[0]
                        funName = node[1] + "-" + selector
                        key = [contract, funName]
                        if key not in ERC20Functions:
                            ERC20Functions.append(key)


            functionAccess = copy.deepcopy(functionAccess2)
            
            len1 = len(staticcall_functions)
            results, resultGas, resultStorages = sort_callnodes(functionAccess)
            len2 = len(staticcall_functions)
            if len2 != len1:
                print("staticcall_functions is updated at tx ", tx)
            
            if len(results) != len(resultStorages):
                sys.exit("results and resultStorages have different lengths")

            if len(results) == 1:
                # get the full name:
                # <0x051e-sellBase-start,0x051e-sellBase-end>
                contractStart = results[0].split("-")[0]
                contractStart = contractStart[2:]
                funcName = results[0].split("-")[1].split("-")[0]
                for contract, func, _, _, _, _, _ in functionAccess:
                    if contract.startswith(contractStart) and func == funcName:
                        key = contract + "-" + func
                        if key not in simple_txs_to_simple_function:
                            simple_txs_to_simple_function[key] = [tx]
                        else:
                            simple_txs_to_simple_function[key].append(tx)
                        break


            # Prune Hard: Read-After-Write. 
            if len(results) > 1:
                # first we need to identify read and write operations
                resultsStorageReads = []
                resultsStorageWrites = []
                for resultStorage in resultStorages:
                    resultsStorageReads.append({})
                    resultsStorageWrites.append({})
                    for contract in resultStorage:
                        for storageAccess in resultStorage[contract]:
                            key = contract + "-" + storageAccess[1]
                            if storageAccess[0] == "sload":
                                resultsStorageReads[-1][key] = 1
                            else:
                                resultsStorageWrites[-1][key] = 1

                rawTree = RAWTree(resultsStorageReads, resultsStorageWrites)
                
                isReadAfterWriteOnce = False  # at least one action is reading some states that are written by previous actions
                for i in range(1, len(results)):
                    currentStorageReads = resultsStorageReads[i]
                    for j in range(0, i):
                        previousStorageWrites = resultsStorageWrites[j]
                        for key in previousStorageWrites:
                            if key in currentStorageReads:
                                isReadAfterWriteOnce = True
                                break
                        if isReadAfterWriteOnce:
                            break
                    if isReadAfterWriteOnce:
                        break

                if isReadAfterWriteOnce != rawTree.isReadAfterWriteOnce():
                    print("isReadAfterWriteOnce is not consistent")
                    rawTree.isReadAfterWriteOnce()
                    sys.exit("isReadAfterWriteOnce is not consistent")


                if not isReadAfterWriteOnce:
                    if str(results) not in read_after_write_no_dependency_functions:
                        read_after_write_no_dependency_functions[str(results)] = [tx]
                    else:
                        read_after_write_no_dependency_functions[str(results)].append(tx)
                    continue
            
                
                # # ignore pruning for now
                # if len(results) == 0:
                #     continue
                # elif len(results) == 1 and (results[0].count("-start") == 1 and results[0].count("-end") == 1) :
                #     continue
                # elif "constructor" in str(results):
                #     continue

                callFlow = str(results)
                # if (tx_category == 4 or tx_category == 5 or tx_category == 6) and len(results) == 0:
                #     print("now is the time")

                print("catgeory", tx_category, "tx:", tx) 
                print(callFlow)

                if callFlow not in callFlowMap[tx_category]:
                    callFlowMap[tx_category][callFlow] = 1
                else:
                    callFlowMap[tx_category][callFlow] += 1
                
                if callFlow not in callFlowExampleMaps[tx_category]:
                    callFlowExampleMaps[tx_category][callFlow] = (to, tx)




    falsePositives = 0
    falsePositivesAppproval = []

    print(" == Another Famous DeFi Protocol Call Flows: ")
    Asorted = {k: v for k, v in sorted(callFlowMap[3].items(), key=lambda item: item[1], reverse=True)}
    
    for callFlow in Asorted:
        if callFlow.count("-start") <= 1 and callFlow.count("-end") <= 1:
            continue
        print(callFlow, Asorted[callFlow])

        falsePositives += Asorted[callFlow]
        if callFlow not in falsePositivesAppproval:
            falsePositivesAppproval.append(callFlow)

        print(callFlowExampleMaps[3][callFlow])

    print(" == User-assisted Contract Call Flows: ")
    # merge 4, 5
    temp = {}
    for callFlow in callFlowMap[4]:
        if callFlow not in temp:
            temp[callFlow] = callFlowMap[4][callFlow]
        else:
            temp[callFlow] += callFlowMap[4][callFlow]

    for callFlow in callFlowMap[5]:
        if callFlow not in temp:
            temp[callFlow] = callFlowMap[5][callFlow]
        else:
            temp[callFlow] += callFlowMap[5][callFlow]

    Asorted = {k: v for k, v in sorted(temp.items(), key=lambda item: item[1], reverse=True)}
    for callFlow in Asorted:
        if callFlow.count("-start") <= 1 and callFlow.count("-end") <= 1:
            continue
        print(callFlow, Asorted[callFlow])

        if callFlow != "[]":
            falsePositives += Asorted[callFlow]
            if callFlow not in falsePositivesAppproval:
                falsePositivesAppproval.append(callFlow)

        if callFlow in callFlowExampleMaps[4]:
            print(callFlowExampleMaps[4][callFlow])
        else:
            print(callFlowExampleMaps[5][callFlow])

    print(" == Hack Call Flows: ")
    for callFlow in callFlowMap[6]:
        if callFlow.count("-start") <= 1 and callFlow.count("-end") <= 1:
            continue
        print(callFlow, callFlowMap[6][callFlow])
        print(callFlowExampleMaps[6][callFlow])


    #     isHack = False
    #     if tx == hack:
    #         # print("now is the time")
    #         isHack = True
    #         pass
    
    print("False positives: ", falsePositives, " out of ", len(txList) - len(categoryCounts[-1]) - len(categoryCounts[0]))

    print("False positive ratio", falsePositives / ( len(txList) - len(categoryCounts[-1]) - len(categoryCounts[0]) ) * 100, "%")

    print("False positive after user approval ", len(falsePositivesAppproval) / ( len(txList) - len(categoryCounts[-1]) - len(categoryCounts[0]) ) * 100, "%")







        

if __name__ == "__main__":
    listBenchmark = [
        # "DODO",  # Easy
        # "Opyn",  # Easy
        # "PickleFi",  # Easy
        # "Punk_1",  # Easy
        # "Harvest1_fUSDT", # Easy
        # "Eminence", # Easy
        # "CheeseBank_1", # Easy
        # "RevestFi", # Easy
        # "VisorFi", # Easy
        # "BeanstalkFarms_interface", # Easy
        # "ValueDeFi", # Easy
        # "XCarnival", # Easy
        # "Warp_interface", # Easy

        # "IndexFi", # Medium
        # "RariCapital1", # Medium
        # "Yearn1_interface", # Medium
        # "InverseFi", # Medium

        # # "bZx2", # a lot of routers on top of main functions # Hard
        # "CreamFi1_1", # Hard
        # # "RariCapital2_3", # Hard
        # "CreamFi2_4" # Hard

        # "UmbrellaNetwork"

        # "AAVE2", \
        # "Lido2", \
        # "Uniswap2"

        "DoughFina", 
        "Bedrock_DeFi",
        "OnyxDAO",
        "BlueberryProtocol",
        "PrismaFi",
        "PikeFinance",
        "GFOX",
        "UwULend"


    ]


    
    for benchmark in listBenchmark:

        staticcall_functions = []
        complementary_functions_nonReadOnly2ReadOnly = []
        complementary_functions_close_source = []
        potential_reentrancy_guard = []
        read_after_write_no_dependency_functions = {}
        ERC20Functions = []
        reEntrancyFunctions = []

        simple_txs_to_simple_function = {}

        # if benchmark != "CreamFi1_1":
        #     continue
        print("\n\n\n\nbenchmark: ", benchmark)
        main(benchmark)
        # readAndAnalyze(benchmark)


        # # for stringstring in string_collect:
        # #     print(stringstring)

        # print("staticcall_functions")
        # for key in staticcall_functions:
        #     print(key)    

        # print("")
        # print("complementary_functions_nonReadOnly2ReadOnly")
        # for key in complementary_functions_nonReadOnly2ReadOnly:
        #     print(key)

        # print("")
        # print("complementary_functions_close_source")
        # for key in complementary_functions_close_source:
        #     print(key)

        # print("")
        # print("potential_reentrancy_guard")
        # for key in potential_reentrancy_guard:
        #     if key not in reEntrancyGuard:
        #         print(key)
        
        # print("")
        # print("read_after_write_no_dependency_functions")
        # for key in read_after_write_no_dependency_functions:
        #     print(key, len(read_after_write_no_dependency_functions[key]), read_after_write_no_dependency_functions[key])
        
        # print("")
        # print("ERC20Functions")
        # for key in ERC20Functions:
        #     print(key)


        # print("")
        # print("reEntrancyFunctions")
        # for key in reEntrancyFunctions:
        #     print(key)

        # # print("")
        # # print("simple_txs_to_simple_function")
        # # for key in simple_txs_to_simple_function:
        # #     print(key, len(simple_txs_to_simple_function[key]), simple_txs_to_simple_function[key])



