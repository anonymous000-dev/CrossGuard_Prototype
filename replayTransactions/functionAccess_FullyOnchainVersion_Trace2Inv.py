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




def benchmark2testingset(benchmark_name):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    jsonFolder = SCRIPT_DIR + "/../benchmarkPackage/benchmarks/"
    # print all files in the directory
    listfiles = os.listdir(jsonFolder)

    files = []
    for file in listfiles:
        if benchmark_name in file:
            files.append(file)

    if benchmark_name == "Punk_1":
        files = ["Punk_1.json", "Punk_2.json", "Punk_3.json"]
    elif benchmark_name == "CheeseBank_1":
        files = ["CheeseBank_1.json", "CheeseBank_2.json", "CheeseBank_3.json"]
    elif benchmark_name == "RevestFi":
        files = ["RevestFi.json", "RevestFi_interface.json"]
    elif benchmark_name == "BeanstalkFarms_interface":
        files = ["BeanstalkFarms_interface.json", "BeanstalkFarms.json"]
    elif benchmark_name == "Warp_interface":
        files = ["Warp_interface.json", "Warp.json"]
    elif benchmark_name == "Yearn1_interface":
        files = ["Yearn1_interface.json", "Yearn1.json"]
    elif benchmark_name == "CreamFi1_1":
        files = ["CreamFi1_1.json", "CreamFi1_2.json"]
    elif benchmark_name == "RariCapital2_3":
        files = ["RariCapital2_1.json", "RariCapital2_2.json", "RariCapital2_3.json", "RariCapital2_4.json"]
    elif benchmark_name == "CreamFi2_4":
        files = ["CreamFi2_1.json", "CreamFi2_2.json", "CreamFi2_3.json", "CreamFi2_4.json"]
    
    # new benchmarks
    elif benchmark_name == "Bedrock_DeFi":
        files = ["Bedrock_DeFi1.json", "Bedrock_DeFi2.json"]
    elif benchmark_name == "BlueberryProtocol":
        files = ["BlueberryProtocol1.json", "BlueberryProtocol2.json", "BlueberryProtocol3.json", "BlueberryProtocol4.json", "BlueberryProtocol5.json"]
    elif benchmark_name == "DoughFina":
        files = ["DoughFina1.json", "DoughFina2.json"]
    elif benchmark_name == "GFOX":
        files = ["GFOX1.json", "GFOX2.json"]
    elif benchmark_name == "OnyxDAO":
        files = ["OnyxDAO1.json", "OnyxDAO2.json", "OnyxDAO3.json", "OnyxDAO4.json", "OnyxDAO5.json", "OnyxDAO6.json", "OnyxDAO7.json"]
    elif benchmark_name == "PrismaFi":
        files = ["PrismaFi1.json", "PrismaFi2.json"]
            

    testingSet = []
    trainingSet = []
    for file in files:
        filePath = jsonFolder + file
        # json read the file
        with open(filePath, 'r') as f:
            data = json.load(f)
            # print("testingSet: ", len(data["testingSet"]))
            for tx in data["testingSet"]:
                if tx not in testingSet:
                    testingSet.append(tx)
            for tx in data["traningSet"]:
                if tx not in trainingSet:
                    trainingSet.append(tx)
    # print("Overall testingSet: ", len(testingSet))
    return trainingSet, testingSet





pruneReadOnly = False
pruneERC20 = False
pruneTrivialControlFlow = False

pruneRuntimeReadOnly = False
pruneCache = False
pruneRAW = False

pruneTraining = False


reEntrancyName = ["flashBorrowToken", "flashLoan", "0xd065-borrow", "0xeb7e-borrow", "0x2db6-borrow", \
                  "0x77f9-0x66fa576f", "0xc9f2-deposit"]

reEntrancyFunctions = []


def extract_name(callnode):
    """Extract the name from the callnode tuple."""
    contract, funcName, status, structLogsStart, structLogsEnd, type, storageAccesses = callnode
    return contract[0:6] + "-" + funcName

globalisReEntrancy = False    

class callTree:
    def __init__(self, node) -> None:
        self.node = node
        self.children = []
    
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
        isReEntrancy = False
        for name in reEntrancyName:
            extracted = extract_name(self.node)
            if extracted.endswith("-" + name) or "-" + name + "-" in extracted:
                isReEntrancy = True
                global globalisReEntrancy
                globalisReEntrancy = True

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
            # # check whether your storageAccesses is a subset of the parent's storageAccesses
            # if root.node is not None and root.node[5] != "delegatecall" and root.node[6] != None and node.node[6] != None:
            #     for contract in node.node[6]:
            #         if contract not in root.node[6]:
            #             sys.exit("storageAccesses is not a subset of the parent's storageAccesses")
            #         for key in node.node[6][contract]:
            #             if key not in root.node[6][contract]:
            #                 sys.exit("storageAccesses is not a subset of the parent's storageAccesses")

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




staticcall_functions = []
complementary_functions_nonReadOnly2ReadOnly = []
complementary_functions_close_source = []
complementary_functions_readOnlySideEffect = []

def sort_callnodes(callnodes):
    global globalisReEntrancy
    globalisReEntrancy = False

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

    if pruneReadOnly:
        # filter out staticcalls
        root.children = [child for child in root.children if child.node[5] != "staticcall"]
    root.children = [child for child in root.children if child.node[5] != "delegatecall"]

    if pruneERC20:
        root.children = [child for child in root.children if child.node[1] not in commonERC20Functions]
    
    return root.toResult(), root.toResultStorage(), globalisReEntrancy
            
     



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




def classify(benchmark):
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
    # 1: privileged txs
    # 2: simple txs to simple protocols
    # 3: another famous DeFi protocol
    # 4: MEV
    # 5: User-assisted contract
    # 6: Hack
    categoryCounts = {-1: [], 0: [], 1: [], 2: [], 3: [], 4: [], 5: [], 6: []}

    # collect deployers of the target contracts
    # Whitelist Policy 1: txs initiated by deployers can be considered as benign
    deployers = set()
    for contract in targetContracts:
        deployer = ce.Contract2Deployer(contract)
        deployers.add(deployer)
    from labelTransactions.transactionLabeling import knownPriviledgedTxOrigin
    if benchmark in knownPriviledgedTxOrigin:
        deployers = deployers.union(knownPriviledgedTxOrigin[benchmark])

    # iterate all tx in txList:
    trainingSet, txList = benchmark2testingset(benchmark)


    an = Analyzer()
    contractSelector2functions = {}
    for tx in trainingSet + txList:
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
        
        if tx_category == 2 and receipt["to"] != None and receipt["input"] != None:
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

        if len(functionAccess) == 0:
            tx_category = 0

        if tx_category == None:
            print(functionAccess)
            sys,exit("tx_category is None for tx ", tx)
            continue
        categoryCounts[tx_category].append(tx)

    print("Category Counts: ")
    print("No Func Access (0): ", len(categoryCounts[0]))
    print("Deployer Transaction (1): ", len(categoryCounts[1]))
    print("Simple Txs to Simple Protocol (2): ", len(categoryCounts[2]))
    print("User-assisted Contract (3 + 4 + 5 + 6): ", len(categoryCounts[3]) + len(categoryCounts[4]) + len(categoryCounts[5]) + len(categoryCounts[6]))
    print("all classified tx: ", sum(len(v) for v in categoryCounts.values()), "/", len(trainingSet + txList))

    return categoryCounts, contractSelector2functions



potential_reentrancy_guard = {}
potential_cache = {}

read_after_write_no_dependency_functions = {}
simple_txs_to_simple_function = {}
ERC20Functions = []

def readAndAnalyze(categoryCounts, contractSelector2functions, benchmark):
    targetContracts = benchmark2targetContracts[benchmark]

    trainingSet, txList = benchmark2testingset(benchmark)
            
    ##########################################################################
    ################### Step 2: Call Flow Analysis
    ##########################################################################
    an = Analyzer()
    ce = CrawlEtherscan()
    for contract in targetContracts:
        funcSigMap2 = an.contract2funcSigMap(contract)
        contractSelector2functions[contract] = funcSigMap2

    callFlowMap = {0: {}, 1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {}}
    callFlowExampleMaps = {0: {}, 1: {}, 2: {}, 3: {}, 4: {}, 5: {}, 6: {}}

    approvedCallFlow = {
        # callflow: validBlock
    }

    for tx_category in categoryCounts:
        if tx_category == -1 or tx_category == 0:
            continue

        if tx_category == 1:
            continue
        
        if tx_category == 6:
            print("hack")

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
            
            tokenTransfers = []
            for txHash in txResultMapping:
                if txHash == tx:
                    if len(txResultMapping[txHash]) == 0:
                        tokenTransfers = []
                    else:
                        tokenTransfers = txResultMapping[txHash][1]
                    break
                    
            if pruneTokenFlow:
                absoluteValue = 0
                for tokenAddr, from_address, to_address, amount in tokenTransfers:
                    if from_address in targetContracts:
                        if tokenAddr in token2DecimalPrices:
                            decimal = token2DecimalPrices[tokenAddr][0]
                            price = token2DecimalPrices[tokenAddr][1]
                            absoluteValue += amount * price / (10 ** decimal)
                if tx_category == 6:
                    print("tokenFlow for hack: ", absoluteValue)
                if absoluteValue < 1000:
                    continue
            
            functionAccess2 = []

            hasOneReEntrancy = False
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

                    elif contract in contractSelector2functions and selector not in contractSelector2functions[contract] and contract in complementary and selector not in complementary[contract]:
                        node[1] = selector
                        funcName = selector
                        key = [contract, funcName, selector]
                        complementary_functions_readOnlySideEffect.append(key)

                        if pruneRuntimeReadOnly:
                            isReadOnly = True
                            # check sstore
                            for address in node[6]:
                                # delete re-entrancy sload and sstore from node[6]
                                temp = []
                                for ii in range(len(node[6][address])):
                                    opcode = node[6][address][ii][0]
                                    slot = str(node[6][address][ii][1])
                                    value = node[6][address][ii][2]
                                    if address in reEntrancyGuard and slot in reEntrancyGuard[address]:
                                        continue
                                    else:
                                        temp.append(node[6][address][ii])
                                node[6][address] = temp
                                    
                                for ii in range(len(node[6][address])):
                                    opcode = node[6][address][ii][0]
                                    slot = str(node[6][address][ii][1])
                                    value = node[6][address][ii][2]

                                    isReadOnly = False

                                    # if opcode == "sstore" and not (address in reEntrancyGuard and slot in reEntrancyGuard[address]):
                                    #     isReadOnly = False
                                    #     if not ifPrint:
                                    #         print("Encounter one read-only alike function", key, "in", tx)
                                    #         ifPrint = True
                                    #     print("\t", opcode, address, slot, value)
                                    #                

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
                        if str(key) not in complementary_functions_close_source and complementary[contract][selector][3]:
                            complementary_functions_close_source.append(str(key))
                    else:
                        if contract not in contractSelector2functions or selector not in contractSelector2functions[contract]:
                            # print("tx: ", tx)
                            # print("contract: ", contract)
                            # print("selector: ", selector)
                            isReadOnly = False
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
                    elif contract in complementary and funcName in complementary[contract]:
                        if complementary[contract][funcName][3]:
                            isReadOnly = True

                        key = [contract, "fallback", "0x", complementary[contract][funcName][3]]
                        if complementary[contract][funcName][3] and str(key) not in complementary_functions_close_source:
                            complementary_functions_close_source.append(key)
                    else:
                        sys.exit("fallback not in contractSelector2functions[contract] and not in complementary[contract], contract = {}, tx = {}".format(contract, tx))
                    

                if pruneCache:
                    for address in node[6]:
                        set0x0 = []
                        for ii in range(len(node[6][address])):
                            opcode = node[6][address][ii][0]
                            slot = str(node[6][address][ii][1])
                            value = node[6][address][ii][2]
                            if opcode == "sstore" and value == "0x0":
                                set0x0.append(slot)
                            if opcode == "sstore" and value == "0x1":
                                if slot in set0x0 and address not in potential_reentrancy_guard:
                                    # print("Potential re-entrancy guard", key, "in", tx)
                                    potential_reentrancy_guard[address] = tx
                                    break
                            
                    # # check sstore
                    # for address in node[6]:
                    #     # delete re-entrancy sload and sstore from node[6]
                    #     temp = []
                    #     for ii in range(len(node[6][address])):
                    #         opcode = node[6][address][ii][0]
                    #         slot = node[6][address][ii][1]
                    #         value = node[6][address][ii][2]
                    #         if address in reEntrancyGuard and slot in reEntrancyGuard[address]:
                    #             continue
                    #         else:
                    #             temp.append(node[6][address][ii])
                    #     node[6][address] = temp


                    isAllAllMatches = True
                    numberOfSstores = 0
                    for address in node[6]:
                        # search for the obvious re-entrancy pattern
                        # contains two sstore, one set it to 0x0 and later set it to 0x1
                        firstSloads = {}
                        lastSstores = {}

                        for ii in range(len(node[6][address])):
                            opcode = node[6][address][ii][0]
                            slot = str(node[6][address][ii][1])
                            value = node[6][address][ii][2]
                            if opcode == "sload" and slot not in firstSloads and slot not in lastSstores:
                                firstSloads[slot] = value
                            elif opcode == "sstore":
                                lastSstores[slot] = value
                                numberOfSstores += 1
                            
                        # check whether all lastSstores are in firstSloads and be equal 
                        for slot in lastSstores:                                    
                            if slot not in firstSloads or firstSloads[slot] != lastSstores[slot]:
                                isAllAllMatches = False
                            elif slot in firstSloads and firstSloads[slot] == lastSstores[slot]:
                                # remove sstore from node[6]
                                temp = []
                                for ii in range(len(node[6][address])):
                                    opcode = node[6][address][ii][0]
                                    _slot = str(node[6][address][ii][1])
                                    value = node[6][address][ii][2]
                                    if opcode == "sstore" and _slot == slot:
                                        continue
                                    temp.append(node[6][address][ii])
                                node[6][address] = temp

                    if isAllAllMatches:
                        if numberOfSstores > 1 and contract not in potential_cache:
                            potential_cache[contract] = lastSstores.keys()

                        isReadOnly = True



                # prune 1: discard the read-only functions
                # prune 2: discard the common ERC20 functions
                if not isReadOnly:
                    if not pruneERC20:
                        functionAccess2.append(node)
                    else:
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
            results, resultStorages, hasOneReEntrancy = sort_callnodes(functionAccess)
            len2 = len(staticcall_functions)

            if pruneRuntimeReadOnly:
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
            
            

            # if len2 != len1:
            #     print("staticcall_functions is updated at tx ", tx)
            
            if len(results) != len(resultStorages):
                sys.exit("results and resultStorages have different lengths")


            # # ignore pruning for now
            if len(results) == 0:
                continue
            elif len(results) == 1 and (results[0].count("-start") == 1 and results[0].count("-end") == 1) :
                continue

            if len(results) == 1 and hasOneReEntrancy:
                # get the full name:
                # <0x051e-sellBase-start,0x051e-sellBase-end>
                contractStart = results[0].split("-")[0]
                contractStart = contractStart[2:]
                funcName = results[0].split("-")[1].split("-")[0]
                for contract, func, _, _, _, _, _ in functionAccess:
                    if contract.startswith(contractStart) and func.startswith( funcName ):
                        key = contract + "-" + func
                        if key not in simple_txs_to_simple_function:
                            simple_txs_to_simple_function[key] = [tx]
                        else:
                            simple_txs_to_simple_function[key].append(tx)
                        break

            # Prune Hard: Read-After-Write. 
            elif len(results) > 1:
                if tx_category == 6:
                    print("before pruneRAW: ", str(results))
                    print("tx: ", tx)

                if pruneRAW:
                    # first we need to identify read and write operations
                    resultsStorageReads = []
                    resultsStorageWrites = []
                    for resultStorage in resultStorages:
                        resultsStorageReads.append({})
                        resultsStorageWrites.append({})
                        for contract in resultStorage:
                            if contract not in targetContracts:
                                continue
                            for storageAccess in resultStorage[contract]:
                                key = contract + "-" + str(storageAccess[1])
                                if storageAccess[0] == "sload":
                                    resultsStorageReads[-1][key] = 1
                                else:
                                    resultsStorageWrites[-1][key] = 1
                    rawTree = RAWTree(resultsStorageReads, resultsStorageWrites, results)
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

                    if not isReadAfterWriteOnce and not hasOneReEntrancy:
                        if str(results) not in read_after_write_no_dependency_functions:
                            read_after_write_no_dependency_functions[str(results)] = [tx]
                        else:
                            read_after_write_no_dependency_functions[str(results)].append(tx)
                        continue
            
                


            callFlow = str(results)
            # if (tx_category == 4 or tx_category == 5 or tx_category == 6) and len(results) == 0:
            #     print("now is the time")
            # print("catgeory", tx_category, "tx:", tx) 
            # print(callFlow)

            if tx in trainingSet and pruneTraining:
                for index in range(1, len(results) + 1):
                    subCallFlow = str(results[0:index])
                    if subCallFlow not in approvedCallFlow:
                        approvedCallFlow[subCallFlow] = 0


            if callFlow in approvedCallFlow and block >= approvedCallFlow[callFlow]:
                continue
                
            if callFlow not in callFlowMap[tx_category]:
                callFlowMap[tx_category][callFlow] = 1

                # if pruneParametric2 is not None:
                #     for index in range(1, len(results) + 1):
                #         subCallFlow = str(results[0:index])
                #         approvedCallFlow[subCallFlow] = block + pruneParametric2
                #         # 267 is the average block time for 1 hour
                #         # 6400 is the average block time for 24 hours
                #         # 19200 is the average block time for 3 days
            else:
                callFlowMap[tx_category][callFlow] += 1
            
            if callFlow not in callFlowExampleMaps[tx_category]:
                receipt = ce.Tx2Receipt(tx)
                to = receipt["to"]
                callFlowExampleMaps[tx_category][callFlow] = (to, tx)


    falsePositives = 0
    falsePositivesAppproval = []

    print(" == Simple Txs to Simple Protocol: ")
    Asorted = {k: v for k, v in sorted(callFlowMap[2].items(), key=lambda item: item[1], reverse=True)}
    
    for callFlow in Asorted:
        if callFlow.count("-start") <= 1 and callFlow.count("-end") <= 1:
            continue
        # print(callFlow, Asorted[callFlow])
        # falsePositives += Asorted[callFlow]
        # if callFlow not in falsePositivesAppproval:
        #     falsePositivesAppproval.append(callFlow)
            
        print(callFlowExampleMaps[2][callFlow])

    # allowedControlFlow = []
    # if pruneParametric:
    #     for callFlow in Asorted:
    #         allowedControlFlow.append(callFlow)


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
    
    totalTxs = len(txList)

    print("False positives: ", falsePositives, " out of ", totalTxs - len(categoryCounts[-1]) - len(categoryCounts[0]))
    print("False positive ratio", falsePositives / ( totalTxs - len(categoryCounts[-1]) - len(categoryCounts[0]) ) * 100, "%")







def executeOnce(listBenchmark, local_pruneRuntimeReadOnly,  local_pruneCache,  local_pruneRAW, local_pruneTraining, local_pruneTokenFlow):
    global pruneRuntimeReadOnly 
    pruneRuntimeReadOnly = local_pruneRuntimeReadOnly
    global pruneCache
    pruneCache = local_pruneCache
    global pruneRAW
    pruneRAW = local_pruneRAW

    global pruneTraining
    pruneTraining = local_pruneTraining
    global pruneTokenFlow
    pruneTokenFlow = local_pruneTokenFlow

    print("pruneRuntimeReadOnly: ", pruneRuntimeReadOnly)
    print("pruneCache: ", pruneCache)
    print("pruneRAW: ", pruneRAW)
    print("pruneTraining: ", pruneTraining)
    print("pruneTokenFlow: ", pruneTokenFlow)

    global reEntrancyName
    for benchmark in listBenchmark:

        if benchmark == "DODO":
            reEntrancyName = ["flashLoan", ]
        elif benchmark == "Opyn":
            reEntrancyName = ["borrow", "withdraw"]
        elif benchmark == "PickleFi":
            reEntrancyName = ["swapExactJarForJar", "execute"]
        elif benchmark == "Punk_1":
            reEntrancyName = []
        elif benchmark == "Harvest1_fUSDT":
            reEntrancyName = []
        elif benchmark == "Eminence":
            reEntrancyName = []
        elif benchmark == "CheeseBank_1":
            reEntrancyName = []
        elif benchmark == "RevestFi":
            reEntrancyName = ["mint", ]
        elif benchmark == "VisorFi":
            reEntrancyName = ["deposit", ]
        elif benchmark == "BeanstalkFarms_interface":
            reEntrancyName = []
        elif benchmark == "ValueDeFi":
            reEntrancyName = ["executeTransaction", ]
        elif benchmark == "XCarnival":
            reEntrancyName = ["upgradeTo", "upgradeToAndCall", ]
        elif benchmark == "Warp_interface":
            reEntrancyName = []
        elif benchmark == "UmbrellaNetwork":
            reEntrancyName = []
        elif benchmark == "IndexFi":
            reEntrancyName = []
        elif benchmark == "RariCapital1":
            reEntrancyName = []
        elif benchmark == "Yearn1_interface":
            reEntrancyName = []
        elif benchmark == "InverseFi":
            reEntrancyName = []
        elif benchmark == "bZx2":
            reEntrancyName = ["flashBorrowToken"]
        elif benchmark == "CreamFi1_1":
            reEntrancyName = ["borrow"]
        elif benchmark == "RariCapital2_3":
            reEntrancyName = ["borrow"]
        elif benchmark == "CreamFi2_4":
            reEntrancyName = ["borrow", ]

        elif benchmark == "DoughFina":
            reEntrancyName = ["flashloanReq", "executeOperation"]
        elif benchmark == "Bedrock_DeFi":
            reEntrancyName = []
        elif benchmark == "OnyxDAO":
            reEntrancyName = []
        elif benchmark == "BlueberryProtocol":
            reEntrancyName = []
        elif benchmark == "PrismaFi":
            reEntrancyName = []
        elif benchmark == "PikeFinance":
            reEntrancyName = []
        elif benchmark == "GFOX":
            reEntrancyName = []
        elif benchmark == "UwULend":
            reEntrancyName = []

        elif benchmark == "AAVE2":
            reEntrancyName = []
        elif benchmark == "Lido2":
            reEntrancyName = ["_upgradeToAndCallSecure", ]
        elif benchmark == "Uniswap2":
            reEntrancyName = ["exactOutput", "exactOutputSingle", ]


        print("\n\n\n\nbenchmark: ", benchmark)
        print("reEntrancyName: ", reEntrancyName)

        categoryCounts, contractSelector2functions = classify(benchmark)
        readAndAnalyze(categoryCounts, contractSelector2functions, benchmark)



        

if __name__ == "__main__":

    import argparse
    # read arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--pruneRuntimeReadOnly", action='store_true', help="prune runtime read-only functions")
    parser.add_argument("--pruneCache", action='store_true', help="prune cache")
    parser.add_argument("--pruneRAW", action='store_true', help="prune RAW dependency")
    parser.add_argument("--pruneTraining", action='store_true', help="also add control flow from training set")
    parser.add_argument("--pruneTokenFlow", action='store_true', help="also add token flow from Trace2Inv")
    args = parser.parse_args()


    # args = parser.parse_args()
    # study
    pruneReadOnly = True
    pruneERC20 = True
    pruneTrivialControlFlow = True
    # # # new rules
    # pruneRuntimeReadOnly = True
    # pruneCache = True
    # pruneRAW = True
    # pruneTraining = True



    listBenchmark = [
        "DODO",  # Easy
        "Opyn",  # Easy
        "PickleFi",  # Easy
        "Punk_1",  # Easy
        "Harvest1_fUSDT", # Easy
        "Eminence", # Easy
        "CheeseBank_1", # Easy
        "RevestFi", # Easy
        "VisorFi", # Easy
        "BeanstalkFarms_interface", # Easy
        "ValueDeFi", # Easy
        "XCarnival", # Easy
        "Warp_interface", # Easy
        "UmbrellaNetwork", # Easy
        "IndexFi", # Medium
        "RariCapital1", # Medium
        "Yearn1_interface", # Medium
        "InverseFi", # Medium
        "bZx2", # a lot of routers on top of main functions # Hard
        "CreamFi1_1", # Hard
        "RariCapital2_3", # Hard
        "CreamFi2_4", # Hard

        "DoughFina",  # Easy
        "Bedrock_DeFi",  # 15.44 %
        "OnyxDAO", # Easy 0.01%
        "BlueberryProtocol", # Easy
        "PrismaFi", # Medium 1.2%
        "PikeFinance", # Easy
        "GFOX", # Easy
        "UwULend",

    ]
    # executeOnce(listBenchmark, True, True, True, False, False)
    executeOnce(listBenchmark, args.pruneRuntimeReadOnly, args.pruneCache, args.pruneRAW, args.pruneTraining, args.pruneTokenFlow)
    # for benchmark in listBenchmark:
    #     staticcall_functions = []
    #     complementary_functions_nonReadOnly2ReadOnly = []
    #     complementary_functions_close_source = []
    #     potential_reentrancy_guard = {}
    #     potential_cache = {}
    #     read_after_write_no_dependency_functions = {}
    #     ERC20Functions = []
    #     reEntrancyFunctions = []
    #     simple_txs_to_simple_function = {}
    #     print("\n\n\n\nbenchmark: ", benchmark)
    #     categoryCounts, contractSelector2functions = classify(benchmark)
    #     readAndAnalyze(categoryCounts, contractSelector2functions, benchmark)
    #     # print("staticcall_functions")
    #     # for key in staticcall_functions:
    #     #     print(key)    
    #     print("")
    #     print("complementary_functions_nonReadOnly2ReadOnly")
    #     for key in complementary_functions_nonReadOnly2ReadOnly:
    #         print(key)

    #     print("")
    #     print("complementary_functions_close_source")
    #     for key in complementary_functions_close_source:
    #         print(key)

    #     print("")
    #     print("potential_reentrancy_guard")
    #     for key in potential_reentrancy_guard:
    #         if key not in reEntrancyGuard:
    #             print(key)

    #     print("")
    #     print("potential_cache")
    #     for key in potential_cache:
    #         print(key, potential_cache[key])
    #     # print("")
    #     # print("read_after_write_no_dependency_functions")
    #     # for key in read_after_write_no_dependency_functions:
    #     #     print(key, len(read_after_write_no_dependency_functions[key]), read_after_write_no_dependency_functions[key])
        
    #     # print("")
    #     # print("ERC20Functions")
    #     # for key in ERC20Functions:
    #     #     print(key)

    #     print("")
    #     print("reEntrancyFunctions")
    #     for key in reEntrancyFunctions:
    #         print(key)

    #     # print("")
    #     # print("simple_txs_to_simple_function")
    #     # for key in simple_txs_to_simple_function:
    #     #     print(key, len(simple_txs_to_simple_function[key]), simple_txs_to_simple_function[key])



