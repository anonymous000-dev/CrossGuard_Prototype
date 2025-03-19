import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from crawlPackage.crawlEtherscan import *
from utilsPackage.compressor import *
from constraintPackage.macros import *
from constraintPackage.utils import *
from labelPackage.readLabels import Labeler


knownTxsNotCollected = [
    "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec",
    "0x52a0541deff2373e1098881998b60af4175d75c410d67c86fcee850b23e61fc2",
    "0xca13006944e6eba2ccee0b2d96a131204491641014622ef2a3df3db3e6939062",
    "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec"
]

knownPriviledgedTxOrigin = {
    "Yearn1_interface": ["0x0cec743b8ce4ef8802cac0e5df18a180ed8402a7"],
    "Bedrock_DeFi": ["0xbfddf5e269c74157b157c7dac5e416d44afb790d"]

}

knownOtherDeployedContracts = {
    "IndexFi": ["0x4d4d44edc240659b18e4b3f46ef3e40b4b8bd5df", "0x4bb23e4b33dc6ebfdf824c1c4c6cd4ad31363e47", "0x672a44626c193ccafcd253b1b096de219fdcc2fa", "0x17ac188e09a7890a1844e5e65471fe8b0ccfadf3", "0xfa6de2697d59e88ed7fc4dfe5a33dac43565ea41", "0xfb6ac20d38a1f0c4f90747ca0745e140bc17e4c3", "0xfa5a44d3ba93d666bf29c8804a36e725ecac659a"],
    "DODO": ["0x9ae501385bc7996a2a4a1fbb00c8d3820611bcb5", "0xa356867fdcea8e71aeaf87805808803806231fdc"],
    "Opyn": ["0xeb7e15b4e38cbee57a98204d05999c3230d36348", "0x951d51baefb72319d9fbe941e1615938d89abfe2", "0x39246c4f3f6592c974ebc44f80ba6dc69b817c71"],
    "bZx2": ["0xb42e611d0196b05acf75ce2d6c8487829f00e9d9", "0xa7eb2bc82df18013ecc2a6c533fc29446442edee", "0x77f973fcaf871459aa58cd81881ce453759281bc", "0x1cf226e9413addaf22412a2e182f9c0de44af002", "0x493c57c4763932315a328269e1adad09653b9081", "0x14094949152eddbfcd073717200da82fed8dc960", "0xf2ad1ee9671f63df7c8f8daa822da1e6fc08b80d", "0xf013406a0b1d544238083df0b93ad0d2cbe0f65f", "0xcc16745a1773dd95ab9ed98599b8d9b835e42e25", ""],
    "PickleFi": ["0xbd17b1ce622d73bd438b9e658aca5996dc394b0d", "0xcffa068f1e44d98d3753966ebd58d4cfe3bb5162", "0x68d14d66b2b0d6e157c06dc8fefa3d8ba0e66a89", "0x53bf2e62fa20e2b4522f05de3597890ec1b352c6", "0xc80090aa05374d336875907372ee4ee636cbc562", "0x09fc573c502037b149ba87782acc81cf093ec6ef", "0x2e35392f4c36eba7ecafe4de34199b2373af22ec", "0x1bb74b5ddc1f4fc91d6f9e7906cf68bc93538e33", "0x8f9676bfa268e94a2480352cc5296a943d5a2809", "0x6949bb624e8e8a90f87cd2058139fcd77d2f3f87", "0xd80e558027ee753a0b95757dc3521d0326f13da2", "0x1370b716575bd7d5aee14128e231a779198e5397", ""],
    "Punk_1": ["0x032b57fa06c8f6c02be7016fcad81b364708eb68", "0x669abcbe9119df3bf718bc7f16bb697c5b9a99a3", "0x93ee305e0923c05b45abd47346b8e03da9b3b325"],
    "CheeseBank_1": ["0xeab126ae68de4c65834ad9b6a570661cdbc2f6d0", ],
    "CreamFi1_1": ["0x892b14321a4fcba80669ae30bd0cd99a7ecf6ac0", "0x44fbebd2f576670a6c33f6fc0b00aa8c5753b322", "0x797aab1ce7c01eb727ab980762ba88e7133d2157", "0xcbae0a83f4f9926997c8339545fb8ee32edc6b76", "0xc7fd8dcee4697ceef5a2fd4608a7bd6a94c77480", "0xe89a6d0509faf730bd707bf868d9a2a744a363c7", "0x338286c0bc081891a4bda39c7667ae150bf5d206", "0x4ee15f44c6f0d8d1136c83efd2e8e4ac768954c6", "0x92b767185fb3b04f881e3ac8e5b0662a027a1d9f", "0x9baf8a5236d44ac410c0186fe39178d5aad0bb87", "0x71a808fd21171d992ebc17678e8ae139079922d0", "0x19d1666f543d42ef17f66e376944a22aea1a8e46", "0x8b86e0598616a8d4f1fdae8b59e55fb5bc33d0d6", "0xa65405e0dd378c65308deae51da9e3bcebb81261", "0xce4fe9b4b8ff61949dcfeb7e03bc9faca59d2eb3", "0x224061756c150e5048a1e4a3e6e066db35037462", "0x1ff8cdb51219a8838b52e9cac09b71e591bc998e", "0x697256caa3ccafd62bb6d3aa1c7c5671786a5fd9", "0x01da76dea59703578040012357b81ffe62015c2d", "0x17107f40d70f4470d20cb3f138a052cae8ebd4be", "0x3623387773010d9214b10c551d6e7fc375d31f58", "0x3ba3c0e8a9e5f4a01ce8e086b3d8e8a603a2129e", "0xfd609a03b393f1a1cfcacedabf068cad09a924e2", "0x8b950f43fcac4931d408f1fcda55c6cb6cbf3096", "0x903560b1CcE601794C584F58898dA8a8b789Fc5d", "0x2a537fa9ffaea8c1a41d3c2b68a9cb791529366d", "0x228619cca194fbe3ebeb2f835ec1ea5080dafbb2", "0xef58b2d5a1b8d3cde67b8ab054dc5c831e9bc025"],
    "Harvest1_fUSDT": ["0xf8ce90c2710713552fb564869694b2505bfc0846", "0xc3f7ffb5d5869b3ade9448d094d81b0521e8326f", "0x4f7c28ccb0f1dbd1388209c67eec234273c878bd", "0xc7ee21406bb581e741fbb8b21f213188433d9f2f", "0x6ac4a7ab91e6fd098e13b7d347c6d4d1494994a2", "0xe85c8581e60d7cd32bbfd86303d2a4fa6a951dac", "0xf1181a71cc331958ae2ca2aad0784acfc436cb93", "0x7aeb36e22e60397098c2a5c51f0a5fb06e7b859c", "0x917d6480ec60cbddd6cbd0c8ea317bcc709ea77b", "0x01112a60f427205dca6e229425306923c3cc2073", "0x3da9d911301f8144bdf5c3c67886e5373dcdff8e", "0x307e2752e8b8a9c29005001be66b1c012ca9cdb7", "0x75071f2653fbc902ebaff908d4c68712a5d1c960", "0x15d3a64b2d5ab9e152f16593cdebc4bb165b5b4a", "0x156733b89ac5c704f3217fee2949a9d4a73764b5", "0x5d9d25c7c457dd82fc8668ffc6b9746b674d4ecb", "0x7ddc3fff0612e75ea5ddc0d6bd4e268f70362cff", "0xa79a083fdd87f73c2f983c5551ec974685d6bb36", "0x7b8ff8884590f44e10ea8105730fe637ce0cb4f6", "0xfe09e53a81fe2808bc493ea64319109b5baa573e", "0xec56a21cf0d7feb93c25587c12bffe094aa0ecda", "0xab7fa2b2985bccfc13c6d86b1d5a17486ab1e04c", "0x7674622c63bee7f46e86a4a5a18976693d54441b", "0x9523fdc055f503f73ff40d7f66850f409d80ef34", "0xf553e1f826f42716cdfe02bde5ee76b2a52fc7eb", "0xc391d1b08c1403313b0c28d47202dfda015633c4", "0xa3cf8d1cee996253fad1f8e3d68bdcba7b3a3db5", "0x9aa8f427a17d6b0d91b6262989edc7d45d6aedf8"]    
}


# Category 1: priviledged transactions, i.e., transactions that are sent by the deployer or the owner of the contract
# Category 2: simple transactions, i.e, transactions that are sent to the contract of the same protocol:
#             ==> maybe we should also consider the input parameters to avoid the caller can do too much?
# Category 3: another famous defi protocol 
# Category 4: MEV

def labelTransaction(benchmark, isPopular = False):
    # preparation
    ce = CrawlEtherscan()
    targetContracts = benchmark2targetContracts[benchmark]
    hack = None
    if not isPopular:
        hack = benchmark2hack[benchmark]
        # print("The Hack Tx for this protocol is: ", hack)

    toContracts = {}
    toContract2Tx = {}

    # collect deployers of the target contracts
    deployers = set()
    for contract in targetContracts:
        deployer = ce.Contract2Deployer(contract)
        deployers.add(deployer)
    if benchmark in knownPriviledgedTxOrigin:
        for contract in knownPriviledgedTxOrigin[benchmark]:
            deployers.add(contract)

    # iterate all tx in txList:
    txList = []
    filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract/{}/combined.txt".format(benchmark)
    if isPopular:
        filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract_study/{}/combined.txt".format(benchmark)

    with open (filePath, 'r') as f:
        for line in f:
            entries = line.split(" ")
            Tx = entries[0]
            contracts = entries[1:]
            txList.append(Tx)

    if isPopular:
        txList = txList[-100000:]

    priviledged_txs = 0
    simple_txs = 0
    nofuncAccess_txs = 0
    no_exists_txs = 0


    for tx in txList:

        # if tx == hack:
        #     print("now is the time")


        block = ce.Tx2Block(tx)
        to = ce.Tx2Receipt(tx)["to"]
        if to is None:
            to = ce.Tx2Receipt(tx)["contractAddress"]
        if to is None:
            sys.exit("to is None")

        # baseline prune 1: we disgard transactions that are directly sent to the target contracts (Special EOA)
        ifKnownContract = benchmark in knownOtherDeployedContracts and to in knownOtherDeployedContracts[benchmark]
        if to in targetContracts or ifKnownContract:
            simple_txs += 1
            continue

        jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
        if not os.path.exists(jsonGzPath):
            if tx in knownTxsNotCollected:
                continue
            else:
                # print("{} not exists".format(jsonGzPath))
                no_exists_txs += 1
                continue

        txResultMapping = readJson(jsonGzPath)
        if tx not in txResultMapping:
            # print("tx not in txResultMapping")
            pass

        functionAccess = []
        for txHash in txResultMapping:
            if txHash == tx:
                if len(txResultMapping[txHash]) == 0:
                    functionAccess = []
                else:
                    functionAccess = txResultMapping[txHash][0]
                break

        # Prune 0: there must exist a func call to one of target contracts, otherwise we ignore it. 
        if len(functionAccess) == 0:
            nofuncAccess_txs += 1
            continue

        details = ce.Tx2Details(tx)
        if "from" in details and details["from"] in deployers:
            priviledged_txs += 1
            continue

        if not isPopular and tx == hack:
            print("hack Transaction: {}".format(tx))
        else:
            to = ce.Tx2Receipt(tx)["to"]
            if to is None:
                to = ce.Tx2Receipt(tx)["contractAddress"]
            if to is None:
                sys.exit("to is None")
            if to not in toContracts:
                toContracts[to] = 0
                toContract2Tx[to] = tx
            toContracts[to] += 1

    print("priviledged_txs = ", priviledged_txs)
    print("simple_txs = ", simple_txs)
    print("nofuncAccess_txs = ", nofuncAccess_txs)
    print("no_exists_txs = ", no_exists_txs)

    labeler = Labeler()

    # sort the toContracts
    toContracts = {k: v for k, v in sorted(toContracts.items(), key=lambda item: item[1], reverse=True)}
    for to in toContracts:
        etherScanLabel =  labeler.contract2EtherScanLabel(to)
        print(to, toContracts[to], toContract2Tx[to])

        if etherScanLabel is None:
            print("")
        else:
            print(etherScanLabel, end = " ")
            deployer = etherScanLabel["deployer"] if "deployer" in etherScanLabel else ""
            if to.lower() in targetContracts:
                print("2")
            elif benchmark == "AAVE2" and "Aave" in deployer:
                print("2") 
            elif benchmark == "Lido2" and "Lido" in deployer:
                print("2")
            elif benchmark == "Uniswap2" and "Uniswap" in deployer:
                print("2")
            elif "deployer" in deployer.lower():
                print("3")
            elif "MEV" in deployer:
                print("4")
            else:
                print("None 5")

            




        






if __name__ == "__main__":
    listBenchmark = [
        # "DODO",  # Easy
        # "Opyn",  # Easy
        # "PickleFi",  # Easy
        # "Punk_1",  # Easy

        # "bZx2", # a lot of routers on top of main functions
        # "CheeseBank_1",   
        # "CreamFi1_1",
        # "Eminence",
        # "Harvest1_fUSDT",
        # "IndexFi",

        # "RariCapital1",
        # "RevestFi",
        # "VisorFi",
        # "Yearn1_interface",

        # "BeanstalkFarms_interface", # newly added, need to fetch trace
        # "ValueDeFi",
        # "XCarnival",
        # "RariCapital2_3",
        # "Warp_interface",
        # "InverseFi",
        # "CreamFi2_4"

        "AAVE2",
        "Lido2",
        "Uniswap2",


        # "Bedrock_DeFi",
        # "DoughFina",
        # "OnyxDAO",

        # "BlueberryProtocol",
        # "PrismaFi",
        # "PikeFinance", 
        # "GFOX",
        # "UwULend"

    ]

    AllDataMoneyFlowInOut = []
    AllDataMoneyFlowAbsolute = []
    
    for benchmark in listBenchmark:
        # if benchmark != "CreamFi1_1":
        #     continue
        print("\n\n\n\nbenchmark: ", benchmark)
        # main(benchmark)
        labelTransaction(benchmark, benchmark in ["AAVE2", "Lido2", "Uniswap2"])


