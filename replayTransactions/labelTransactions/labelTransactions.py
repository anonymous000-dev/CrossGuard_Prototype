import os, sys
import ujson as json
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from utilsPackage.compressor import readJson
from crawlPackage.crawlEtherscan import *

from labelPackage.readLabels import Labeler
from constraintPackage.macros import benchmark2targetContracts


# benchmarks finished: DODO, Opyn, PickleFi, Punk_1, CheeseBank_1, Eminence, Harvest1_fUSDT, RariCapital1, RevestFi
# benchmarks unfinished: bZx2, CreamFi1_1, IndexFi, VisorFi, Yearn1_interface

# CreamFi1_1:
# Cream.Finance: Deployer
# 



def countToLabel():
    # # parse the file toLabel2.md,
    path = os.path.join(SCRIPT_DIR, 'toLabels2_argmented4.md')
    lines = None
    with open(path, 'r') as f:
        lines = f.readlines()
    
    # countList = []
    
    # currentBenchmark = None
    # currentTxList = []
    # currentTxListWithoutFuncAccess = []

    ce = CrawlEtherscan()
    
    # for ii, line in enumerate(lines):
    #     if line.startswith("benchmark:"):
    #         benchmark = line.split(":")[1].strip()

    #         currentBenchmark = benchmark
    #         # load transaction:
    #         filePath = SCRIPT_DIR + "/../Benchmarks_Traces/CrossContract/{}/combined.txt".format(benchmark)
    #         currentTxList = []
    #         currentTxListWithoutFuncAccess = []

    #         with open (filePath, 'r') as f:
    #             for line2 in f:
    #                 entries = line2.split(" ")
    #                 Tx = entries[0]
    #                 contracts = entries[1:]
    #                 currentTxList.append(Tx)

    #                 block = ce.Tx2Block(Tx)
    #                 jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(benchmark,block)
    #                 if not os.path.exists(jsonGzPath):
    #                     currentTxListWithoutFuncAccess.append(Tx)
    #                 else:
    #                     txResultMapping = readJson(jsonGzPath)
    #                     if Tx not in txResultMapping or len(txResultMapping[Tx]) == 0 or \
    #                         len(txResultMapping[Tx][0]) == 0:
    #                         currentTxListWithoutFuncAccess.append(Tx)

    #         countList.append( [benchmark, {1:0, 2:0, 3:0, 4:0, 5:0, 6:0}, len(currentTxList), len(currentTxListWithoutFuncAccess)] )


    #     elif line.startswith("hack Transaction: "):
    #         countList[-1][1][6] += 1

    #     elif line.startswith("priviledged_txs ="):
    #         count = int(line.split("=")[1].strip())
    #         countList[-1][1][1] += count

    #     elif line.startswith("simple_txs ="):
    #         count = int(line.split("=")[1].strip())
    #         countList[-1][1][2] += count


    #     elif line.startswith("0x") and len(line) > 100:
    #         # 0x3d71d79c224998e608d03c5ec9b405e7a38505f0 3059 0x71daf441ce9ae0fead33f3761fe2e1356fccdc679b7b3c0cdb957edb2471f7c1
    #         contract = line.split(" ")[0]
    #         count = int(line.split(" ")[1])
    #         Tx = line.split(" ")[2]

    #         category = lines[ii + 1].split(" ")[-1].strip()
    #         if category == "Hack":
    #             countList[-1][1][6] += count
    #         elif category.isdigit():
    #             countList[-1][1][int(category)] += count                
    #             pass
    #         elif category == "" or category == "XX":
    #             pass
    #         else:
    #             print(category)
    #             print("error")
    #             sys.exit(1)
            

    # for item in countList:
    #     print(item[0])
    #     print(item[1])
    #     # add up values in item[1]
    #     total = 0
    #     for key in item[1]:
    #         total += item[1][key]
        
    #     print("\tclassified + no func access:")
    #     print("\t{}+{}={}".format(total, item[3], total + item[3]), "out of", item[2])



    labeler = Labeler()
    # label all everything we can using data from etherscan 
    path = os.path.join(SCRIPT_DIR, 'toLabels2_argmented5.md')
    # clean the file
    with open(path, 'w') as f:
        pass


    knownPriviledgedTxOrigin = {
        "Yearn1_interface": ["0x0cec743b8ce4ef8802cac0e5df18a180ed8402a7"]
    }





    skipALine = False
    deployers = set()

    countTODOS = {}

    for ii, line in enumerate(lines):
        if line.startswith("benchmark:"):
            benchmark = line.split(":")[1].strip()
            countTODOS[benchmark] = 0
            # collect deployers of the target contracts
            deployers = set()
            targetContracts = benchmark2targetContracts[benchmark]
            for contract in targetContracts:
                deployer = ce.Contract2Deployer(contract)
                deployers.add(deployer)
            if benchmark in knownPriviledgedTxOrigin:
                for contract in knownPriviledgedTxOrigin[benchmark]:
                    deployers.add(contract)


        elif line.startswith("0x") and len(line) > 100:
            # 0x3d71d79c224998e608d03c5ec9b405e7a38505f0 3059 0x71daf441ce9ae0fead33f3761fe2e1356fccdc679b7b3c0cdb957edb2471f7c1
            contract = line.split(" ")[0]

            count = int(line.split(" ")[1])
            Tx = line.split(" ")[2]
            category = lines[ii + 1].split(" ")[-1].strip()

            with open(path, 'a') as f:
                f.write(line)

            if category == "3" and benchmark == "RariCapital2_3":
                label = labeler.contract2EtherScanLabel(contract)
                if "deployer" in label and label["deployer"] == "Rari Capital: Deployer 2":
                    with open(path, 'a') as f:
                        f.write(str(label) + " 2\n")
                else:
                    with open(path, 'a') as f:
                        f.write(str(label) + " 3\n")
                skipALine = True
                continue

            elif category == "3" and benchmark == "CreamFi2_4":
                label = labeler.contract2EtherScanLabel(contract)
                if "deployer" in label and label["deployer"] == "Cream.Finance: Deployer":
                    with open(path, 'a') as f:
                        f.write(str(label) + " 2\n")
                else:
                    with open(path, 'a') as f:
                        f.write(str(label) + " 3\n")
                skipALine = True
                continue

            elif category == "5" and benchmark == "CreamFi2_4":
                label = labeler.contract2EtherScanLabel(contract)
                if "deployer" in label and label["deployer"] == "Cream Finance Flashloan Attacker":
                    with open(path, 'a') as f:
                        f.write(str(label) + " 6\n")
                else:
                    with open(path, 'a') as f:
                        f.write(str(label) + " 5\n")
                skipALine = True
                continue

            elif benchmark == "InverseFi":
                label = labeler.contract2EtherScanLabel(contract)
                if "deployer" in label and label["deployer"] == "Inverse Finance: Deployer":
                    with open(path, 'a') as f:
                        f.write(str(label) + " 2\n")
                else:
                    with open(path, 'a') as f:
                        f.write(str(label) + " {}\n".format(category))
                skipALine = True
                continue


            elif category == "" or category == "XX" or category.endswith("}"):
                label = labeler.contract2EtherScanLabel(contract)
                
                if "labels" in label and "mev-bot" in label["labels"]:
                    with open(path, 'a') as f:
                        f.write(str(label) + " 4\n")
                elif "labels" in label and len(label["labels"]) != 0:
                    with open(path, 'a') as f:
                        f.write(str(label) + " 3\n")
                else:
                    deployer = ce.Contract2Deployer(contract)
                    if deployer in deployers:
                        with open(path, 'a') as f:
                            f.write(str(label) + " 2\n")
                    elif "labels" in label and len(label["labels"]) == 0:
                        with open(path, 'a') as f:
                            f.write(str(label) + " 5\n")
                    else:
                        with open(path, 'a') as f:
                            f.write(str(label) + "\n")
                        
                        countTODOS[benchmark] += 1
                    
                skipALine = True
                continue
            else:
                continue


        if skipALine:
            skipALine = False
            continue
        else:
            with open(path, 'a') as f:
                f.write(line)
    
    for key in countTODOS:
        print(key, countTODOS[key])
        




if __name__ == '__main__':
    countToLabel()