import sys
import ujson as json
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
import time

otherLabels = {}

class Labeler:
    def __init__(self):
        self.labelDict = None
        archivedPath = os.path.join(SCRIPT_DIR, "combinedAllLabels.json")
        with open(archivedPath, "r") as f:
            self.labelDict = json.load(f)

        self.etherscanLabelDict = {}
        path = os.path.join(SCRIPT_DIR, "etherScanLabels.json")
        with open(path, "r") as f:
            self.etherscanLabelDict = json.load(f)
        
        self.driver = None
    

    def contract2EtherScanLabel(self, contract: str):
        result = {}
        
        # if the contract is in the archived labels, return the label
        if contract in self.labelDict:
            result['name'] = self.labelDict[contract]["name"] if "name" in self.labelDict[contract] else ""
            result['labels'] = self.labelDict[contract]["labels"] if "labels" in self.labelDict[contract] else []
            return self.labelDict[contract]

        if contract in self.etherscanLabelDict:
            return self.etherscanLabelDict[contract]
        
        return {}
        
        if self.driver is None:
            self.driver = uc.Chrome(service=ChromeService(ChromeDriverManager().install()))

        print(f"https://etherscan.io/address/{contract}#code")
        self.driver.get(f"https://etherscan.io/address/{contract}#code")
        
        time.sleep(2)  # Wait for the page to load. Adjust the sleep time as necessary.
        
        # else crawl etherscan
        # result = {}
        # Extract "Contract Name"
        try:
            contract_name_xpath = "//div[contains(text(), 'Contract Name:')]/following-sibling::div/span[@class='h6 fw-bold mb-0']"
            contract_name = self.driver.find_element(By.XPATH, contract_name_xpath).text
            result['name'] = contract_name
        except:
            result['name'] = ""

        # Extract "TokenTracker"
        try:
            token_text_xpath = "//div[contains(@class, 'd-flex align-items-center gap-1 mt-2')]/a"
            token_tracker = self.driver.find_element(By.XPATH, token_text_xpath).text
            if "labels" in result:
                result['labels'].append(token_tracker)
            else:
                result['labels'] = [token_tracker] 
        except:
            if "labels" not in result:
                result['labels'] = []

        # Extract "Deployer"
        base_xpath = "//div[@id='ContentPlaceHolder1_trContract']"
        try:    
            contract_creator_xpath = f"{base_xpath}//a[contains(@href, 'address')]"
            creator_name = self.driver.find_element(By.XPATH, contract_creator_xpath).text
            result['deployer'] = creator_name
        except:
            try:
                contract_address_xpath = f"{base_xpath}//span[contains(@data-highlight-target, '0x')]"
                contract_address = self.driver.find_element(By.XPATH, contract_address_xpath).text
                result['deployer'] = contract_address
            except:
                result['deployer'] = ""


        # store:
        self.etherscanLabelDict[contract] = result
        path = os.path.join(SCRIPT_DIR, "etherScanLabels.json")
        with open(path, "w") as f:
            json.dump(self.etherscanLabelDict, f)

        return result   


    
    def contract2CrawledLabel(self, contract: str):
        # first: if etherscan has a label for the contract
        # second: if walletlabels has a label for the contract
        # third: if the deployer has a label
        if contract not in self.labelDict:
            return None
        return self.labelDict[contract]["labels"]


def getLabelsMap():
    path = os.path.join(SCRIPT_DIR, "combinedAllLabels.json")
    print(path)
    labelDict = {}
    with open(path, "r") as f:
        labelDict = json.load(f)
        # for contract in labelDict:
        #     labelDictContract = labelDict[contract]
        #     name = labelDictContract["name"]
        #     labels = labelDictContract["labels"]
        #     if len(labels) != 1:
        #         print(labels)

    return labelDict

def contract2Label(contract: str):
    labelDict = getLabelsMap()
    return labelDict[contract]




Hack2Labels = {}

def addLabels2Map(protocol, contract, category):
    if category == "Wallet":
        return
    if protocol not in Hack2Labels:
        Hack2Labels[protocol] = {}
    if category not in Hack2Labels[protocol]:
        Hack2Labels[protocol][category] = []
    
    Hack2Labels[protocol][category].append(contract)


closedSourceContract = []
openSourceContract = []
    
if __name__ == "__main__":
    # SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # file = SCRIPT_DIR + "/../studyResult3.txt"
    # labeler = Labeler()
    # with open(file, "r") as f:
    #     lines = f.readlines()
    #     for line in lines:
    #         if line.startswith("0x"):
    #             contract = line.strip()
    #             print("working on ", contract)
    #             label = labeler.contract2EtherScanLabel(contract)
    #             print(label)



    labeler = Labeler()
    # print(labeler.contract2EtherScanLabel("0xa79828df1850e8a3a3064576f380d90aecdd3359"))
    
    path = SCRIPT_DIR + "/contractAddresses.md"
    print("# Three types: 1. Exploiter 2. Target DeFi Protocol  3. Other Protocol")
    
    # read the file
    with open(path, "r") as f:
        lines = f.readlines()
        currentTargetProtocol = None
        currentHackTx = None

        for line in lines:
            address = line.strip()
            if address.startswith("#"):
                print(line)
                print("")
                # line is of the format #  Hack:Opyn 0xa858463f30a08c6f3410ed456e59277fbe62ff14225754d2bb0b4f6a75fdc8ad
                TargetProtocolandHack = line.split(":")[1].strip()
                currentTargetProtocol = TargetProtocolandHack.split(" ")[0].strip()
                currentHackTx = TargetProtocolandHack.split(" ")[1].strip()
                # print(currentTargetProtocol)
                # print(currentHackTx)

            elif address.startswith("0x"):
                if address == "0xba12222222228d8ba445958a75a0704d566bf2c8":
                    print("now is the time")

                label = labeler.contract2EtherScanLabel(address)
                if label["name"] == "":
                    closedSourceContract += [address]
                else:
                    openSourceContract += [address]

                # print(address)
                category = "None"
                if "deployer" in label and "Exploiter" in label["deployer"]:
                    category = "Exploiter"
                elif "0xbaC8a476...bc88bB3a8" in label["deployer"]:
                    label["deployer"] = "PickleFi Exploiter"
                    category = "Exploiter"
                elif "Cream Finance Flashloan Attacker" in label["deployer"]:
                    category = "Exploiter"
                elif "Harvest.Finance: Hacker" in label["deployer"]:
                    category = "Exploiter"
                elif address == "0x0d043128146654c7683fbf30ac98d7b2285ded00":
                    category = "Exploiter"
                elif address == "0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963":
                    category = "Exploiter"
                elif address == "0xc8a65fadf0e0ddaf421f28feab69bf6e2e589963" or \
                    address == "0x14ec0cd2acee4ce37260b925f74648127a889a28":
                    category = "Wallet"
                elif label["deployer"] == "" and label["name"] == "":
                    category = "Wallet"
                elif label["deployer"] == "0x1751E3E1...3Fc59F7D0":
                    category = "Exploiter"
                elif address == "0x8B4C1083cd6Aef062298E1Fa900df9832c8351b3":
                    category = "Exploiter"
                elif label["deployer"] == "0x915C2D6f...7d4c3fb8E":
                    category = "Exploiter"
                    label["deployer"] = "Opyn Exploiter"
                elif label["deployer"] == "0xeBc6bD6a...B9CF03C40":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"
                elif label["deployer"] == "0x882d72aa...5316CD9aa":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"
                elif label["deployer"] == "Punk Protocol Whitehat":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"
                elif label["deployer"] == "0x368A6558...82C571b23":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"
                elif label["deployer"] == "0xa773603b...76D8a9A2F":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"
                elif label["deployer"] == "0x16CC37d0...AbB396A2b":
                    category = "Exploiter"
                    label["deployer"] = "Exploiter"


                

                

                elif currentTargetProtocol == "PolyNetwork" and (address == "0x250e76987d838a75310c34bf422ea9f1ac4cc906" or \
                    address == "0xcf2afe102057ba5c16f899271045a0a37fcb10f2" or \
                    address == "0x5a51e2ebf8d136926b9ca7b59b60464e7c44d2eb" or \
                    address == "0x838bf9e95cb12dd76a54c9f9d2e3082eaf928270"):
                    category = "Target(PolyNetwork)"

                elif currentTargetProtocol == "HarmonyBridge" and (address == "0xf9fb1c508ff49f78b60d3a96dea99fa5d7f3a8a6" or \
                        address == "0x715cdda5e9ad30a0ced14940f9997ee611496de6"):
                    category = "Target(Harmony)"
                elif "Harvest" in currentTargetProtocol and "Harvest.Finance: Deployer" in label["deployer"] :
                    category = ("Target(Harvest)")
                elif label["deployer"] == "Beanstalk: Publius" and "Beanstalk" in currentTargetProtocol:
                    category = ("Target(Beanstalk)")
                elif "yearn: Deployer" in label["deployer"] and "Yearn" in currentTargetProtocol:
                    category = ("Target(Yearn)")
                elif "XCarnival: Deployer" in label["deployer"] and "XCarnival" in currentTargetProtocol:
                    category = ("Target(XCarnival)")
                elif "bZx Protocol: Deployer" in label["deployer"] and "bZx" in currentTargetProtocol:
                    category = ("Target(bZx)")
                elif "Revest Finance: Deployer" in label["deployer"] and "Revest" in currentTargetProtocol:
                    category = ("Target(RevestFi)")
                elif "Cream.Finance: Deployer" in label["deployer"] and "CreamFi" in currentTargetProtocol:
                    category = ("Target(CreamFi)")
                elif label["deployer"] == "0x11690B00...Cd344547f" and "CreamFi" in currentTargetProtocol:
                    category = ("Target(CreamFi)")

                elif "Rari Capital: Deployer" in label["deployer"] and "RariCapital" in currentTargetProtocol:
                    category = ("Target(RariCapital)")
                elif (address == "0x220f93183a69d1598e8405310cb361cff504146f" or address == "0xe980efb504269ff53f7f4bc92a2bd1e31b43f632" or \
                        address == "0xfea425f0baadf191546cf6f2dbf72357d631ae46" or address ==  "0xfea425f0baadf191546cf6f2dbf72357d631ae46" or \
                        address == "0xe097783483d1b7527152ef8b150b99b9b2700c8d" or address == "0x8922c1147e141c055fddfc0ed5a119f3378c8ef8" or \
                        address == "0xebe0d1cb6a0b8569929e062d67bfbc07608f0a47" or address == "0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f" or \
                        address == "0x26267e41ceca7c8e0f143554af707336f27fa051" ) and \
                        "RariCapital" in currentTargetProtocol:
                    category = "Target(RariCapital)"

                elif "Umbrella Network: Deployer" in label["deployer"] and "Umbrella" in currentTargetProtocol:
                    category = ("Target(Umbrella)")
                elif "Inverse Finance: Deployer" in label["deployer"] and "InverseFi" in currentTargetProtocol:
                    category = ("Target(InverseFi)")
                elif "Cheese Bank: Deployer" in label["deployer"] or \
                    "0xF3A40B25...E717F897E" in label["deployer"] and "CheeseBank" in currentTargetProtocol:
                    category = ("Target(CheeseBank)")
                    label["deployer"] = "Cheese Bank: Deployer"
                elif "Value DeFi Protocol: Deployer" in label["deployer"] and "ValueDeFi" in currentTargetProtocol:
                    category = ("Target(ValueDeFi)")
                elif "0x8f3E8A97...0DAB2E1b3" == label["deployer"] and "Warp" in currentTargetProtocol:
                    category = ("Target(Warp)")
                    label["deployer"] = "Warp: Deployer"
                elif "0xDe99eA53...1e32d3a7F" == label["deployer"] and "Opyn" in currentTargetProtocol:
                    category = ("Target(Opyn)")
                    label["deployer"] = "Opyn: Deployer"
                elif label["deployer"] == "0x11df15F0...373138F5a" and "CreamFi" in currentTargetProtocol:
                    category = ("Target(CreamFi)")
                elif "Opyn" in currentTargetProtocol and (address == "0xeb7e15b4e38cbee57a98204d05999c3230d36348" or address == "0x82151ca501c81108d032c490e25f804787bef3b8"):
                    category = ("Target(Opyn)")
                elif "Rari" in label["deployer"] and "RariCapital" in currentTargetProtocol:
                    category = ("Target(RariCapital)")
                elif "VisorFi" in currentTargetProtocol and (address == "0x3a84ad5d16adbe566baa6b3dafe39db3d5e261e5" or address == "0xc9f27a50f82571c1c8423a42970613b8dbda14ef" or \
                    address == "0xf938424f7210f31df2aee3011291b658f872e91e"):
                    category = ("Target(VisorFi)")
                elif "DODO" in currentTargetProtocol and (address == "0x2bbd66fc4898242bdbd2583bbe1d76e8b8f71445"):
                    category = ("Target(DODO)")
                elif "DODO" in currentTargetProtocol and  (address == "0x7f4e7fb900e0ec043718d05caee549805cab22c8" or address == "0xf2df8794f8f99f1ba4d8adc468ebff2e47cd7010" or \
                    address == "0x051ebd717311350f1684f89335bed4abd083a2b6"):
                    category = ("Target(DODO)")
                elif "IndexFi" in currentTargetProtocol and "Indexed: Deployer" in label["deployer"]:
                    category = ("Target(IndexFi)")
                elif "IndexFi" in currentTargetProtocol and (address == "0xfa5a44d3ba93d666bf29c8804a36e725ecac659a" or label["deployer"] == "0xF237d689...e82e0ae3D"):
                    category = ("Target(IndexFi)")
                elif "PickleFi" in currentTargetProtocol and (address == "0x6949bb624e8e8a90f87cd2058139fcd77d2f3f87" or label["deployer"] == "0xf00D9880...9C4f4316A"):
                    category = ("Target(PickleFi)")
                elif "RoninNetwork" in currentTargetProtocol and "Axie Infinity" in label["deployer"]:
                    category = ("Target(RoninNetwork)")
                elif "Punk" in currentTargetProtocol and "Punk Protocol" in label["deployer"]:
                    category = ("Target(Punk)") 
                elif "Nomad" in currentTargetProtocol and "Nomad Deployer" in label["deployer"]:
                    category = ("Target(Nomad)")
                elif "Eminence" in currentTargetProtocol and ("Yearn Fi Deployer" in label["deployer"] or "0x2D407dDb...71447d45C" == label["deployer"]):
                    category = ("Target(Eminence)")


                elif "0x4cAddE3D...6760895Dd" == label["deployer"]:
                    category = ("Other(Chainlink)")
                elif address == "0x97dec872013f6b5fb443861090ad931542878126":
                    category = ("Other(Uniswap)")
                elif "Aave Deployer" in label["deployer"]:
                    category = "Other(Aave)"
                elif "name" in label and "Dai" in label["name"] and "deployer" in label and \
                        "Maker: Deployer 4" in label["deployer"]:
                    category = "Other(DAI)"
                elif "deployer" in label and "Aave: Deployer" in label["deployer"]:
                    category = "Other(AAVE)"
                elif "deployer" in label and "Circle: Deployer" in label["deployer"]:
                    category = ("Other(USDC)")
                elif "Maker: Deployer" in label["deployer"]:
                    category = ("Other(Maker)")
                elif label["name"] == "BoredApeYachtClub" and label["deployer"] == "Bored Ape Yacht Club: Deployer":
                    category = ("Other(BAYC)")
                elif "Curve.fi: Deployer" in label["deployer"]:
                    category = ("Other(Curve.fi)")
                elif label["name"] == "TetherToken" and "Bitfinex: Deployer" in label["deployer"]:
                    category = ("Other(USDT)")
                elif "Compound: Deployer" in label["deployer"]:
                    category = ("Other(Compound)")
                elif "Uniswap: Deployer" in label["deployer"]:
                    category = ("Other(Uniswap)")
                elif "Renascent Finance: Deployer" in label["deployer"]:
                    category = ("Other(Renascent)")
                elif "dYdX: Deployer" in label["deployer"]:
                    category = ("Other(dYdX)")
                elif "Yearn: MultiSig Signer Banteg" in label["deployer"]:
                    if "Yearn" not in currentTargetProtocol:
                        category = ("Other(Yearn)")
                    else:
                        category = ("Target(Yearn)")
                elif label["deployer"] == "0x2D407dDb...71447d45C" or label["deployer"] == "Yearn Fi Deployer":
                    if "Yearn" not in currentTargetProtocol:
                        category = ("Other(Yearn)")
                        label["deployer"] = "Yearn Fi Deployer"
                    else:
                        category = ("Target(Yearn)")
                        label["deployer"] = "Yearn Fi Deployer"



                elif "Wrapped BTC: Deployer" in label["deployer"]:
                    category = ("Other(WBTC)")
                elif "ERC1820Registry" in label["name"]:
                    category = ("Other(Utils-ERC1820Registry)")

                elif "sushiswap" in label["labels"]:
                    category = ("Other(SushiSwap)")
                elif label["name"] == "UniswapV2Pair" and "Uniswap V2 (UNI-V2)" in label["labels"]:
                    category = ("Other(UniswapV2)")
                elif label["name"] == "UniswapV3Pool":
                    category = ("Other(UniswapV3)")
                elif label["deployer"] == "Liquity: Deployer":
                    category = ("Other(Liquity)")
                elif label["deployer"] == "0xF82e119A...A034a97b5":
                    category = ("Other(Aave)")
                elif label["deployer"] == "Olympus DAO: Deployer":
                    category = ("Other(Olympus)")
                elif label["deployer"] == "0x49598E2F...97CE8f0bb":
                    category = ("Other(Aave)")
                    label["deployer"] = "Aave Deployer"
                elif "Aave REP: Deployer" in label["deployer"]:
                    category = ("Other(Aave)")
                elif label["deployer"] == "0x7EeAC6CD...7F707289a":
                    category = ("Other(Curve.fi)")
                    label["deployer"] = "CurveFi Deployer"  
                elif "TrueUSD (TUSD)" in label["labels"]:
                    category = ("Other(TrueUSD)")
                elif "chainlink" in label["labels"]:
                    category = ("Other(Chainlink)")
                elif "Synthetix: Deployer" in label["deployer"]:
                    category = ("Other(Synthetix)")
                elif "synthetix" in label["labels"]:
                    category = ("Other(Synthetix)")
                elif "Kyber: Deployer" in label["deployer"]:
                    category = ("Other(Kyber)")
                elif "Kyber" in label["name"]:
                    category = ("Other(Kyber)")
                elif "WethHelper" == label["name"]:
                    category = ("Other(Utils-WethHelper)")
                elif address == "0x37bc7498f4ff12c19678ee8fe19d713b87f6a9e6":
                    category = ("Other(Utils-EthPriceFeed)")
                elif "Convex Finance: Deployer" in label["deployer"]:
                    category = ("Other(Convex)")
                elif "Lido: Deployer" in label["deployer"]:
                    category = ("Other(Lido)")
                elif "DefiDollar: Deployer" in label["deployer"]:
                    category = ("Other(DefiDollar)")
                elif "SushiSwap: Deployer" in label["deployer"]:
                    category = ("Other(SushiSwap)")
                elif "Aave Deployer" in label["deployer"]:
                    category = ("Other(Aave)")
                elif "fei-protocol" in label["labels"]:
                    category = ("Other(Fei)")
                elif "Uniswap (UNI)" in label["labels"]:
                    category = ("Other(Uniswap)")
                elif address == "0xbe7616b06f71e363a310aa8ce8ad99654401ead7":
                    category = ("Other(Compound)")
                elif "Sybil Delegate" in label["deployer"]:
                    category = ("Other(Compound)") 
                elif address == "0x83d055d382f25e6793099713505c68a5c7535a35":
                    category = ("Other(Aave)")
                elif address == "0xed279fdd11ca84beef15af5d39bb4d4bee23f0ca":
                    category = ("Other(Curve.fi)")
                elif "aave" in label["labels"]:
                    category = ("Other(Aave)")
                elif label["deployer"] == "0x536Ee634...66E9B8eC7" or label["deployer"] == "0x8183F851...6FBe08eBA":
                    category = ("Other(Chainlink)")
                elif label["deployer"] == "0x697A7135...27a3fbA0C":
                    category = ("Other(Balancer)")
                elif label["deployer"] == "0x71C05a4e...265d4Bdc8":
                    category = ("Other(Balancer)")

                elif label["deployer"] == "0x61E5E1ea...De9224e99":
                    category = "Other(Chainlink)" 
                elif label["deployer"] == "0x73f2f3A4...a0c0d90aB":
                    category = "Other(Yearn)"

                elif address == "0x2b33cf282f867a7ff693a66e11b0fcc5552e4425":
                    category = "Other(Lido)"
                elif address == "0x1eb4cf3a948e7d72a198fe073ccb8c7a948cd853":
                    category = "Other(Maker)"
                elif address == "0x0d438f3b5175bebc262bf23753c1e53d03432bde":
                    category = "Other(NXM)"
                elif address == "0x2847a5d7ce69790cb40471d454feb21a0be1f2e3":
                    category = "Other(Aave)"
                elif label["deployer"] == "0xbBFE34E8...d7bd88c46":
                    label["deployer"] = "Compound Deployer"
                    category = "Other(Compound)"
                elif address == "0xdcd90c7f6324cfa40d7169ef80b12031770b4325":
                    category = "Other(Yearn)"
                elif "0xbBFE34E8...d7bd88c46" == label["deployer"]:
                    category = "Other(Compound)"
                    label["deployer"] = "Compound Deployer"
                elif address == "0xab53b3906398897f5c4161bfe2ba61d302f00218":
                    category = "Other(Aave)"
                elif address == "0xf236f3eda58287664526ad5c99712d3c1040c759":
                    category = "Other(Kyber)"
                elif address == "0x000f400e6818158d541c3ebe45fe3aa0d47372ff":
                    category = "Other(Utils-ArbitraryCaller)"


                
    


                else:
                    # if label["deployer"] is of the format XXX: Deployer, extract XXX and category is Other(XXX)
                    deployer = label["deployer"]
                    if "Deployer" in deployer:
                        deployer = deployer.split(":")[0]
                        category = f"Other({deployer})"
                        # need to double check!!!! !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

                    else:
                        category = ("TODO")
                

                addLabels2Map(currentTargetProtocol, address, category)

                # if "Target" in category:
                #     print(f"\t{address}")

                print(address)
                print(json.dumps(label))
                print(category)
                print("")
                    
    # # # pretty print Hack2Labels
    # # import pprint
    # # pp = pprint.PrettyPrinter(indent=1)
    # # pp.pprint(Hack2Labels)
    

    # # for key in Hack2Labels:
    # #     print(key)
    # #     asdas = Hack2Labels[key].keys()
    # #     # sort, custimized: E > T > O
    # #     asdas = list(asdas)
    # #     asdas = sorted(asdas, key=lambda x: 0 if "Exploiter" in x else 1 if "Target" in x else 2)
        
    # #     for category in asdas:
    # #         print(f"\t{category}")
    # #         print("\t", len(Hack2Labels[key][category]), end = " ")
    # #         count = 0
    # #         records = []
    # #         for address in Hack2Labels[key][category]:
    # #             if address in closedSourceContract:
    # #                 records.append(address)
    # #                 count += 1
    # #         if count > 0:
    # #             print("\t", count, "of them are closed source")
    # #             if "Other" in category:
    # #                 print("\t", records)
    # #         else:
    # #             print("")


                


