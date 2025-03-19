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
from constraintPackage.utils import *
import numpy as np
import pandas as pd

NOTCOLLECTED = -1
REVERTED = -1
NOFUNCACCESS = 0
DEPLOYER = 1
SIMPLE = 2
OTHERDEFI = 3
MEV = 4
USERASSISTED = 5
HACK = 6


class txLabeler:
    # label -1: not collected OR transaction reverted
    # label 0: no function access
    # label 1: Transactions from deployers, privileged transactions
    # label 2: Simple Transactions, directly sent from one of the functions of router contracts
    # label 3: another famous defi protocol 
    # label 4: MEV
    # label 5: 
    # label 6: hack
    def __init__(self, benchmark):
        self.targetContracts = benchmark2targetContracts[benchmark]
        self.deployers = []
        self.ce = CrawlEtherscan()
        for contract in self.targetContracts:
            deployer = self.ce.Contract2Deployer(contract).lower()
            if deployer not in self.deployers:
                self.deployers.append(deployer)
        self.classifier = classifier()
        self.benchmark = benchmark
        if benchmark in benchmark2hack:
            self.hack = benchmark2hack[benchmark]
        if benchmark in ["AAVE2", "Lido2", "Uniswap2"]:
            self.hack = "0xNotAvailable"


        self.knownTxsNotCollected = [
            "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec",
            "0x52a0541deff2373e1098881998b60af4175d75c410d67c86fcee850b23e61fc2",
            "0xca13006944e6eba2ccee0b2d96a131204491641014622ef2a3df3db3e6939062",
            "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec",
            "0x9ef7a35012286fef17da12624aa124ebc785d9e7621e1fd538550d1209eb9f7d",
            "0xd770356649f1e60e7342713d483bd8946f967e544db639bd056dfccc8d534d8e",
            "0xed7efd5bf771ae1e115fb59b9f080c2f66d74bf3c9234a89acb0e91e48181aec"
        ]




    def label(self, tx):

        tx_category = None
        
        block = self.ce.Tx2Block(tx)
        receipt = self.ce.Tx2Receipt(tx)
        to = receipt["to"]
        status = receipt["status"]
        from_ = receipt["from"]
        if not isinstance(status, int):
            status = int(status, 16)

        # Category -1: Reverted
        if status == 0 or tx in revertedTransactions:
            return REVERTED
        
        if from_ in self.deployers:
            return DEPLOYER
        
        if to is None:
            to = receipt["contractAddress"]
        if to is None:
            sys.exit("to is None")
        
        # Category 2: Simple Transactions, directly sent from one of the functions of router contracts
        if to in self.targetContracts:
            tx_category = 2
        
        # Category 1/3/4/5/6: if we have classified the contract
        category = self.classifier.benchmark_contract2Category(self.benchmark, to)
        if category != None:
            if category.lower() == "hack":
                return HACK
            else:
                tx_category = int(category)
                return tx_category

        # Category 1: Transactions from deployers
        details = self.ce.Tx2Details(tx)
        if "from" in details and details["from"] in self.deployers:
            tx_category = DEPLOYER
        if tx == self.hack:
            tx_category = HACK 

        # Category 0: No function access
        jsonGzPath = SCRIPT_DIR + "/../constraintPackage/cache/functionAccess/{}/{}.json".format(self.benchmark, block)
        if not os.path.exists(jsonGzPath):
            if tx in self.knownTxsNotCollected:
                return NOTCOLLECTED
            else:
                # sys.exit("{} not exists".format(jsonGzPath))
                return NOTCOLLECTED

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
            return NOFUNCACCESS
        
        if tx_category == None:
            # print(functionAccess)
            print("tx_category is None for tx ", tx)

        return tx_category
    
    

