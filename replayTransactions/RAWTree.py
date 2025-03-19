import sys

class RAWTree:
    def __init__(self, resultsStorageReads, resultsStorageWrites, results):
        if len(resultsStorageReads) != len(resultsStorageWrites):
            sys.exit("len(resultsStorageReads) != len(resultsStorageWrites)")
        if len(resultsStorageReads) != len(results):
            sys.exit("len(resultsStorageReads) != len(results)")
        self.RAWListDependentOnPrevious = []
        self.RAWListDependentOnFuture = []
        self.results = results
        for _ in range(0, len(resultsStorageReads)):
            self.RAWListDependentOnPrevious.append([])
            self.RAWListDependentOnFuture.append([])

        for i in range(1, len(resultsStorageReads)):
            currentStorageReads = resultsStorageReads[i]
            for j in range(0, i):
                previousStorageWrites = resultsStorageWrites[j]

                isDependent = False
                for key in currentStorageReads:
                    if key in previousStorageWrites:
                        isDependent = True
                        break
                if isDependent:
                    self.RAWListDependentOnPrevious[i].append(j)
                    self.RAWListDependentOnFuture[j].append(i)


        
    def isReadAfterWriteOnce(self):
        for i in range(0, len(self.RAWListDependentOnPrevious)):
            if len(self.RAWListDependentOnPrevious[i]) > 0:
                return True
        return False


    def splittedResults(self):
        new_results_indexes = []

        for i in range(0, len(self.results)):
            isAlreadyIn = False
            for a_set in new_results_indexes:
                if i in a_set:
                    isAlreadyIn = True
                    break
            if not isAlreadyIn:
                new_results_indexes.append( [i] )
                currentStack = [i]
                while len(currentStack) > 0:
                    current = currentStack.pop()
                    for dependent in self.RAWListDependentOnFuture[current]:
                        if dependent not in new_results_indexes[-1]:
                            currentStack.append(dependent)
                            new_results_indexes[-1].append(dependent)
                    for dependent in self.RAWListDependentOnPrevious[current]:
                        if dependent not in new_results_indexes[-1]:
                            currentStack.append(dependent)
                            new_results_indexes[-1].append(dependent)

        # sort all sublists in new_results
        for i in range(0, len(new_results_indexes)):
            new_results_indexes[i].sort()
        
        new_results = []
        for indexes in new_results_indexes:
            new_results.append([self.results[i] for i in indexes])

        return new_results 
    


if __name__ == "__main__":
    resultsStorageReads = [{1: 1, 2: 2}, {3: 3}, {4: 4}, {5: 5}, {6:6}, {7:7}]
    resultsStorageWrites = [{1: 1, 2: 2}, {1: 1}, {2: 2}, {5: 5}, {5:5}, {-1:-1, -2:-2}]
    results = ["one", "two", "three", "four", "five", "siz"]
    rawTree = RAWTree(resultsStorageReads, resultsStorageWrites, results)
    print(rawTree.RAWListDependentOnPrevious)
    print(rawTree.RAWListDependentOnFuture)

    print(rawTree.isReadAfterWriteOnce())
    print(rawTree.splittedResults())
    pass
        




        


