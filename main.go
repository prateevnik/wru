// WRU, "What Are You", a static binary analysis tool

package main

import (
	"flag"
	"fmt"
	"log"
	"time"
	"wru/bayes"
	"wru/crypto"
	"wru/errors"
	"wru/euclid"
	"wru/filechecks"
	"wru/filechecks/windows"
	"wru/persistence"
)

var debug = false

var levelOneVerbosity string // = "Here we will print more verbose output, maybe a line or two.\n Specify as -v"
var levelTwoVerbosity string
var vulnPointerUsage string = "Used to specify that a binary is known to be vulnerable in some way"
var quickBayesianString string = "#Experimental: give rough probability of some things for target file"
var peerGroupPercentageBoundaryString = "plus/minus percentage boundaries from target file, for peer group for quick Bayesian predictions "

//var HorizontalLine = "___________________________________________________________________________________"

func main() {

	go progressWidget(100 * time.Millisecond)

	storedInfoPtr := flag.Bool("storedinfo", false, levelOneVerbosity)
	verbosePtr := flag.Bool("v", false, levelOneVerbosity)
	moreVerbosePtr := flag.Bool("vv", false, levelTwoVerbosity)
	userSuppliedDescriptionPtr := flag.String("description", "", "A phrase describing the target binary")
	vulnerablePtr := flag.Int("vulnerable", -1, vulnPointerUsage)
	numberPeersPtr := flag.Int("peers", 4, "integer number of similar binaries to list, will be rounded down to even number")
	// Bayes is experimental w/ fragile parsing, e.g: bayesian=probability_of:networking>0,given_that:binsz>55000
	bayesianPtr := flag.String("bayesian", "", "Experimental: a parsed argument to obtain conditional probability of X, given Y")
	quickBayesianPtr := flag.Bool("quickbayesian", false, quickBayesianString)
	peerGroupPercentageBoundary := flag.Int("peer_percentage_boundary", 50, peerGroupPercentageBoundaryString)

	flag.Parse()

	args := extractCommandLineArgs()
	targetFile := args[0]

	// SPECIAL CASES where we don't analyze the target file
	if *storedInfoPtr == true {
		fmt.Println(persistence.PrintStoredInfo(targetFile))
		return
	} else if *bayesianPtr != "" {
		//fmt.Println("Bayes is on")
		osType := filechecks.ExternalTestResultAsString(targetFile, "rabin2", "-I", "os", "", 1, "")
		bayes.BayesianAnalysis(*bayesianPtr, osType)
		return
	}
	// end of SPECIAL CASES

	var osType = filechecks.ExternalTestResultAsString(targetFile, "rabin2", "-I", "os", "", 1, "")
	var allTestResults = testOneFile(targetFile, osType)
	var methodsUsed = windows.Methods()

	var targetFileHash, _ = crypto.MD5hashAsPrimaryKey(targetFile) //<== wru sub-package
	persistence.StoreResult(targetFileHash, targetFile, osType, allTestResults, methodsUsed, *userSuppliedDescriptionPtr, *vulnerablePtr)

	if osType == "windows" {

		euclidianPeersArray, functionalityArray, verbosity := doWindowsAnalysis(targetFile, targetFileHash, osType, numberPeersPtr,
			allTestResults, methodsUsed, verbosePtr, moreVerbosePtr, quickBayesianPtr, peerGroupPercentageBoundary)

		printResults(targetFile, verbosity, euclidianPeersArray, functionalityArray)
	} else if osType == "linux" {
		fmt.Println("Support for Linux coming soon!")
	} else {
		fmt.Printf("ah, we don't support this OS yet: %s \n", osType)
	}
}

func doWindowsAnalysis(targetFile string, targetFileHash string, osType string, numberPeersPtr *int,
	allTestResults map[int]map[string]int, methodsUsed string, verbosePtr *bool, moreVerbosePtr *bool, quickBayesianPtr *bool, peerGroupPercentageBoundary *int) ([]string, []string, string) {

	euclidianPeersArray := euclid.GetEuclideanPeers(targetFile, targetFileHash, osType, numberPeersPtr)

	functionalityArray := windows.GetFunctionalityArray(allTestResults, methodsUsed)
	var verbosity string

	if *quickBayesianPtr == true {
		peerBoundary := 50 // default is 50% above and below targetFile's number in each area is the peer group for Bayesian analysis
		if *peerGroupPercentageBoundary > 0 {
			peerBoundary = *peerGroupPercentageBoundary
		}
		verbosity = verbosity + bayes.QuickBayesian(targetFile, targetFileHash, osType, peerBoundary)
	}

	if *verbosePtr == true {
		verbosity = verbosity + windows.GetAttackSurfaceSWAG(targetFile, allTestResults, methodsUsed)
	} else if *moreVerbosePtr == true {
		verbosity = verbosity + windows.GetAttackSurfacePeersAverage(targetFile, allTestResults, methodsUsed)
	} else {
		// pass
	}

	return euclidianPeersArray, functionalityArray, verbosity
}

func printResults(targetFile string, verbosity string, euclidianPeersArray []string, functionalityArray []string) {

	fmt.Printf("\n %s has functionality in the following %d areas:", targetFile, len(functionalityArray))
	for _, area := range functionalityArray {
		fmt.Print("\t", area)
	}
	fmt.Println("\n")

	fmt.Printf("This binary may be similar to these other programs (smaller score means a closer match):\n")
	fmt.Println(errors.HorizontalLine)

	for _, peer := range euclidianPeersArray {
		fmt.Println("\t", peer)
	}

	fmt.Println("\n", verbosity)
}

func extractCommandLineArgs() []string {
	args := flag.Args()
	if len(args) != 1 {
		log.Fatal("Specify one file argument. The file arg must come after any other flags like -v or -vv \n " +
			"Example: wru -v <filename>" +
			"\n\n\t Other command line options: \n" +
			"\t --peers=<integer number of similar binaries to list, will be rounded down to even number>\n" +
			"\t --storedinfo <filename> will print information from our data store on the specified file\n" +
			"\t --description=\"your description of target file\" \n" +
			"\t --vulnerable=1 stores that the specified file is vulnerable (0 sets to NOT vulnerable) \n" +
			"\t --bayesian=<probability_of:something,given_that:precondition> **EXPERIMENTAL**" +
			"\n\t\t e.g: --bayesian=\"probability_of:networking_calls>0,given_that:binsz>55000\" +\n" +
			"\t --quickbayesian " + quickBayesianString + "\n" +
			"\t --peer_percentage_boundary " + peerGroupPercentageBoundaryString +
			"")

	}
	return args
}

// meh, need to ensure that the Radare2 binary 'rabin2' is in the $PATH when run
func testOneFile(targetFile string, osType string) map[int]map[string]int {
	// store various test scores in map object, where the key value is numeric order of tests (Go has no Set type)
	// will need to branch into different test suites for Windows vs. Linux, etc., based on what each binary provides

	scores := make(map[int]map[string]int)
	scoresKeyCounter := 0

	codeSizeMap := make(map[string]int)
	// below: use regex "sz=" to splt up 3rd slice which will look like 'sz=13599'. Overkill but regex flexibility for future..
	codeSizeScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-S", ".text", "", 3, "sz=")
	codeSizeMap["codeSize"] = codeSizeScore
	scores[scoresKeyCounter] = codeSizeMap
	scoresKeyCounter = scoresKeyCounter + 1

	binszMap := make(map[string]int)
	binszScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-I", "binsz", "", 1, "")
	binszMap["binsz"] = binszScore
	scores[scoresKeyCounter] = binszMap
	scoresKeyCounter = scoresKeyCounter + 1

	symbolsMap := make(map[string]int)
	symbolsScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-s", "symbols", "Symbols", 0, "")
	symbolsMap["symbols"] = symbolsScore
	scores[scoresKeyCounter] = symbolsMap
	scoresKeyCounter = scoresKeyCounter + 1

	sectionsMap := make(map[string]int)
	sectionsScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-S", "sections", "", 0, "")
	sectionsMap["sections"] = sectionsScore
	scores[scoresKeyCounter] = sectionsMap
	scoresKeyCounter = scoresKeyCounter + 1

	libraryMap := make(map[string]int)
	libraryScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-l", "librar", "Linked libraries", 0, "") // # of linked libraries
	libraryMap["library_count"] = libraryScore
	scores[scoresKeyCounter] = libraryMap
	scoresKeyCounter = scoresKeyCounter + 1

	importsMap := make(map[string]int)
	importsScore := filechecks.ExternalTestResult(targetFile, "rabin2", "-i", "imports", "", 0, "") // # of imports
	importsMap["imports"] = importsScore
	scores[scoresKeyCounter] = importsMap
	scoresKeyCounter = scoresKeyCounter + 1

	dataSectionStringsCountMap := make(map[string]int)
	dataSectionStringCount := filechecks.ExternalTestResultLineCount(targetFile, "rabin2", "-z") // # of strings in .data section.  .data is where initialized data goes
	dataSectionStringsCountMap["numDataStrings"] = dataSectionStringCount
	scores[scoresKeyCounter] = dataSectionStringsCountMap
	scoresKeyCounter = scoresKeyCounter + 1

	wholeFileStringsCountMap := make(map[string]int)
	wholeFileStringCount := filechecks.ExternalTestResultLineCount(targetFile, "rabin2", "-zz") // # of strings in entire file
	wholeFileStringsCountMap["numWholeFileStrings"] = wholeFileStringCount
	scores[scoresKeyCounter] = wholeFileStringsCountMap
	scoresKeyCounter = scoresKeyCounter + 1

	// for now, rationale is that OS specific checks likely to be customized to OS,
	// so better to have have OS tests in an IF block, for each OS. We'll see if this proves best..
	if osType == "windows" {
		libCategoriesCount := windows.Libraries(targetFile) //libCategoriesCount = map[int]map[string]int
		//fmt.Println("from main.testOneFile, libCategoriesCount = ", libCategoriesCount)
		//fmt.Println(libCategoriesCount) // map[3:map[UI:0] 4:map[REGISTRY:0] 5:map[SECURITY:0] 6:map[CRYPTO:0] 7:map[unknown:74] 0:map[system:16] 1:map[NETWORKING:0] 2:map[MEDIA:0]]
		for i := 0; i < len(libCategoriesCount); i++ {
			var littleMap = libCategoriesCount[i]
			if debug {
				fmt.Println("FTW! retrieved Windows library category map is ", littleMap)
			}
			scores[scoresKeyCounter] = littleMap
			scoresKeyCounter = scoresKeyCounter + 1
		}
	}

	if debug {
		fmt.Println("#################")
		fmt.Println("ABOUT TO RETURN SCORES:")
		fmt.Println(scores)
		fmt.Println("#################")
	}
	return scores
}

func progressWidget(delay time.Duration) {
	for {
		for _, r := range `-\|/` {
			fmt.Printf("\r%c", r)
			time.Sleep(delay)
		}
	}
}
