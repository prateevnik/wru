package windows

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"wru/errors"
	"wru/euclid"
	"wru/filechecks"
	"wru/persistence"
)

var debug = false
var importedLibraries string

func getLibrariesForThisFile(scrapedLibsForThisFile string) []string {
	// index 7 for libname. Do REGEX for each line. TrimSpace etc. if needed.
	// Then stuff into array.
	var librariesForThisFile []string
	lines := strings.Split(scrapedLibsForThisFile, "\n")
	for _, line := range lines {

		if strings.Contains(strings.ToLower(line), ".dll") { // FIXME ugly matching
			bits := strings.Fields(line)
			rawlib := bits[7] // name=imp.cygssl-1.0.0.dll_SSL_library_init
			//dllIndex := strings.Index(rawlib,".dll")
			// fmt.Println("index of .dll is: ", dllIndex)
			libChunks := strings.Split(rawlib, ".")

			oneLibrary := pickOutDLLname(libChunks)
			oneLibrary = oneLibrary + "dll"

			//oneLib := libChunks[1] + ".dll"
			librariesForThisFile = append(librariesForThisFile, oneLibrary)
		}
	}
	return librariesForThisFile
}

func pickOutDLLname(libChunks []string) string {
	var oneLibrary string
	for _, chunk := range libChunks {
		chunk = strings.ToLower(chunk)
		// fmt.Println(chunk)
		if strings.Contains(chunk, "name=imp") {
			// pass
		} else if strings.Contains(chunk, "dll") {
			// pass
		} else {
			oneLibrary = oneLibrary + chunk + "."
		}
	}
	return oneLibrary
}

func getMapNumberLibCallsForEachLibrary(librariesForThisFile []string, uniqueImportedLibraries []string) []map[string]int {
	var libraryCalls []map[string]int                          // an *array* of maps, where map is of type string:int
	for _, oneUniqueLibrary := range uniqueImportedLibraries { // BEGIN for EACH LIB
		oneLibMap := make(map[string]int)
		libCount := 0

		// find how many times the lib is called
		for i := 0; i < len(librariesForThisFile); i++ {
			if oneUniqueLibrary == librariesForThisFile[i] {
				libCount = libCount + 1
			}
		}
		oneLibMap[oneUniqueLibrary] = libCount
		libraryCalls = append(libraryCalls, oneLibMap)
	} // END EACH LIB
	return libraryCalls
}

// Methods returns string like "Library1.method; libary1.method2; lib2.method3". Don't like that
// we're calling rabin2 -s more than once, but will avoid performance optimization for now...
// well, let's try setting a package variable 'importedLibraries', can't resist .. fingers crossed this doesn't become a shared state bug
func Methods() string { // want to return somethign like "Library1.method; libary1.method2; lib2.method3"
	var concatenatedMethodsString string
	matchingLines := getArrayOfStringsMatchingPatternExcludeString(importedLibraries, "name=imp.*", "name=imp.") // Go's RE2 regex acts weird but this seems to work..

	count := 0
	seperator := ""
	for _, libCall := range matchingLines {
		if count > 0 {
			seperator = ";"
		}
		concatenatedMethodsString = concatenatedMethodsString + seperator + libCall
		count = count + 1
	}
	//fmt.Println("windows.Methods ret: ", concatenatedMethodsString)
	return concatenatedMethodsString
}

func getArrayOfStringsMatchingPatternExcludeString(rawString string, regexExpr string, excludeString string) []string {
	matchArray := strings.Split(rawString, "\n")
	ourRegex := regexp.MustCompile(regexExpr)
	unserStringArray := make([]string, 0)

	for _, element := range matchArray {
		matchingTerm := ourRegex.FindString(element)
		if len(matchingTerm) > 0 {
			unserString := strings.TrimPrefix(matchingTerm, excludeString)
			unserStringArray = append(unserStringArray, unserString)
		}
	}
	return unserStringArray
}

// Libraries parses info on imported Libraries in Windows
// TODO: only scrape libs with 'rabin2 -s' once, right now we're doing it
// each time we call this for a certain libraryCategory, hella inefficient :(
// func Libraries(targetFile string, libraryCategory string) map[string]int {
func Libraries(targetFile string) map[int]map[string]int {
	importedLibraries = filechecks.ScrapeAllOutPut(targetFile, "rabin2", "-s")
	errors.Debug(debug, "filechecks/windows::Libraries, importedLibraries >>> ", importedLibraries)

	librariesForThisFile := getLibrariesForThisFile(importedLibraries)
	uniqueImportedLibraries := MapUniqueStrings(librariesForThisFile)
	if debug {
		fmt.Println("filechecks/windows::Libraries, uniqueImportedLibraries ==", uniqueImportedLibraries)
	}
	// Below:  libraryCalls = []map[string]int, an *array* of maps, where map is of type string:int
	libraryCalls := getMapNumberLibCallsForEachLibrary(librariesForThisFile, uniqueImportedLibraries) // [map[KERNEL32.dll:62] map[WSOCK32.dll:25]]

	libCategoryCount := getLibCategoryCountMap(libraryCalls)
	return libCategoryCount // OLD: map[UI:0 REGISTRY:0 SECURITY:0 CRYPTO:0 unknown:74 system:16 NETWORKING:0 MEDIA:0]
}

func getLibCategoryCountMap(libraryCalls []map[string]int) map[int]map[string]int {
	categories := persistence.GetLibCategories()

	libCategoryCount := make(map[int]map[string]int)
	orderCounter := 0
	for _, category := range categories { //range = [system NETWORKING MEDIA UI REGISTRY SECURITY CRYPTO]
		oneCategoryCountMap := make(map[string]int)
		totalCallsForThisCategory := addUpCallsFromUsedLibraries(category, libraryCalls)
		oneCategoryCountMap[category] = totalCallsForThisCategory
		libCategoryCount[orderCounter] = oneCategoryCountMap
		orderCounter = orderCounter + 1
	}

	if debug {
		fmt.Println("::getLibCategoryCountMap", libCategoryCount)
	}
	return libCategoryCount
}

// just total up the number of calls for a given category (e.g. "networking") from all imported libraries
func addUpCallsFromUsedLibraries(category string, libraryCalls []map[string]int) int {
	var totalCallsForThisCategory int
	for _, libraryMap := range libraryCalls {

		// fmt.Println(libraryMap) // map[OLEACC.dll:4], looks good:)
		// get category for this library, SQLquery
		// if it's not in current category, just skip
		// otherwise add to total int
		for libraryName, numCalls := range libraryMap {
			thisLibCategory := persistence.GetLibraryCategory(libraryName)

			errors.Debug(debug, "filechecks/windows::addUpCallsFromUsedLibraries, thisLibCategory SQL gets: ", thisLibCategory, " our library at hand is: ", libraryName)

			if thisLibCategory == category {
				totalCallsForThisCategory = totalCallsForThisCategory + numCalls
			} else {
				errors.Debug(debug, "This one did *not* match current library category: ", libraryName)
			}
		}
	}
	return totalCallsForThisCategory
}

/* GetFunctionalityArray returns array of only those library categories that were used by targetFile, e.g. NETWORKING: 14 calls, etc.
   Also does method name guessing too.  Supposing the number of category functions identified by
   library names is X, and the number of category functions identified by function names is Y, then:
      use whichever estimate for the category (X or Y) is greater
*/
func GetFunctionalityArray(allTestResults map[int]map[string]int, methodsUsed string) []string {
	functionalityArray := make([]string, 0)
	// pull library category labels out of DB table.
	uniqueLibCategories := persistence.GetLibCategories()

	for _, oneMap := range allTestResults {

		for k, v := range oneMap {
			thisKey := strings.ToUpper(k)

			//-- BEGIN logic for each category, eg. NETWORKING --//
			for _, category := range uniqueLibCategories {
				if thisKey == category {
					highestNumberEstimatedFunctions := getLargestOfLibraryOrFunctionEstimates(v, methodsUsed, category)
					functionalityArray = append(functionalityArray, category+": "+strconv.Itoa(highestNumberEstimatedFunctions)+" functions ")
				}
			}
			//-- END logic for each category, eg. NETWORKING --//
		}
	}
	if debug {
		fmt.Println(functionalityArray)
	}
	return functionalityArray
}

func getLargestOfLibraryOrFunctionEstimates(v int, methodsUsed string, category string) int {
	highestNumberEstimatedFunctions := 0
	library_CentricCandidateNumber := 0

	if v > 0 {
		library_CentricCandidateNumber = v
		//fmt.Println("libraryCentricCandidateNumber for ", category, " = ", strconv.Itoa(library_CentricCandidateNumber))
	}

	function_Name_GuessingCandidateNumber := GetNumberFunctionsByGuessingNames(methodsUsed, category)

	if function_Name_GuessingCandidateNumber > library_CentricCandidateNumber {
		highestNumberEstimatedFunctions = function_Name_GuessingCandidateNumber
	} else {
		highestNumberEstimatedFunctions = library_CentricCandidateNumber
	}
	return highestNumberEstimatedFunctions
}

/*
GetNumberFunctionsByGuessingNames should be a method that pulls methods by name.. should have this already somewhere
then for each method, see if it matches the listing of category matches, eg NETWORKING has 'inet', 'gethostby' etc
*/
func GetNumberFunctionsByGuessingNames(methodsUsed string, category string) int {
	//errors.Debug(debug, "methodsUsed = ", methodsUsed, "category= ", category)
	// fmt.Println("::GetNumberFunctionsByGuessingNames,  methodsUsed = ", methodsUsed, "category= ", category) // cygwin1.dll___cxa_atexit;cygwin1.dll___errno, etc.
	var numberFunctionsForCategory = 0
	libMethodPairs := strings.Split(methodsUsed, ";")
	for _, pair := range libMethodPairs {

		rawSplit := strings.Split(strings.ToLower(pair), ".dll_")
		function := rawSplit[1]

		// NOW see if function matches something for category at hand, from our SQLlite db...
		guessingWordsArray := persistence.GetGuessingWords(category)
		//fmt.Println(guessingWordsArray)
		for _, category_word_snippt := range guessingWordsArray {
			if strings.Contains(function, category_word_snippt) {
				//fmt.Println("HIT!  function ", function, " contains ", category_word_snippt, " for ", category)
				numberFunctionsForCategory = numberFunctionsForCategory + 1
			}
		}
	}

	if debug {
		fmt.Println("::GetNumberFunctionsByGuessingNames, for category ", category, " we guessed # = ", strconv.Itoa(numberFunctionsForCategory))
	}
	return numberFunctionsForCategory
}

// GetAttackSurfaceSWAG is just a Scientific Wild Ass Guess about
// how much attack surface a binary offers, to aid in deciding whether
// to manually debug / analyze it or not
func GetAttackSurfaceSWAG(targetFile string, allTestResults map[int]map[string]int, d string) string {

	codeSegmentInBytes := getCodeSegmentSizeInBytes(allTestResults)

	averageBinSz := persistence.GetAverageBinarySize("windows")
	avgBinSzInt, _ := strconv.Atoi(averageBinSz) // probably an unnecessary cast from string to int
	relativePercentage := (float64(codeSegmentInBytes-avgBinSzInt) / float64(avgBinSzInt)) * 100

	relativeAdjective := "% *smaller* "
	if relativePercentage > 0 {
		relativeAdjective = "% LARGER "
	}

	numberUsedLibCategories := len(GetFunctionalityArray(allTestResults, d))
	swag := "Code instruction segment for " + targetFile + " is " + strconv.Itoa(codeSegmentInBytes) +
		" bytes, which is " + strconv.FormatFloat(relativePercentage, 'f', 0, 64) + relativeAdjective + "than the average in our DB." +
		"\nNumber of identified library categories is " + strconv.Itoa(numberUsedLibCategories)

	logOfCodeSize := int(euclid.LogOrZero(float64(codeSegmentInBytes))) // ugly :(
	swag = putQualitativeLabelOnSWAGscore(logOfCodeSize, numberUsedLibCategories, swag, targetFile)
	return swag
}

func getCodeSegmentSizeInBytes(allTestResults map[int]map[string]int) int {
	var codeSegmentInBytes int
	for _, oneMap := range allTestResults {
		for k, v := range oneMap {
			thisKey := strings.ToLower(k)
			if thisKey == "binsz" {
				//fmt.Printf("::GetAttackSurfaceSWAG, binsz = %d \n", v)
				codeSegmentInBytes = v
			}
		}
	}
	return codeSegmentInBytes
}

func putQualitativeLabelOnSWAGscore(logOfCodeSize int, numberUsedLibCategories int, swag string, targetFile string) string {
	swagScore := logOfCodeSize + numberUsedLibCategories
	if swagScore > 8 {
		swag = swag + "\nSWAG: attack surface for debugging/analyzing " + targetFile + " is LARGE"
	} else if swagScore > 7 {
		swag = swag + "\nSWAG: attack surface for debugging/analyzing " + targetFile + " is LARGER THAN AVERAGE"
	} else if swagScore > 6 {
		swag = swag + "\nSWAG: attack surface for debugging/analyzing " + targetFile + " is MEDIUM"
	} else {
		swag = swag + "\nSWAG: attack surface for debugging/analyzing " + targetFile + " is SMALL"
	}
	return swag
}

// GetAttackSurfacePeersAverage does a DB query to compare attack surface average attack surface in our peer group
func GetAttackSurfacePeersAverage(targetFile string, allTestResults map[int]map[string]int, d string) string {
	peerSwag := GetAttackSurfaceSWAG(targetFile, allTestResults, d) // start with -v info..
	// could this:  select avg(binsz) from filestore
	peerSwag = peerSwag + "..ADDITIONAL VERBOSITY NOT WORKED OUT YET."
	return peerSwag
}

/*
MapUniqueStrings might be useful elsewhere. So exporting for now.
*/
func MapUniqueStrings(passedArray []string) []string {
	m := map[string]bool{}
	t := []string{}

	for _, v := range passedArray {
		if _, seen := m[v]; !seen {
			t = append(t, v)
			m[v] = true
		}
	}
	return t
}
