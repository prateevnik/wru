package bayes

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"wru/errors"
	"wru/persistence"
)

var debug = false

/* QuickBayesian : for each measure (e.g. binsz, etc) get peer group of binaries within plus/minus 50% of targetFile.  Get the Bayesian probability
of each lib category (NETWORKING, DATABASE) and 'known_vulnerable' for targetFile based on the +/- 50% peer universe.  Then get
 the *average* of all the probabilities of each category, to give the average Bayesian probability of NETWORKING, DATABASE, etc.
 Return these averaged probabilities for targetFile to have certain capabilities as a formatted string.
*/

// QuickBayesian gets average Bayesian probabilities of important things
func QuickBayesian(targetFile string, targetFileHash string, osType string, peerGroupPercentageBoundary int) string {
	libCategories := make([]string, 0)
	libCategories = append(libCategories, "NETWORKING", "MEDIA", "UI", "REGISTRY", "SECURITY", "CRYPTO", "DATABASE")
	//libCategories = append(libCategories, "NETWORKING") // FIXME limiting categories while troubleshooting
	// fields in DB, all are pattern <LABEL>_calls
	// networking_calls, media_calls, UI_calls, registry_calls, security_calls, crypto_calls,

	errors.Debug(debug, "::QuickBayesian -- targetFile = ", targetFile, ", targetFileHash = ",
		targetFileHash, " peerGroupPercentageBoundary=", strconv.Itoa(peerGroupPercentageBoundary))

	bayesianResultsString := "\n[BAYESIAN estimates: would get rough prob. of some things for target file, +/- boundary=" + strconv.Itoa(peerGroupPercentageBoundary) + "]"

	for _, libCategory := range libCategories {
		errors.Debug(debug, "::QuickBayesian, loop over libCategories, now on: ", libCategory)
		tabElement := "\t\t"
		if len(libCategory) > 6 {
			tabElement = "\t"
		}
		bayesianResultsString = bayesianResultsString + "\n\t" + libCategory + tabElement +
			deriveAverageProbabilityOfThisCategory(libCategory, peerGroupPercentageBoundary, targetFile, targetFileHash, osType) + "%"
	}
	bayesianResultsString = bayesianResultsString + "\n" + errors.HorizontalLine + "\n"

	return bayesianResultsString
}

func deriveAverageProbabilityOfThisCategory(category string, peerGroupPercentageBoundary int, targetFile string, targetFileHash string, osType string) string {

	peerMeasures := getFieldsToCreatePeersBy()

	var runningSum, counter float64 // initializes to zero, as expected

	for _, measure := range peerMeasures {
		//fmt.Println("Need to do something with 'measure' here in each of the 3 methods below.. ", measure)
		probabilityOfPriorGivenPosterior := quickBayesianProbabilityOfPriorGivenPosterior(category, measure, peerGroupPercentageBoundary, targetFile, targetFileHash, osType)
		probabilityOfPosterior := quickBayesianProbabilityOfPosterior(category, osType)
		probabilityOfPrior := quickBayesianProbabilityOfPrior(category, measure, peerGroupPercentageBoundary, targetFile, targetFileHash, osType)

		thisPeerMeasureBayesProbability := Theorem(probabilityOfPriorGivenPosterior, probabilityOfPosterior, probabilityOfPrior)
		errors.Debug(debug, "thisPeerMeasureBayesProbability is: ", strconv.FormatFloat(thisPeerMeasureBayesProbability, 'f', 4, 64))
		// if test, for NaN .. such as a divide by zero error
		if math.IsNaN(thisPeerMeasureBayesProbability) {
			// skip this one... a divide by zero error or something
		} else {

			runningSum = runningSum + thisPeerMeasureBayesProbability
			errors.Debug(debug, "runningSum is now: ", strconv.FormatFloat(runningSum, 'f', 4, 64))
			counter = counter + 1
		}
	}
	errors.Debug(debug, "::deriveAverageProbabilityOfThisCategory, runningSum was ", strconv.FormatFloat(runningSum, 'f', 4, 64), ", counter was ", strconv.FormatFloat(counter, 'f', 4, 64))
	averageProbabilityForThisCategory := computeAverageProbabilityForThisCategory(runningSum, counter)
	// Below: 0.181 becomes 18.1, for printing as '18.1 %'
	averageProbabilityForThisCategory = averageProbabilityForThisCategory * 100

	printMe := strconv.FormatFloat(averageProbabilityForThisCategory, 'f', 1, 64)
	return printMe
}

func computeAverageProbabilityForThisCategory(runningSum float64, counter float64) float64 {
	// <== get the average Bayes prob for this category (such as NETWORKING) occuring, across peer measures..
	averageProbabilityForThisCategory := runningSum / counter
	return averageProbabilityForThisCategory
}

//******* STUBBING it out here,

/*
   examples based on answering: what is probability of NETWORKing, given that the code_size is between 51000 and 153000 bytes?
   The code_size is taken from zip.exe as a reference to work with.
*/
/*
 Example: what is the probability of code_size being between roughly 51000 and 153000 bytes, given that the program is known to have NETWORKing?  (using the entire universe
 of binaries of same osType in our DB )   TODO still
*/
func quickBayesianProbabilityOfPriorGivenPosterior(category string, measure string, peerGroupPercentageBoundary int, targetFile string, targetFileHash string, osType string) float64 {
	errors.Debug(debug, "::quickBayesianProbabilityOfPriorGivenPosterior .. we have ", targetFile, targetFileHash, osType, strconv.Itoa(peerGroupPercentageBoundary))
	// step 1: get universe of progs, with osType, having the category of interest (such as NETWORKING).  We'll call this 'variable y'
	y_numberRecordsHavingCategoryOfInterest := getNumberRecordsHavingCategoryOfInterest(category, osType)

	// step 2: get number of programs from universe used for step 1 that have 'measure' within upper and lower bounds specified.  We'll call this 'variable x'
	x_numberRecordsWithinCategoryMeetingBoundsCriteria := getNumberRecordsWithCategoryMeetingBoundsCriteria(category, measure, osType, peerGroupPercentageBoundary, targetFileHash)

	// step 3: divide x by y, return float value (should be between 0 and 1.0)
	probabilityOfPriorGivenPosterior := x_numberRecordsWithinCategoryMeetingBoundsCriteria / y_numberRecordsHavingCategoryOfInterest
	errors.Debug(debug, "::quickBayesianProbabilityOfPriorGivenPosterior, will return: ", strconv.FormatFloat(probabilityOfPriorGivenPosterior, 'f', 2, 64))
	if probabilityOfPriorGivenPosterior > 1 {
		fmt.Fprintln(os.Stderr, "::quickBayesianProbabilityOfPriorGivenPosterior - probability is IMPOSSIBLE, greater than 1.0")
	}
	return probabilityOfPriorGivenPosterior
}

// Step1: Get universe of binaries, with osType, having the category of interest (such as NETWORKING).  We'll call this 'variable y'
func getNumberRecordsHavingCategoryOfInterest(category string, osType string) float64 {
	sqlQuery := "SELECT COUNT(*) FROM filestore WHERE " + category + "_calls > 0 AND os_type = '" + osType + "' "
	errors.Debug(debug, sqlQuery)
	NumberRecordsHavingCategory := persistence.DoBuiltUpPreparedQuery(sqlQuery)
	floatNumberRecordsHavingCategory, err := strconv.ParseFloat(NumberRecordsHavingCategory, 64)
	if err != nil {
		errors.Debug(debug, "::getNumberRecordsHavingCategoryOfInterest blew up ...trying to cast string to float64")
		panic(err)
	}
	errors.Debug(debug, "::getNumberRecordsHavingCategoryOfInterest , about to return: ", NumberRecordsHavingCategory)
	return floatNumberRecordsHavingCategory
}

// Step 2: Get  number of binaries from universe used for step 1 that have 'measure' within upper and lower bounds specified.  We'll call this 'variable x'
func getNumberRecordsWithCategoryMeetingBoundsCriteria(category string, measure string, osType string, peerGroupPercentageBoundary int, targetFileHash string) float64 {
	lowerBound, upperBound, NumberRecordsWithinBounds := getNumberOfRecordsWithinUpperLowerBounds(targetFileHash, measure, osType, peerGroupPercentageBoundary)
	errors.Debug(debug, "::getNumberRecordsWithCategoryMeetingBoundsCriteria, lowerBound is ", lowerBound, ", upperBound is ", upperBound, ", NumberRecordsWithinBounds is ", NumberRecordsWithinBounds)
	// SELECT count(*) FROM filestore WHERE  NETWORKING_calls > 0 AND os_type = 'windows' AND code_size > 51000 AND code_size < 150000
	sqlQuery := "SELECT COUNT(*) FROM filestore WHERE " + category + "_calls > 0 AND os_type = '" + osType + "' AND " + measure + " > " + lowerBound + " AND " + measure + " < " + upperBound
	errors.Debug(debug, "::getNumberRecordsWithCategoryMeetingBoundsCriteria--> ", sqlQuery)
	NumberRecordsHavingCategoryAndWithinBounds := persistence.DoBuiltUpPreparedQuery(sqlQuery)
	floatNumberRecordsHavingCategoryAndWithinBounds, err := strconv.ParseFloat(NumberRecordsHavingCategoryAndWithinBounds, 64)
	if err != nil {
		errors.Debug(debug, "::getNumberRecordsWithCategoryMeetingBoundsCriteria blew up ...trying to cast string to float64")
		panic(err)
	}
	errors.Debug(debug, "::getNumberRecordsWithCategoryMeetingBoundsCriteria , about to return: ", NumberRecordsHavingCategoryAndWithinBounds)
	return floatNumberRecordsHavingCategoryAndWithinBounds
}

//******* END STUBBING

// Example: what is the probability of NETWORKing, at all? Given the whole universe of programs in our DB.  ** WORKS :) **
func quickBayesianProbabilityOfPosterior(category string, osType string) float64 {
	probabilityOfThisCategory := persistence.GetProbabilityOfSomething(category+"_calls", ">", "0", osType)
	errors.Debug(debug, "::quickBayesianProbabilityOfPosterior, will return this probability: ", strconv.FormatFloat(probabilityOfThisCategory, 'f', 4, 64))
	return probabilityOfThisCategory
}

// Example: what is the probability of a program having code_size between 51000 and 153000 bytes? Given the whole universe of programs in our DB.
// Note: have to first get code_size of targetFile, then computer lower and upper bounds to select peer binary universe.
// e.g. SELECT COUNT(code_size) FROM filestore WHERE code_size > 51000 and code_size < 153000 AND os_type = 'windows'
func quickBayesianProbabilityOfPrior(category string, measure string, peerGroupPercentageBoundary int, targetFile string, targetFileHash string, osType string) float64 {

	lowerBound, upperBound, NumberRecordsWithinBounds := getNumberOfRecordsWithinUpperLowerBounds(targetFileHash, measure, osType, peerGroupPercentageBoundary)

	floatNumberRecordsWithinBounds, err1 := strconv.ParseFloat(NumberRecordsWithinBounds, 64)
	errors.Debug(debug, "::quickBayesianProbabilityOfPrior, number of records where ", measure, " is more than ", lowerBound, " and less than ", upperBound, " is ", strconv.FormatFloat(floatNumberRecordsWithinBounds, 'f', 2, 64))
	if err1 != nil {
		log.Fatal(err1)
	}

	totalRecordsForOStype := persistence.GetFloat64TotalRecords(osType)
	probabilityOfPrior := floatNumberRecordsWithinBounds / totalRecordsForOStype

	errors.Debug(debug, "floatNumberRecordsWithinBounds = ", strconv.FormatFloat(floatNumberRecordsWithinBounds, 'f', 2, 64), ", totalRecordsForOStype=",
		strconv.FormatFloat(totalRecordsForOStype, 'f', 2, 64), ", ergo, probabilityOfPrior= ", strconv.FormatFloat(probabilityOfPrior, 'f', 2, 64))

	return probabilityOfPrior
}

func getNumberOfRecordsWithinUpperLowerBounds(targetFileHash string, measure string, osType string, peerGroupPercentageBoundary int) (string, string, string) {
	targetFileMeasureValue := retrieveMeasureValueForTargetFile(targetFileHash, measure, osType)
	errors.Debug(debug, "::quickBayesianProbabilityOfPrior, targetFileMeasureValue for ", measure, " = ", strconv.FormatFloat(targetFileMeasureValue, 'f', 2, 64))

	errors.Debug(debug, "::quickBayesianProbabilityOfPrior, percentageBoundary = ", strconv.Itoa(peerGroupPercentageBoundary))
	margin := float64(peerGroupPercentageBoundary)
	// so 50 becomes 50.0
	margin = margin / 100
	lowerBoundMultiplier := float64(1.0 - margin)
	if lowerBoundMultiplier < 0 {
		lowerBoundMultiplier = 0.0
	}
	upperBoundMultiplier := float64(1.0 + margin)
	if upperBoundMultiplier < 0 {
		upperBoundMultiplier = 0.0
	}
	lowerBoundFloat := float64(targetFileMeasureValue) * lowerBoundMultiplier
	lowerBound := strconv.FormatFloat(lowerBoundFloat, 'f', 0, 64)
	upperBoundFloat := float64(targetFileMeasureValue) * upperBoundMultiplier
	upperBound := strconv.FormatFloat(upperBoundFloat, 'f', 0, 64)
	errors.Debug(debug, "::quickBayesianProbabilityOfPrior, for measure ", measure, " lowerBound=", lowerBound, " upperBound=", upperBound)
	sqlQuery := "SELECT COUNT(" + measure + ") FROM filestore WHERE " + measure + " > " + lowerBound + " and " + measure + " < " + upperBound + " AND os_type = '" + osType + "' "
	errors.Debug(debug, sqlQuery)
	NumberRecordsWithinBounds := persistence.DoBuiltUpPreparedQuery(sqlQuery)
	return lowerBound, upperBound, NumberRecordsWithinBounds
}

func retrieveMeasureValueForTargetFile(targetFileHash string, measure string, osType string) float64 {
	sqlQuery := "SELECT " + measure + " FROM filestore WHERE md5_hash = '" + targetFileHash + "' AND os_type = '" + osType + "' "
	errors.Debug(debug, sqlQuery)

	rawTargetFileMeasureValue := persistence.DoBuiltUpPreparedQuery(sqlQuery)

	floatTargetFileMeasureValue, err1 := strconv.ParseFloat(rawTargetFileMeasureValue, 64)
	if err1 != nil {
		log.Fatal(err1)
	}
	return floatTargetFileMeasureValue
}

func getFieldsToCreatePeersBy() []string {
	quickBayesianPeerMeasures := make([]string, 0)
	quickBayesianPeerMeasures = append(quickBayesianPeerMeasures, "code_size", "binsz",
		"symbols", "sections", "library_count", "imports", "num_data_strings", "num_wholefile_strings", "system_calls", "networking_calls", "media_calls", "UI_calls",
		"registry_calls", "security_calls", "crypto_calls", "database_calls", "unknown_calls")
	return quickBayesianPeerMeasures
}

// Theorem is the key invocation of Bayes' theorem
func Theorem(probabilityOfPriorGivenPosterior float64, probabilityOfPosterior float64, probabilityOfPrior float64) float64 {
	if debug {
		fmt.Println("::Theorem args:")
		fmt.Printf("probabilityOfPriorGivenPosterior is %f, probabilityOfPosterior is %f, probabilityOfPrior is %f \n ", probabilityOfPriorGivenPosterior, probabilityOfPosterior, probabilityOfPrior)
	}
	probabilityOfPosteriorGivenPrior := (probabilityOfPriorGivenPosterior * probabilityOfPosterior) / probabilityOfPrior

	// if probabilityOfPrior is zero, that's a divide by zero error, resulting in "+Inf", so we hack return value to zero to compensate
	if probabilityOfPosteriorGivenPrior == math.Inf(+1) {
		probabilityOfPosteriorGivenPrior = 0.0
	}
	return probabilityOfPosteriorGivenPrior
}

// BayesianAnalysis is experimental, with fragile parsing right now
// below: have to use quotes, otherwise > or < breaks the args
// format: bayesian="probability_of:networking_calls>0,given_that:binsz>55000"
func BayesianAnalysis(meh string, osType string) {
	args := strings.Split(meh, ",")

	posteriorString := strings.Split(args[0], ":") // probability_of:networking_calls>0
	priorString := strings.Split(args[1], ":")

	postString := posteriorString[1] // "networking_calls>0"
	priString := priorString[1]

	postOperator := determineMathematicalOperator(postString) // ">" etc.
	postFieldName := determineFieldName(postString, postOperator)
	//fmt.Println("postFieldName is: ", postFieldName)

	priOperator := determineMathematicalOperator(priString)
	priorFieldName := determineFieldName(priString, priOperator)
	//fmt.Println("priorFieldName is: ", priorFieldName)

	postNumericValue := determineNumericTestValue(postString, postOperator)
	//fmt.Println("postNumericValue is ", postNumericValue, )

	priorNumericValue := determineNumericTestValue(priString, priOperator)
	//fmt.Println("priorNumericValue is ", priorNumericValue, )

	// next: derive stuff from DB, a la: "SELECT COUNT(binsz) FROM filestore WHERE binsz > 55000"
	probabilityOfPrior := persistence.GetProbabilityOfSomething(priorFieldName, priOperator, priorNumericValue, osType)
	//fmt.Println("BayesianAnalysis, GetProbabilityOfSomething for Prior =>", probabilityOfPrior, "<=")

	probabilityOfPosterior := persistence.GetProbabilityOfSomething(postFieldName, postOperator, postNumericValue, osType)
	//fmt.Println("BayesianAnalysis, GetProbabilityOfSomething for POSTERIOR =>", probabilityOfPosterior, "<=")

	/// implementing this:  select count(md5_hash) from filestore where binsz > 55000 AND  networking_calls > 2
	probabilityOfPriorGivenPosterior := persistence.GetProbabilityOfPriorGivenPosterior(priorFieldName, priOperator, priorNumericValue, postFieldName, postOperator, postNumericValue, osType)
	//fmt.Println("::probabilityOfPriorGivenPosterior is ", probabilityOfPriorGivenPosterior)

	floatProb := Theorem(probabilityOfPriorGivenPosterior, probabilityOfPosterior, probabilityOfPrior)
	floatProb = floatProb * 100
	printMe := strconv.FormatFloat(floatProb, 'f', 1, 64)

	fmt.Println(":: BayesianAnalysis,  probabilityOfPosteriorGivenPrior = ", printMe, "%")

}

func determineFieldName(postString string, operator string) string {
	//var fieldName string
	chunks := strings.Split(postString, operator)
	fieldName := chunks[0]
	//fmt.Println("fieldName is ", fieldName)
	return fieldName
}

//FIXME change from string to int or float64, for strictness...not urgent for now

func determineNumericTestValue(postString string, operator string) string {
	chunks := strings.Split(postString, operator)
	numericValue := chunks[1]
	//fmt.Println("numericValue is ", numericValue)
	return numericValue
}

func determineMathematicalOperator(postString string) string {
	// now parse posteriors, priors...for >, <, or =
	var operator string
	if strings.Contains(postString, ">") {
		//fmt.Println("operator is for GREATER THAN, >")
		operator = ">"
	} else if strings.Contains(postString, "<") {
		//fmt.Println("operator is for LESS than, <")
		operator = "<"
	} else if strings.Contains(postString, "=") {
		//fmt.Println("operator is for EQUAL, =")
		operator = "="
	} else {
		fmt.Println("Fragile Bayes module arg parsing couldn't handle this: ", postString)
	}
	return operator
}
