package persistence

import (
	"bufio"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"wru/errors"
	// is this OK below?
	_ "github.com/mattn/go-sqlite3"
)

// need to work in best DB practices from http://go-database-sql.org
// .. they say sql.DB is meant to be long-lived, global is often OK..
// since README on github updated for copying data.db into place, will no
// longer have ugly code to try to create .wru/data.db on the fly.
var (
	debug             = false
	configurationFile = "wru.conf"
	db                *sql.DB
	err               error
)

func PrintStoredInfo(targetFile string) string {
	db = getDBconnection()
	defer db.Close()

	var firstSQLquery = "SELECT description FROM filestore WHERE filename = $1 COLLATE  NOCASE"
	infoStringTargetFile := doSimplePreparedQuery(db, firstSQLquery, targetFile)

	if len(infoStringTargetFile) == 0 {
		infoStringTargetFile = "no description or vulnerability data stored in our db for " + targetFile
	}
	return infoStringTargetFile
}

// RetrieveStoredMethodCallsForFile pulls a string like "msvcrt.dll__exit;msvcrt.dll__c_exit;msvcrt.dll_strncpy"
func RetrieveStoredMethodCallsForFile(md5_hash string) string {
	db = getDBconnection()
	defer db.Close()

	var methodsSQLquery = "SELECT method_calls FROM filestore WHERE md5_hash = $1"
	methodsStringTargetFile := doSimplePreparedQuery(db, methodsSQLquery, md5_hash)

	if len(methodsStringTargetFile) == 0 {
		methodsStringTargetFile = "no methods data stored in our db for file with hash: " + md5_hash
	}
	return methodsStringTargetFile
}

// RetrievePeerBinaryRows does just that..
func RetrievePeerBinaryRows(osType string) *sql.Rows {
	db = getDBconnection()
	defer db.Close()

	// now get the rest of the rows
	peerBinaryRows, queryError := db.Query("SELECT md5_hash, filename, description, static_score, code_size, binsz, "+
		" symbols, sections, library_count, imports, num_data_strings,"+
		"system_calls, networking_calls, media_calls, ui_calls, registry_calls, security_calls, crypto_calls, database_calls, unknown_calls, known_vulnerable  FROM filestore WHERE os_type = $1", osType)

	if queryError != nil {
		log.Fatal(queryError)
	}
	return peerBinaryRows
}

// RetrieveTargetFileRows does that
func RetrieveTargetFileRows(targetFileHash string) *sql.Rows {
	db = getDBconnection()
	defer db.Close()

	// end setup, on with the show:
	targetRows, targetErr := db.Query("SELECT md5_hash, filename, static_score, code_size, binsz, "+
		" symbols, sections, library_count, imports, num_data_strings, system_calls, networking_calls, media_calls, ui_calls, registry_calls, security_calls, crypto_calls, database_calls, unknown_calls  FROM filestore WHERE md5_hash = $1", targetFileHash)
	if targetErr != nil {
		log.Fatal(err)
	}
	return targetRows
}

// to convert a float number to a string
func floatToString(inputNum float64) string {
	return strconv.FormatFloat(inputNum, 'f', 6, 64)
}

func createDummyConfigFile(WRUdir string, configFile string) {
	if _, statError := os.Stat(WRUdir); os.IsNotExist(statError) {
		errors.Debug(debug, "The WRU directory does not exist, will try to create: ", WRUdir)
		os.MkdirAll(WRUdir, 0700)
	}

	dummyLine := []byte("# Uncomment line below to specify path to an alternate SQLite DB (maybe shared?) used by WRU \n# databasedir=/foo/bar/\n")
	writeError := ioutil.WriteFile(configFile, dummyLine, 0600)
	if writeError != nil {
		errors.Debug(debug, "::createDummyConfigFile, could not create placeholder config file at: ", configFile)
	}
}

// TODO have a default SQLite db directory for *nix, like /var/
func getDatabaseFileDirectory() string { // returns /Users/username/.wru/
	fallbackLocation := "/var/local/wru/"

	WRUdir := getWRUdir() // by default will be /Users/username/.wru/, unless changed below..
	var configFile = WRUdir + configurationFile
	file, openError := os.Open(configFile)

	// *NO* PERSONAL CONFIG FILE FOUND..
	if openError != nil {
		errors.Debug(debug, "::getDatabaseFileDirectory, looks like no config file in user's home dir, specifically: ", configFile)
		//createDummyConfigFile(WRUdir, configFile) // eh, get this working ... logic should check if there's an *uncommented* entry in personal config file
		// or just print usage message, put wru.conf in $HOME/.wru ? FIXME

		if _, statError := os.Stat(fallbackLocation); os.IsNotExist(statError) {
			errors.Debug(debug, "Fallback DB location at this location does not exist: ", fallbackLocation)
		} else {
			WRUdir = fallbackLocation
		}

		// A PERSONAL CONFIG FILE *WAS* FOUND, SO USE IT:
	} else {
		defer file.Close()
		scanner, customWRUdir := extractUserSpecifiedDBdirectory(file, WRUdir)
		if scanError := scanner.Err(); scanError != nil {
			log.Fatal(scanError)
		}
		WRUdir = customWRUdir
	}

	errors.Debug(debug, "::getDatabaseFileDirectory, about to return: ", WRUdir)
	return WRUdir
}

func extractUserSpecifiedDBdirectory(file *os.File, WRUdir string) (*bufio.Scanner, string) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var line = scanner.Text() // TODO make this work for more than one line in file, of course

		if line[:1] == "#" {
			errors.Debug(debug, "Config line began with #", "")
		} else {
			s := strings.Split(line, "=")
			userSpecifiedWRUdir := strings.TrimSpace(s[1])
			errors.Debug(debug, "Config file tells us : ", userSpecifiedWRUdir)

			if len(userSpecifiedWRUdir) > 1 {
				WRUdir = userSpecifiedWRUdir
			}
		}
	}
	return scanner, WRUdir
}

func getWRUdir() string {
	usr, err0 := user.Current()
	if err0 != nil {
		log.Fatal(err0)
	}
	var homeDir = usr.HomeDir
	var WRUdir = homeDir + "/.wru/"
	return WRUdir
}

func checkDBexists(pathToDataDB string, WRUdir string) {
	if _, statError := os.Stat(pathToDataDB); os.IsNotExist(statError) {
		errors.Debug(debug, "The database file does NOT exist, need to create it first:", pathToDataDB)
		os.MkdirAll(WRUdir, 0700)

		_, createError := os.Create(pathToDataDB)
		if createError != nil {
			fmt.Printf("Blew up trying to create DB at %s \n", pathToDataDB)
			fmt.Printf("\t Check filesystem permissions, and any config file settings at %s%s.\n", WRUdir, configurationFile)
		}
	}
}

func pullFromScores(label string, scores map[int]map[string]int) float64 {
	var testValue float64
	for i := 0; i < len(scores); i++ {
		var littleMap = scores[i]
		for key, value := range littleMap {
			//testValue = getLogOrZero(value)
			if key == label {
				testValue = float64(value)
				errors.Debug(debug, "persistence.pullFromScores, we get:", strconv.FormatFloat(testValue, 'f', 1, 64))
			}
		}
	}
	return testValue
}

func getPathToDataDB() string {
	var WRUdir = getWRUdir()
	var userPrefDir = getDatabaseFileDirectory()
	if len(userPrefDir) > 1 {
		WRUdir = userPrefDir
	}
	var pathToDataDB = WRUdir + "/" + "data.db"
	errors.Debug(debug, "::getPathToDataDB, about to return: ", pathToDataDB)
	return pathToDataDB
}

// StoreResult acts to store the metadata and so on for a file we analyzed
// when updating DB fields, don't forget to update package euclid methods (kludgy)
func StoreResult(MD5hash string, targetFile string, osType string, scores map[int]map[string]int, methodsUsed string, userSuppliedDescriptionPtr string, vulnerablePtr int) {

	var WRUdir = getWRUdir()
	var pathToDataDB = getPathToDataDB()

	checkDBexists(pathToDataDB, WRUdir)

	db = getDBconnection()
	defer db.Close()

	if err != nil {
		fmt.Printf("Blew up trying to access database file at %s \n", pathToDataDB)
		fmt.Println(err)
		os.Exit(1)
	}

	var codeSize = pullFromScores("codeSize", scores)
	var binsz = pullFromScores("binsz", scores)
	var symbols = pullFromScores("symbols", scores)
	var sections = pullFromScores("sections", scores)
	var libraryCount = pullFromScores("library_count", scores)
	var imports = pullFromScores("imports", scores)
	var numDataStrings = pullFromScores("numDataStrings", scores)
	var numWholeFileStrings = pullFromScores("numWholeFileStrings", scores)

	var registryCalls = int(pullFromScores("REGISTRY", scores))
	var securityCalls = int(pullFromScores("SECURITY", scores))
	var cryptoCalls = int(pullFromScores("CRYPTO", scores))
	var databaseCalls = int(pullFromScores("DATABASE", scores))
	var unknownCalls = int(pullFromScores("unknown", scores))
	var systemCalls = int(pullFromScores("system", scores))
	var networkingCalls = int(pullFromScores("NETWORKING", scores))
	var mediaCalls = int(pullFromScores("MEDIA", scores))
	var uiCalls = int(pullFromScores("UI", scores))

	// now put stuff in the table..
	if debug {
		fmt.Println("userSuppliedDescriptionPtr = ", userSuppliedDescriptionPtr)
		fmt.Println(" vulnerablePtr = ", vulnerablePtr)
	}

	_, execError2 := db.Exec("INSERT INTO `filestore` (md5_hash, filename, timestamp, os_type, " +
		"static_score, code_size, binsz, symbols, sections, library_count, imports," +
		"num_data_strings, num_wholefile_strings, description, known_vulnerable, " +
		"system_calls, networking_calls, media_calls, " +
		"UI_calls, registry_calls,security_calls,crypto_calls, database_calls, unknown_calls, method_calls" +
		") VALUES ('" +
		MD5hash +
		"', '" + targetFile +
		"', CURRENT_TIMESTAMP" +
		", '" + osType +
		"', '" + floatToString(0.0) + // static score is deprecated in favor of Euclidean distance 8-13-17
		"', '" + floatToString(codeSize) +
		"', '" + floatToString(binsz) +
		"', '" + floatToString(symbols) +
		"', '" + floatToString(sections) +
		"', '" + floatToString(libraryCount) +
		"', '" + floatToString(imports) +
		"', '" + floatToString(numDataStrings) +
		"', '" + floatToString(numWholeFileStrings) +
		"', '" + userSuppliedDescriptionPtr +
		"', '" + strconv.Itoa(vulnerablePtr) +
		"', '" + strconv.Itoa(systemCalls) +
		"', '" + strconv.Itoa(networkingCalls) +
		"', '" + strconv.Itoa(mediaCalls) +
		"', '" + strconv.Itoa(uiCalls) +
		"', '" + strconv.Itoa(registryCalls) +
		"', '" + strconv.Itoa(securityCalls) +
		"', '" + strconv.Itoa(cryptoCalls) +
		"', '" + strconv.Itoa(databaseCalls) +
		"', '" + strconv.Itoa(unknownCalls) +
		"', '" + methodsUsed +
		"' ) ")

	if execError2 != nil { // fugly code here, FIXME
		var theProblem = execError2.Error() // GoLang standard is error always is a string, so..
		if strings.Contains(theProblem, "UNIQUE constraint failed") {
			errors.Debug(debug, "### FWIW, looks like we already have this file in the database, with MD5hash %s . ###\n", MD5hash)

			vulnUpdate := "0"       // worried about SQLi ... seems crude
			if vulnerablePtr == 1 { // if vuln ptr is not set from command line, default value is -1.  So 1 means set to VULN, 0 means unset VULN bit.
				//fmt.Println("We have this file already but need to flag it as VULNERABLE")
				vulnUpdate = "1"
			} else if vulnerablePtr == 0 {
				//fmt.Println("We have this file already , vuln ptr is ", vulnerablePtr)
				vulnUpdate = "0"
			}
			if vulnerablePtr == 0 || vulnerablePtr == 1 {
				_, execError := db.Exec("UPDATE `filestore` SET " +
					vulnUpdate +

					" WHERE md5_hash = '" + MD5hash + "'")

				if execError != nil {
					fmt.Println(err)
				}
			} else { // not update Vuln flag, but file already in DB, so just update metadata for the file

				_, execError := db.Exec("UPDATE `filestore` SET " +

					"filename = '" + targetFile + "', " +
					"timestamp = CURRENT_TIMESTAMP, " +
					"os_type = '" + osType + "', " +
					"static_score = '" + floatToString(0.0) + "', " +
					"code_size = '" + floatToString(codeSize) + "', " +
					" binsz = '" + floatToString(binsz) + "', " +
					"symbols = '" + floatToString(symbols) + "', " +
					"sections = '" + floatToString(sections) + "', " +
					"library_count = '" + floatToString(libraryCount) + "', " +
					"imports = '" + floatToString(imports) + "', " +
					"num_data_strings = '" + floatToString(numDataStrings) + "', " +
					"num_wholefile_strings = '" + floatToString(numWholeFileStrings) + "', " +
					"description = '" + userSuppliedDescriptionPtr + "', " +
					"known_vulnerable = '" + strconv.Itoa(vulnerablePtr) + "', " +
					"system_calls = '" + strconv.Itoa(systemCalls) + "', " +
					"networking_calls = '" + strconv.Itoa(networkingCalls) + "', " +
					"media_calls = '" + strconv.Itoa(mediaCalls) + "', " +
					"UI_calls = '" + strconv.Itoa(uiCalls) + "', " +
					"registry_calls = '" + strconv.Itoa(registryCalls) + "', " +
					"security_calls = '" + strconv.Itoa(securityCalls) + "', " +
					"crypto_calls = '" + strconv.Itoa(cryptoCalls) + "', " +
					"database_calls = '" + strconv.Itoa(databaseCalls) + "', " +
					"unknown_calls = '" + strconv.Itoa(unknownCalls) + "', " +
					" method_calls = '" + methodsUsed + "' " +

					" WHERE md5_hash = '" + MD5hash + "'")

				if execError != nil {
					fmt.Println(execError)
				}
			}

		} else {
			fmt.Println(execError2)
			os.Exit(1)
		}
	}
}

// NEU as of 4-25-18, trying to get DRY in effect..
// note: don't do db.Close() within this shared helper function, since that will kill the *db
// instance before handing it to the calling functions.. defeating the purpose of it all :)
func getDBconnection() *sql.DB {
	var pathToDataDB = getPathToDataDB()
	var WRUdir = getWRUdir()
	checkDBexists(pathToDataDB, WRUdir)

	db, err = sql.Open("sqlite3", pathToDataDB)
	errors.Check(err)

	db.Ping() // if we're going to fail on DB access, fail now!
	if err != nil {
		fmt.Println("persistence.getDBconnection blew up trying to test connection to DB (ping) at ", pathToDataDB)
		os.Exit(1)
	}
	return db
}

// GetLibCategories just gets labels in small array, case insensitive
func GetLibCategories() []string {
	var categorySQLquery = "SELECT DISTINCT category FROM lib_categories WHERE LENGTH(category) > 1 COLLATE  NOCASE"
	var categories []string
	categories = doQueryNoParameters(categorySQLquery)
	return categories
}

func GetGuessingWords(category string) []string {
	var firstSQLquery = "SELECT word FROM guessing_words WHERE category = '" + category + "'"
	guessWordsArray := doQueryNoParameters(firstSQLquery)
	return guessWordsArray
}

func doQueryNoParameters(passedQuery string) []string {
	db = getDBconnection()
	defer db.Close() // SCHEISSE

	stmt, statementError := db.Prepare(passedQuery) // prepared statement, for safety :)
	errors.Check(statementError)
	defer stmt.Close()

	rows, queryError := stmt.Query()
	errors.Check(queryError)
	defer rows.Close()

	var queryResultArray []string
	var oneRowAnswer string

	for rows.Next() {
		scanError := rows.Scan(&oneRowAnswer)

		queryResultArray = append(queryResultArray, oneRowAnswer)

		if scanError != nil {
			log.Fatal(scanError)
		}
	}

	/*
		if err = rows.Err(); err != nil {
			errors.Debug(debug, "::doQueryNoParameters, must have not been any results at all?", "")
			log.Fatal(err)
		}
	*/
	//errors.Debug(debug, "::doQueryNoParameters, we return : ", queryResultArray)
	//fmt.Println(queryResultArray)
	return queryResultArray
}

// GetLibraryCategory just returns a category label for a passed library, e.g. "networking"
func GetLibraryCategory(library string) string {
	db = getDBconnection()
	defer db.Close()

	var firstSQLquery = "SELECT category FROM libraries WHERE library_name = $1 COLLATE  NOCASE"
	libraryCategory := doSimplePreparedQuery(db, firstSQLquery, library)
	if len(libraryCategory) == 0 {
		libraryCategory = "unknown"
	}

	return libraryCategory
}

func GetAverageBinarySize(osType string) string {
	db = getDBconnection()
	defer db.Close()

	var firstSQLquery = "SELECT ROUND(AVG(binsz)) FROM filestore WHERE os_type = $1" // select avg(binsz) from filestore where os_type = 'windows'

	avgSz := doSimplePreparedQuery(db, firstSQLquery, osType)
	return avgSz
}

func doSimplePreparedQuery(db *sql.DB, SQLquery string, libName string) string {

	stmt, err := db.Prepare(SQLquery) // prepared statement, for safety :)
	errors.Check(err)
	defer stmt.Close()

	rows, err := stmt.Query(libName)
	errors.Check(err)
	defer rows.Close()

	var oneRowAnswer string
	var oneQueryAnswer string
	var rowCounter = 0
	var separator = ""

	for rows.Next() {
		err1 := rows.Scan(&oneRowAnswer)

		if err1 != nil {
			log.Fatal(err1)
		}
		if rowCounter > 0 {
			separator = ", "
		}
		oneQueryAnswer = oneQueryAnswer + separator + oneRowAnswer
		rowCounter = rowCounter + 1
	}

	if err = rows.Err(); err != nil {
		errors.Debug(debug, "::doSimplePreparedQuery, must have not been any results at all?", "")
		log.Fatal(err)
	}
	return oneQueryAnswer
}

// TODO seems like queries could be refactored into fewer methods..maybe just this one?
func DoBuiltUpPreparedQuery(SQLquery string) string {
	db = getDBconnection()
	defer db.Close()

	stmt, err := db.Prepare(SQLquery) // prepared statement, for safety :)
	errors.Check(err)
	defer stmt.Close()

	rows, err := stmt.Query()
	errors.Check(err)
	defer rows.Close()

	var oneRowAnswer string
	var oneQueryAnswer string
	var rowCounter = 0
	var separator = ""

	for rows.Next() {
		err1 := rows.Scan(&oneRowAnswer)

		if err1 != nil {
			log.Fatal(err1)
		}
		if rowCounter > 0 {
			separator = ", "
		}
		oneQueryAnswer = oneQueryAnswer + separator + oneRowAnswer
		rowCounter = rowCounter + 1
	}

	if err = rows.Err(); err != nil {
		errors.Debug(debug, "::DoBuiltUpPreparedQuery, must have not been any results at all?", "")
		log.Fatal(err)
	}
	return oneQueryAnswer
}

func GetFloat64TotalRecords(osType string) float64 {
	db = getDBconnection()
	defer db.Close()

	var sqlQueryForTotal = "SELECT COUNT(md5_hash) FROM filestore WHERE os_type = $1"
	rawTotalRecords := doSimplePreparedQuery(db, sqlQueryForTotal, osType) // just contrived $1 arg, to fit need of 'doSimplePreparedQuery'
	float64TotalRecords, err := strconv.ParseFloat(rawTotalRecords, 64)
	errors.Check(err)

	return float64TotalRecords
}

//GetProbabilityOfSomething should return a value between 0.0 and 1.0
func GetProbabilityOfSomething(targetFieldName string, operator string, numericValue string, osType string) float64 { // e.g. priorFieldName =binsz
	db = getDBconnection()
	defer db.Close()

	var sqlQueryForTarget = "SELECT COUNT(" + targetFieldName + ") FROM filestore WHERE " + targetFieldName + " " + operator + " " + numericValue + " AND os_type = $1"

	errors.Debug(debug, "::GetProbabilityOfSomething, sqlQueryForTarget = ", sqlQueryForTarget)

	rawPriorNumber := doSimplePreparedQuery(db, sqlQueryForTarget, osType)
	float64PriorNumber, err := strconv.ParseFloat(rawPriorNumber, 64) // 604
	errors.Check(err)

	float64TotalRecords := GetFloat64TotalRecords(osType)
	probability := float64PriorNumber / float64TotalRecords

	return probability
}

// GetProbabilityOfPriorGivenPosterior (priorFieldName, priOperator, priorNumericValue, postFieldName, postOperator, postNumericValue)
/// implementing this:  select count(md5_hash) from filestore where binsz > 55000 AND  networking_calls > 2
func GetProbabilityOfPriorGivenPosterior(priorFieldName string, priOperator string, priorNumericValue string, postFieldName string, postOperator string, postNumericValue string, osType string) float64 {
	db = getDBconnection()
	defer db.Close()

	var sqlQuery = "SELECT COUNT(md5_hash) FROM filestore WHERE " + priorFieldName + " " + priOperator + " " + priorNumericValue + " AND " + postFieldName + " " + postOperator + " " + postNumericValue + " AND os_type = $1"
	rawProbOfPriorGivenPosterior := doSimplePreparedQuery(db, sqlQuery, osType)
	float64ProbabilityOfPriorGivenPosterior, parseError := strconv.ParseFloat(rawProbOfPriorGivenPosterior, 64)
	errors.Check(parseError)
	// fmt.Println("float64ProbabilityOfPriorGivenPosterior = ", float64ProbabilityOfPriorGivenPosterior)
	float64TotalRecords := GetFloat64TotalRecords(osType)
	float64ProbabilityOfPriorGivenPosterior = float64ProbabilityOfPriorGivenPosterior / float64TotalRecords
	// fmt.Println("float64ProbabilityOfPriorGivenPosterior is NOW = ", float64ProbabilityOfPriorGivenPosterior)

	return float64ProbabilityOfPriorGivenPosterior
}
