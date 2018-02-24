package filechecks

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"wru/errors"
)

var debug = false

// ExternalTestResult invokes rabin2 from Radare2 project
// counts lines that matchString, returns an integer.  Radare version 2.4 no longer returns summary statistic for things like number of imports.
func ExternalTestResultCountOccurrences(targetFile string, command string, arg1 string) int {
	lineCount := ExternalTestResultLineCount(targetFile, command, arg1)
	// subtract 1, for the label "[Symbols]"
	lineCount = lineCount - 1
	if debug {
		fmt.Println("::ExternalTestResultCountOccurrences, for ", command, " ", arg1, " will return: ", lineCount)
	}
	return lineCount
}

// ExternalTestResult invokes rabin2 from Radare2 project
// if zero-length regex string is supplied (""), it will skip trying to split again based on regex. Good for when the selected column is the number format we want already.
// TODO make better..for now key off of matchString as label for test in DB
func ExternalTestResult(targetFile string, command string, arg1 string, matchString string, excludeString string, sliceNum int, regex string) int {
	var Aus bytes.Buffer = GetAusPut(targetFile, command, arg1)
	bits := strings.Fields(scrapeResults(Aus, matchString, excludeString))
	if (len(bits) - 1) < sliceNum { // will get index out of range panic
		return 0
	}
	if debug {
		fmt.Printf("targetFile %s, command %s, arg1 %s, matchSTring %s, excludeString %s, sliceNum %d, regex %s", targetFile, command, arg1, matchString, excludeString, sliceNum, regex)
	}

	testAnswerBit := bits[sliceNum] // < PROBLEM IST HIER (setupx86.exe). It has no .text section!

	if len(regex) > 0 {
		errors.Debug(debug, "REGEX is \n", regex)
		ourRegex := regexp.MustCompile(regex)
		interimArray := ourRegex.Split(testAnswerBit, -1)
		//errors.Debug(debug, "using REGEX, interimArray is: ", string(interimArray))
		testAnswerBit = strings.Join(interimArray, "")
		testAnswerBit = strings.TrimSpace(testAnswerBit)

	}

	if debug {
		fmt.Printf("::getExternalTestResult, testAnswerBit for command arg %s is >>%s<< \n", arg1, testAnswerBit)
	}

	score, err := strconv.Atoi(testAnswerBit)
	errors.Check(err)
	return score
}

// ExternalTestResultAsString leverages rabin2 from Radare2 project
// NEU .. and not DRY , should refactor, TODO
func ExternalTestResultAsString(targetFile string, command string, arg1 string, matchString string, excludeString string, sliceNum int, regex string) string {
	var Aus bytes.Buffer = GetAusPut(targetFile, command, arg1)
	bits := strings.Fields(scrapeResults(Aus, matchString, excludeString))
	testAnswerBit := bits[sliceNum]
	if len(regex) > 0 {
		errors.Debug(debug, "::getExternalTestResultAsString REGEX is \n", regex)
		ourRegex := regexp.MustCompile(regex)
		interimArray := ourRegex.Split(testAnswerBit, -1)

		testAnswerBit = strings.Join(interimArray, "")
		testAnswerBit = strings.TrimSpace(testAnswerBit)
	}

	errors.Debug(debug, "::getExternalTestResultAsString, will return testAnswerBit for command arg ", arg1, " as follows >>", testAnswerBit, "<< \n")
	return testAnswerBit
}

/*  scrapeResults returns a single line that matches the passed include / exclude pattern
 */
func scrapeResults(Aus bytes.Buffer, expr string, excludeString string) string {

	errors.Debug(debug, "::scrapeResults, expr is %s \n", expr)
	errors.Debug(debug, "::scrapeResults, exclude is %s \n", excludeString)

	var matchingLine string
	for {
		line, err := Aus.ReadString(10) // newline is 0x0A, or 10
		if err != nil {
			if err == io.EOF {
				break // to break out of the otherwise infinite for loop
			} else {
				panic(err)
			}
		}
		matched, err := regexp.MatchString(expr, line)
		errors.Check(err)

		if matched == true {
			// do a check if this matches our excludeString, if so, don't break
			if len(excludeString) > 0 {
				// FIXME ugly here **** handle for excludeSTring is turned on, func..
				xMatched, err := regexp.MatchString(excludeString, line)
				errors.Check(err)

				if xMatched == true {
					//fmt.Printf("we matched exclude string, so will skip : %s \n", line)
				} else {
					//fmt.Printf("EVEN WITH exclude string, it's valid match, will return >>%s<< \n", line)
					matchingLine = line
					break
				}

			} else {
				matchingLine = line
				break
			}
		}
	}
	if !(len(matchingLine) > 0) {
		matchingLine = "0"
	}

	errors.Debug(debug, "DEBUG| ::scrapeResults returning >>", matchingLine)
	return matchingLine
}

// ExternalTestResultLineCount is another func that leverages Radare2
func ExternalTestResultLineCount(targetFile string, command string, arg1 string) int {
	var Aus bytes.Buffer = GetAusPut(targetFile, command, arg1)
	var lineCount = 0
	for {
		_, err := Aus.ReadString(10) // newline is 0x0A, or 10

		if err != nil {
			if err == io.EOF {
				break // to break out of the otherwise infinite for loop
			} else {
				panic(err)
			}
		}
		lineCount = lineCount + 1
	}
	if debug {
		fmt.Println("::ExternalTestResultLineCount will return: ", lineCount)
	}
	return lineCount
}

// GetAusPut just scrapes result of command..
func GetAusPut(targetFile string, command string, arg1 string) bytes.Buffer {
	unserKommando := exec.Command(command, arg1, targetFile)
	var Aus bytes.Buffer
	unserKommando.Stdout = &Aus
	err := unserKommando.Run()
	errors.Check(err)
	return Aus
}

// ScrapeAllOutPut converts all STDOUT of external command into a single string.
func ScrapeAllOutPut(targetFile string, command string, arg1 string) string {
	var Aus = GetAusPut(targetFile, command, arg1)
	var antwortString = ""

	for {
		line, err := Aus.ReadString(10) // newline is 0x0A, or 10
		if err != nil {
			if err == io.EOF {
				break // to break out of the otherwise infinite for loop
			} else {
				panic(err)
			}
		}
		antwortString = antwortString + line
	}
	return antwortString
}
