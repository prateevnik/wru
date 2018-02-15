package errors

import (
	"fmt"
	"testing"
)

var HorizontalLine = "___________________________________________________________________________________"

// Check is just here for the sake of DRY (Dont' Repeat Yourself)
func Check(e error) {
	if e != nil {
		fmt.Printf("\n errors.Check, WRU blew up with %s \n\n", e.Error())
		panic(e)
	}
}

// Debug is trying to use the DRY principle. Goal is to reduce lines of code
// in the main packages for better readability.
func Debug(debug bool, messages ...string) {
	var printMeString string

	if debug {
		for _, msg := range messages {
			printMeString = printMeString + msg
		}
		fmt.Println(printMeString)
	}
}

// plagiarized assertEqual from https://gist.github.com/samalba/6059502
func AssertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}
