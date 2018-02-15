package bayes

import (
	"fmt"
	"testing"
	"wru/errors"
)

// the 'Output' comment at the end is key, it is parsed by the Go test harness to check if the code output is working

func TestExampleBayesFormula(t *testing.T) {
	meh := Theorem(0.25, 0.33, 0.44)

	fmt.Println(meh)
	// for some reson 0.1875 is getting 'fail'
	//// Output:  0.1875
	errors.AssertEqual(t, meh, 0.1875, "BRORKEN!!")
}
