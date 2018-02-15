package crypto

import "testing"

//func MD5hashAsPrimaryKey(targetFile string) (string, error) {
func TestMD5hashAsPrimaryKey(t *testing.T) {

	var meh, _ = MD5hashAsPrimaryKey("/bin/ls")

	if len(meh) == 0 {
		t.Error("MD5hashAsPrimaryKey is busted somehow")
		t.Error(".. you have to run this on Mac or *nix for now.")
	}
}
