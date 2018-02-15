package crypto

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
)

var debug = false

// MD5hashAsPrimaryKey is for inserting unique records into SQLite, use MD5 hash as primary key
func MD5hashAsPrimaryKey(targetFile string) (string, error) {
	var result []byte

	file, err := os.Open(targetFile)
	if err != nil {
		brokenResult := fmt.Sprintf("%x", result)
		return brokenResult, err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		brokenResult := fmt.Sprintf("%x", result)
		return brokenResult, err
	}

	var ourHash = hash.Sum(result)
	MD5asString := fmt.Sprintf("%x", ourHash)
	if debug {
		fmt.Printf("MD5hashAsPrimaryKey, for %s hash is %x \n", targetFile, ourHash)
		fmt.Printf("MD5hashAsPrimaryKey, fmt.Sprintf conversion gets %s \n", MD5asString)
	}
	// encode the returned bytes as hex to get a familiar looking MD5 hash string:
	return MD5asString, nil
}
