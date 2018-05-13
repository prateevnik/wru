package euclid

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"wru/persistence"
)

var debug = false

// keyVal struct is used by a couple methods in this package, so declaring at package level
type keyVal struct {
	Key   string
	Value float64
}

func getTargetFileNumbers(targetFileHash string) map[string]float64 {

	targetRows := persistence.RetrieveTargetFileRows(targetFileHash)
	referenceMap := make(map[string]float64)

	var targetmd5Hash, targetfileName string
	var targetcodeSize, targetbinsz, targetsymbols,
		targetsections, targetlibraryCount, targetimports, targetnum_data_strings, targetsystem_calls, targetnetworking_calls, targetmedia_calls,
		targetui_calls, targetregistry_calls, targetsecurity_calls, targetcrypto_calls, targetdatabase_calls, targetunknown_calls float64

	//fmt.Println("PRUEFPUNKT A")
	for targetRows.Next() {
		err := targetRows.Scan(&targetmd5Hash, &targetfileName,
			&targetcodeSize, &targetbinsz, &targetsymbols, &targetsections, &targetlibraryCount, &targetimports, &targetnum_data_strings,
			&targetsystem_calls, &targetnetworking_calls, &targetmedia_calls, &targetui_calls, &targetregistry_calls, &targetsecurity_calls,
			&targetcrypto_calls, &targetdatabase_calls, &targetunknown_calls)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println("PRUEFPUNKT B")

		referenceMap["targetcodeSize"] = targetcodeSize
		referenceMap["targetbinsz"] = targetbinsz
		referenceMap["targetsymbols"] = targetsymbols
		referenceMap["targetsections"] = targetsections
		referenceMap["targetlibraryCount"] = targetlibraryCount
		referenceMap["targetimports"] = targetimports
		referenceMap["targetnum_data_strings"] = targetnum_data_strings
		referenceMap["targetsystem_calls"] = targetsystem_calls
		referenceMap["targetnetworking_calls"] = targetnetworking_calls
		referenceMap["targetmedia_calls"] = targetmedia_calls
		referenceMap["targetui_calls"] = targetui_calls
		referenceMap["targetregistry_calls"] = targetregistry_calls
		referenceMap["targetsecurity_calls"] = targetsecurity_calls
		referenceMap["targetcrypto_calls"] = targetcrypto_calls
		referenceMap["targetdatabase_calls"] = targetdatabase_calls
		referenceMap["targetunknown_calls"] = targetunknown_calls

	}
	return referenceMap
}

//  GetEuclideanPeers sorts stuff, should return a string for display
func GetEuclideanPeers(targetFile string, targetFileHash string, osType string, numberPeersPtr *int, fileInfoPtr *bool,
	userSpecifiedMetadata *string, userSpecifiedExcludeMetadata *string) []string {

	euclidianPeersMap := GetEuclidianPeerBinaries(targetFileHash, osType, fileInfoPtr, userSpecifiedMetadata, userSpecifiedExcludeMetadata)

	if debug {
		fmt.Println("::GetEuclideanPeers, euclidianPeersMap is: ", euclidianPeersMap)
	}

	// begin sorting stuff, to show peers in order of closest first..
	var ss []keyVal
	for k, v := range euclidianPeersMap {
		ss = append(ss, keyVal{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value < ss[j].Value
	})
	// ... end sorting stuff.

	euclidianPeersArray := buildUpStringArrayOfPeers(ss, numberPeersPtr)
	return euclidianPeersArray
}

func buildUpStringArrayOfPeers(ss []keyVal, numberPeersPtr *int) []string {
	var euclidianPeersArray []string
	//---- experiment --
	for _, keyVal := range ss {
		if *numberPeersPtr > 0 {
			if debug {
				fmt.Printf("%s, %f\n", keyVal.Key, keyVal.Value)
			}

			onePeer := keyVal.Key + ": " + strconv.FormatFloat(keyVal.Value, 'f', 4, 64)
			euclidianPeersArray = append(euclidianPeersArray, onePeer)
		}
		*numberPeersPtr = *numberPeersPtr - 1
	}
	//---- experiment --
	return euclidianPeersArray
}

//GetEuclidianPeerBinaries returns a map for sorting, to find closest peers for target file
// will want to sort returned map[string]float64 as per: https://stackoverflow.com/questions/18695346/how-to-sort-a-mapstringint-by-its-values
// #################################################################
func GetEuclidianPeerBinaries(targetFileHash string, osType string, fileInfoPtr *bool,
	userSpecifiedMetadata *string, userSpecifiedExcludeMetadata *string) map[string]float64 {

	mapOfTargetFileValues := getTargetFileNumbers(targetFileHash)
	peerBinaryRows := persistence.RetrievePeerBinaryRows(osType) // HIER

	var md5Hash, fileName, description string
	var codeSize, binsz, symbols, sections, libraryCount, imports, num_data_strings, system_calls, networking_calls,
		media_calls, ui_calls, registry_calls, security_calls, crypto_calls, database_calls, unknown_calls, known_vulnerable float64

	mapOfKnownFilesWithEuclideanDistances := make(map[string]float64)

	for peerBinaryRows.Next() {
		// HIER: should spin off a Go routine to compute Euclidean

		err := peerBinaryRows.Scan(&md5Hash, &fileName, &description, &codeSize, &binsz, &symbols, &sections, &libraryCount, &imports, &num_data_strings,
			&system_calls, &networking_calls, &media_calls, &ui_calls, &registry_calls, &security_calls, &crypto_calls, &database_calls, &unknown_calls, &known_vulnerable)
		if err != nil {
			log.Fatal(err)
		}

		if *fileInfoPtr {
			if len(description) > 0 {
				fileName = fileName + " [" + description + "]"
			} else {
				fileName = fileName + " [na]"
			}
		}

		if debug {
			if targetFileHash == md5Hash {
				fmt.Printf("this is our TARGETFILE! target file hash is %s and current db hash is %s \n", targetFileHash, md5Hash)
			}
		}

		euclidcodeSize2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetcodeSize"]) - LogOrZero(codeSize)), 2)
		euclidbinsz2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetbinsz"]) - LogOrZero(binsz)), 2)
		euclidsymbols2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetsymbols"]) - LogOrZero(symbols)), 2)
		euclidsections2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetsections"]) - LogOrZero(sections)), 2)
		euclidlibraryCount2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetlibraryCount"]) - LogOrZero(libraryCount)), 2)
		euclidimports2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetimports"]) - LogOrZero(imports)), 2)
		euclidnum_data_strings2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetnum_data_strings"]) - LogOrZero(num_data_strings)), 2)
		euclidsystem_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetsystem_calls"]) - LogOrZero(system_calls)), 2)
		euclidnetworking_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetnetworking_calls"]) - LogOrZero(networking_calls)), 2)
		euclidmedia_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetmedia_calls"]) - LogOrZero(media_calls)), 2)
		euclidui_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetui_calls"]) - LogOrZero(ui_calls)), 2)
		euclidregistry_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetregistry_calls"]) - LogOrZero(registry_calls)), 2)
		euclidsecurity_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetsecurity_calls"]) - LogOrZero(security_calls)), 2)
		euclidcrypto_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetcrypto_calls"]) - LogOrZero(crypto_calls)), 2)
		eucliddatabase_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetdatabase_calls"]) - LogOrZero(database_calls)), 2)
		euclidunknown_calls2 := math.Pow((LogOrZero(mapOfTargetFileValues["targetunknown_calls"]) - LogOrZero(unknown_calls)), 2)

		// take Log10, as with other measures:
		euclidPercentPeerMethodsFoundInTargetFile2 := math.Pow(LogOrZero(getPercentageFileAMethodsFoundInFileB(md5Hash, targetFileHash)), 2)
		euclidPercentTargetFileMethodsFoundInPeer2 := math.Pow(LogOrZero(getPercentageFileAMethodsFoundInFileB(targetFileHash, md5Hash)), 2) // math.Pow returns float64

		// ugly FIXME... if userSpecifiedMetadata was passed in, limit the metadata fields to those specified via flag "-metadata="
		// for efficiency, don't bother figuring this out unless -filemetadata arg was used (non zero length)
		if len(*userSpecifiedMetadata) > 0 {
			// TODO parse *userSpecifiedMetadata now..
			if !(strings.Contains(*userSpecifiedMetadata, "codeSize")) { //fmt.Println("CHECK: looks like 'codeSize' NOT within ", *userSpecifiedMetadata)
				euclidcodeSize2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "binsz")) {
				euclidbinsz2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "symbols")) {
				euclidsymbols2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "sections")) {
				euclidsections2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "libraryCount")) {
				euclidlibraryCount2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "imports")) {
				euclidimports2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "num_data_strings")) {
				euclidnum_data_strings2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "system_calls")) {
				euclidsystem_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "networking_calls")) {
				euclidnetworking_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "media_calls")) {
				euclidmedia_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "ui_calls")) {
				euclidui_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "registry_calls")) {
				euclidregistry_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "security_calls")) {
				euclidsecurity_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "crypto_calls")) {
				euclidcrypto_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "database_calls")) {
				eucliddatabase_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "unknown_calls")) {
				euclidunknown_calls2 = 0
			}
			if !(strings.Contains(*userSpecifiedMetadata, "shared_lib_functions")) {
				euclidPercentPeerMethodsFoundInTargetFile2 = 0
				euclidPercentTargetFileMethodsFoundInPeer2 = 0
			}
		}

		// ugly, FIXME if userSpecifiedMetadata was passed in, limit the metadata fields to those specified via flag "-metadata="
		// for efficiency, don't bother figuring this out unless -filemetadata arg was used (non zero length)
		// This is inverse logic to the include block above.  If user DOES specify a metadata element, this time, it's to remove it
		// from scope, so if we find that an element has been specified, we zero out that element now.
		if len(*userSpecifiedExcludeMetadata) > 0 {
			if strings.Contains(*userSpecifiedExcludeMetadata, "codeSize") { //fmt.Println("CHECK: looks like 'codeSize' within ", *userSpecifiedExcludeMetadata) so zero it
				euclidcodeSize2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "binsz") {
				euclidbinsz2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "symbols") {
				euclidsymbols2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "sections") {
				euclidsections2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "libraryCount") {
				euclidlibraryCount2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "imports") {
				euclidimports2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "num_data_strings") {
				euclidnum_data_strings2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "system_calls") {
				euclidsystem_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "networking_calls") {
				euclidnetworking_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "media_calls") {
				euclidmedia_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "ui_calls") {
				euclidui_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "registry_calls") {
				euclidregistry_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "security_calls") {
				euclidsecurity_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "crypto_calls") {
				euclidcrypto_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "database_calls") {
				eucliddatabase_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "unknown_calls") {
				euclidunknown_calls2 = 0
			}
			if strings.Contains(*userSpecifiedExcludeMetadata, "shared_lib_functions") {
				euclidPercentPeerMethodsFoundInTargetFile2 = 0
				euclidPercentTargetFileMethodsFoundInPeer2 = 0
			}
		}

		euclidSumSQRT := math.Sqrt(euclidcodeSize2 + euclidbinsz2 + euclidsymbols2 + euclidsections2 + euclidlibraryCount2 + euclidimports2 + euclidnum_data_strings2 +
			euclidsystem_calls2 + euclidnetworking_calls2 + euclidmedia_calls2 + euclidui_calls2 + euclidregistry_calls2 + euclidsecurity_calls2 + euclidcrypto_calls2 +
			eucliddatabase_calls2 +
			euclidunknown_calls2 +
			euclidPercentTargetFileMethodsFoundInPeer2 +
			euclidPercentPeerMethodsFoundInTargetFile2)

		if debug == true {
			fmt.Printf("for %s the value of C, euclidSumSQRT = %f \n", fileName, euclidSumSQRT)
		}

		if known_vulnerable > 0 {
			fileName = fileName + " *** FLAGGED *** "
		}

		mapOfKnownFilesWithEuclideanDistances[fileName] = euclidSumSQRT
	}

	return mapOfKnownFilesWithEuclideanDistances
}

/*
func zeroOutUnspecifiedMetadataColumns(userSpecifiedMetadata *string, float64, float64, float64, float64,
	float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64 )
 (float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64, float64)
 {

 }
*/

func getPercentageFileAMethodsFoundInFileB(targetFileHash string, md5Hash string) float64 {
	// get string like "msvcrt.dll__exit;msvcrt.dll__c_exit;msvcrt.dll_strncpy", then parse it into [] string
	targetFileMethodsString := persistence.RetrieveStoredMethodCallsForFile(targetFileHash)
	tgtFileMethodsArray := strings.Split(targetFileMethodsString, ";")
	//fmt.Println(tgtFileMethodsArray)

	peerBinaryMethodsString := persistence.RetrieveStoredMethodCallsForFile(md5Hash)
	peerMethodsArray := strings.Split(peerBinaryMethodsString, ";")
	//fmt.Println(peerMethodsArray)

	// now, do FOR loop on tgtFileMethodsArray, get percentage in peerMethodsArray
	var numTargetMethodsFoundInPeer float64 = 0
	totalNumMethodsInPeer := float64(len(peerMethodsArray))

	for _, targetMethod := range tgtFileMethodsArray {
		//fmt.Println("A targetMethod is: ", targetMethod)
		for _, peerMethod := range peerMethodsArray {
			//fmt.Printf("Within targetMethod %s, a peerMethod is: %s \n", targetMethod, peerMethod)
			if targetMethod == peerMethod {
				numTargetMethodsFoundInPeer = numTargetMethodsFoundInPeer + 1
			}
		}
	}

	if debug {
		fmt.Printf("numTargetMethodsFoundInPeer: %f \n", numTargetMethodsFoundInPeer)
		fmt.Printf("totalNumMethodsInPeer: %f \n", totalNumMethodsInPeer)
	}

	percentageNotFound := (1.0 - (numTargetMethodsFoundInPeer / totalNumMethodsInPeer)) * 100 // express as "79" not ".79" .. may really skew stuff...

	return percentageNotFound
}

func LogOrZero(some_number float64) float64 {
	if some_number > 0 {
		return math.Log10(some_number)
	} else {
		return 0
	}
}
