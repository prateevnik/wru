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
	var targetstaticScore, targetcodeSize, targetbinsz, targetsymbols,
		targetsections, targetlibraryCount, targetimports, targetnum_data_strings, targetsystem_calls, targetnetworking_calls, targetmedia_calls,
		targetui_calls, targetregistry_calls, targetsecurity_calls, targetcrypto_calls, targetdatabase_calls, targetunknown_calls float64

	//fmt.Println("PRUEFPUNKT A")
	for targetRows.Next() {
		err := targetRows.Scan(&targetmd5Hash, &targetfileName, &targetstaticScore,
			&targetcodeSize, &targetbinsz, &targetsymbols, &targetsections, &targetlibraryCount, &targetimports, &targetnum_data_strings,
			&targetsystem_calls, &targetnetworking_calls, &targetmedia_calls, &targetui_calls, &targetregistry_calls, &targetsecurity_calls,
			&targetcrypto_calls, &targetdatabase_calls, &targetunknown_calls)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println("PRUEFPUNKT B")

		referenceMap["targetstaticScore"] = targetstaticScore
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
// evolving as of 8-10-17
func GetEuclideanPeers(targetFile string, targetFileHash string, osType string, numberPeersPtr *int) []string {

	euclidianPeersMap := GetEuclidianPeerBinaries(targetFileHash, osType)
	if debug {
		fmt.Println("euclidianPeersMap is: ", euclidianPeersMap)
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
func GetEuclidianPeerBinaries(targetFileHash string, osType string) map[string]float64 {

	mapOfTargetFileValues := getTargetFileNumbers(targetFileHash)
	peerBinaryRows := persistence.RetrievePeerBinaryRows(osType) // HIER

	var md5Hash, fileName string
	var staticScore, codeSize, binsz, symbols, sections, libraryCount, imports, num_data_strings, system_calls, networking_calls,
		media_calls, ui_calls, registry_calls, security_calls, crypto_calls, database_calls, unknown_calls, known_vulnerable float64

	mapOfKnownFilesWithEuclideanDistances := make(map[string]float64)

	//fmt.Println("ZOWIE?")
	for peerBinaryRows.Next() {
		// HIER: call a Go routine to compute Euclidean

		err := peerBinaryRows.Scan(&md5Hash, &fileName, &staticScore, &codeSize, &binsz, &symbols, &sections, &libraryCount, &imports, &num_data_strings,
			&system_calls, &networking_calls, &media_calls, &ui_calls, &registry_calls, &security_calls, &crypto_calls, &database_calls, &unknown_calls, &known_vulnerable)
		if err != nil {
			log.Fatal(err)
		}

		//fmt.Println("ZING?")
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
			fileName = fileName + " *** VULNERABLE *** "
		}

		mapOfKnownFilesWithEuclideanDistances[fileName] = euclidSumSQRT
	}

	return mapOfKnownFilesWithEuclideanDistances
}

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
