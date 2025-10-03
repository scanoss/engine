// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * go-wrapper/example/wfp_scanner.go
 *
 * Example Go application demonstrating SCANOSS snippet scanning
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

// #cgo CFLAGS: -I../
// #cgo LDFLAGS: ${SRCDIR}/../libsnippets_wrapper.a -lldb -lssl -lcrypto -lz -lm -lpthread
// #include "snippets_wrapper.h"
// #include <stdlib.h>
import "C"
import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type WFPData struct {
	MD5        [16]byte
	TotalLines int
	FilePath   string
	Hashes     []uint32
	Lines      []uint32
}

func parseWFPFile(filepath string) (*WFPData, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open WFP file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	wfpData := &WFPData{
		Hashes: make([]uint32, 0),
		Lines:  make([]uint32, 0),
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Parse file header line
		if strings.HasPrefix(line, "file=") {
			parts := strings.Split(strings.TrimPrefix(line, "file="), ",")
			if len(parts) < 3 {
				continue
			}

			// Parse MD5
			md5Bytes, err := hex.DecodeString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("failed to decode MD5: %v", err)
			}
			copy(wfpData.MD5[:], md5Bytes)

			// Parse total lines
			wfpData.TotalLines, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("failed to parse total lines: %v", err)
			}

			// Parse file path
			wfpData.FilePath = parts[2]

		} else if strings.Contains(line, "=") {
			// Parse hash lines (format: line_number=hash1,hash2,...)
			parts := strings.Split(line, "=")
			if len(parts) != 2 {
				continue
			}

			lineNum, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}

			// Parse hashes for this line
			hashStrings := strings.Split(parts[1], ",")
			for _, hashStr := range hashStrings {
				hashValue, err := strconv.ParseUint(hashStr, 16, 32)
				if err != nil {
					continue
				}
				wfpData.Hashes = append(wfpData.Hashes, uint32(hashValue))
				wfpData.Lines = append(wfpData.Lines, uint32(lineNum))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return wfpData, nil
}

func scanWFP(wfpData *WFPData) (*C.wrapper_scan_result_t, error) {
	if len(wfpData.Hashes) == 0 {
		return nil, fmt.Errorf("no hashes found in WFP data")
	}

	// Prepare C struct
	cInput := C.wrapper_scan_input_t{}

	// Copy MD5
	for i := 0; i < 16; i++ {
		cInput.md5[i] = C.uint8_t(wfpData.MD5[i])
	}

	// Set file path
	cFilePath := C.CString(wfpData.FilePath)
	defer C.free(unsafe.Pointer(cFilePath))
	cInput.file_path = cFilePath

	// Allocate C memory for hashes and lines
	hashCount := len(wfpData.Hashes)
	cHashes := (*C.uint32_t)(C.malloc(C.size_t(hashCount * 4)))
	cLines := (*C.uint32_t)(C.malloc(C.size_t(hashCount * 4)))
	defer C.free(unsafe.Pointer(cHashes))
	defer C.free(unsafe.Pointer(cLines))

	// Copy data to C memory
	hashesSlice := (*[1 << 30]C.uint32_t)(unsafe.Pointer(cHashes))[:hashCount:hashCount]
	linesSlice := (*[1 << 30]C.uint32_t)(unsafe.Pointer(cLines))[:hashCount:hashCount]

	for i := 0; i < hashCount; i++ {
		hashesSlice[i] = C.uint32_t(wfpData.Hashes[i])
		linesSlice[i] = C.uint32_t(wfpData.Lines[i])
	}

	// Set pointers and counts
	cInput.hashes = cHashes
	cInput.lines = cLines
	cInput.hash_count = C.uint32_t(hashCount)
	cInput.total_lines = C.int(wfpData.TotalLines)

	if debugMode {
		fmt.Fprintf(os.Stderr, "[GO DEBUG] About to call C.snippets_wrapper_scan\n")
		fmt.Fprintf(os.Stderr, "[GO DEBUG] hash_count=%d, total_lines=%d\n", hashCount, wfpData.TotalLines)
		fmt.Fprintf(os.Stderr, "[GO DEBUG] cInput.hash_count=%d, cInput.total_lines=%d\n", cInput.hash_count, cInput.total_lines)
		fmt.Fprintf(os.Stderr, "[GO DEBUG] cHashes=%p, cLines=%p\n", cHashes, cLines)
	}

	// Call the scan function
	if debugMode {
		fmt.Fprintf(os.Stderr, "[GO DEBUG] Calling C.snippets_wrapper_scan now...\n")
	}
	cResult := C.snippets_wrapper_scan(&cInput)
	if debugMode {
		fmt.Fprintf(os.Stderr, "[GO DEBUG] Returned from C.snippets_wrapper_scan\n")
	}
	if cResult == nil {
		return nil, fmt.Errorf("scan failed: result is nil")
	}

	return cResult, nil
}

var debugMode bool

func main() {
	// Parse command line flags
	ossDbName := flag.String("oss-db-name", "oss", "OSS database name")
	flag.BoolVar(&debugMode, "q", false, "Enable debug output")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: wfp_scanner [options] <wfp_file_path>")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExample WFP file format:")
		fmt.Println("file=e27b911d391391f94a862ebbe40ddcc0,1652,path/to/file.c")
		fmt.Println("1=63e9a57f")
		fmt.Println("3=e6f64278")
		fmt.Println("6=aa323afd,31466ee5,87dece99")
		os.Exit(0)
	}

	wfpFilePath := flag.Arg(0)

	// Initialize wrapper with database name and debug mode
	cDbName := C.CString(*ossDbName)
	defer C.free(unsafe.Pointer(cDbName))
	C.snippets_wrapper_init(cDbName, C.bool(debugMode))
	defer C.snippets_wrapper_cleanup()

	// Parse WFP file
	fmt.Printf("Parsing WFP file: %s\n", wfpFilePath)
	wfpData, err := parseWFPFile(wfpFilePath)
	if err != nil {
		log.Fatalf("Failed to parse WFP file: %v", err)
	}

	fmt.Printf("File: %s\n", wfpData.FilePath)
	fmt.Printf("MD5: %x\n", wfpData.MD5)
	fmt.Printf("Total lines: %d\n", wfpData.TotalLines)
	fmt.Printf("Number of hashes: %d\n", len(wfpData.Hashes))

	// Scan the WFP data
	fmt.Println("\nScanning snippets...")
	result, err := scanWFP(wfpData)
	if err != nil {
		log.Fatalf("Failed to scan: %v", err)
	}
	defer C.snippets_wrapper_free_result(result)

	// Print results
	fmt.Println("\n=== Scan Results ===")
	switch result.match_type {
	case C.WRAPPER_MATCH_FILE:
		fmt.Println("✓ Match Type: FILE")
		fmt.Println("  Complete file match found!")
	case C.WRAPPER_MATCH_SNIPPET:
		fmt.Println("✓ Match Type: SNIPPET")
		fmt.Println("  Code snippet match found!")
	case C.WRAPPER_MATCH_BINARY:
		fmt.Println("✓ Match Type: BINARY")
		fmt.Println("  Binary file match found!")
	case C.WRAPPER_MATCH_NONE:
		fmt.Println("✗ Match Type: NONE")
		fmt.Println("  No match found")
	default:
		fmt.Printf("? Match Type: UNKNOWN (%d)\n", result.match_type)
	}

	if result.error_msg != nil {
		errorMsg := C.GoString(result.error_msg)
		fmt.Printf("\nError: %s\n", errorMsg)
	}

	// Print matching MD5s
	if result.match_count > 0 {
		fmt.Printf("\n=== Matching Files (%d) ===\n", result.match_count)
		matchesSlice := (*[1 << 30]C.wrapper_match_info_t)(unsafe.Pointer(result.matches))[:result.match_count:result.match_count]
		for i := 0; i < int(result.match_count); i++ {
			md5Hex := C.GoString(&matchesSlice[i].file_md5_hex[0])
			hits := int(matchesSlice[i].hits)
			rangeCount := int(matchesSlice[i].range_count)

			fmt.Printf("  %s (hits: %d)", md5Hex, hits)

			// Print ranges if available
			if rangeCount > 0 && matchesSlice[i].range_from != nil {
				rangeFromSlice := (*[1 << 30]C.int)(unsafe.Pointer(matchesSlice[i].range_from))[:rangeCount:rangeCount]
				rangeToSlice := (*[1 << 30]C.int)(unsafe.Pointer(matchesSlice[i].range_to))[:rangeCount:rangeCount]
				rangeOSSSlice := (*[1 << 30]C.int)(unsafe.Pointer(matchesSlice[i].oss_line))[:rangeCount:rangeCount]

				fmt.Printf(" - ranges: ")
				for r := 0; r < rangeCount; r++ {
					if r > 0 {
						fmt.Printf(", ")
					}
					fmt.Printf("%d-%d-%d", rangeFromSlice[r], rangeToSlice[r], rangeOSSSlice[r])
				}
			}
			fmt.Println()
		}
	}
}
