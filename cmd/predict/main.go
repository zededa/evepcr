// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	epcr "github.com/zededa/evepcr"
)

func main() {
	oldEventLog := flag.String("old", "", "Path to the source (currently running) event log file")
	newEventLog := flag.String("new", "", "Path to the destination (new version) event log file (any partition state)")
	rootfsImage := flag.String("rootfs", "", "Path to the destination squashfs rootfs image; when set PCR 13 is predicted from its content")
	outFile := flag.String("out", "predicted_pcrs.gob", "Output file to serialize PCR values")
	compareFile := flag.String("compare", "", "PCR YAML file with actual values to compare against predictions; exits 1 on mismatch")
	algo := flag.String("algo", "sha256", "Hash algorithm to use when comparing PCR values (sha1, sha256, sha384, sha512)")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()
	if *oldEventLog == "" || *newEventLog == "" {
		fmt.Println("Flags -old and -new are required.")
		flag.Usage()
		os.Exit(1)
	}

	var rootfsHash []byte
	if *rootfsImage != "" {
		imgBytes, err := os.ReadFile(*rootfsImage)
		if err != nil {
			fmt.Printf("reading rootfs image: %v\n", err)
			os.Exit(1)
		}
		rootfsHash, err = epcr.HashRootfsImage(imgBytes)
		if err != nil {
			fmt.Printf("HashRootfsImage: %v\n", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Printf("rootfs hash: %s\n", hex.EncodeToString(rootfsHash))
		}
	}

	allPCRs, err := epcr.PredictPCRsFromFiles(*oldEventLog, *newEventLog, rootfsHash)
	if err != nil {
		fmt.Printf("PredictPCRs failed: %v\n", err)
		os.Exit(1)
	}

	// Merge any extra PCR values supplied as positional args (<index>:<hexstring>).
	for _, arg := range flag.Args() {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid PCR argument %q: expected <index>:<hexstring>\n", arg)
			os.Exit(1)
		}
		idx, err := strconv.Atoi(parts[0])
		if err != nil || idx < 0 || idx >= 24 {
			fmt.Fprintf(os.Stderr, "invalid PCR index in %q: must be 0-23\n", arg)
			os.Exit(1)
		}
		val, err := hex.DecodeString(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid hex value in %q: %v\n", arg, err)
			os.Exit(1)
		}

		found := false
		for _, existing := range allPCRs[idx] {
			if string(existing) == string(val) {
				found = true
				break
			}
		}
		if !found {
			allPCRs[idx] = append(allPCRs[idx], val)
		}
	}

	if *verbose {
		indices := make([]int, 0, len(allPCRs))
		for i := range allPCRs {
			indices = append(indices, i)
		}
		sort.Ints(indices)
		for _, i := range indices {
			fmt.Printf("PCR[%2d]: ", i)
			for _, v := range allPCRs[i] {
				fmt.Printf("%s ", hex.EncodeToString(v))
			}
			fmt.Println()
		}
		fmt.Println()
		_, _ = epcr.GetGptPartitionTableFromFile(*oldEventLog, nil, nil, nil, true)
	}

	if err := epcr.SerializePcrsToFile(*outFile, allPCRs); err != nil {
		fmt.Printf("SerializePcrsToFile failed: %v\n", err)
		os.Exit(1)
	}

	if *compareFile != "" {
		ymlPcrs, err := epcr.ReadPCRs(*compareFile, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading compare file: %v\n", err)
			os.Exit(1)
		}
		algoKey := strings.ToLower(*algo)
		indexes, ok := ymlPcrs[algoKey]
		if !ok {
			fmt.Fprintf(os.Stderr, "algorithm %q not found in %s\n", *algo, *compareFile)
			os.Exit(1)
		}
		actual := make(map[int][]byte, len(indexes))
		for index, value := range indexes {
			value = strings.TrimPrefix(strings.ToLower(value), "0x")
			digest, err := hex.DecodeString(value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "decoding PCR %d: %v\n", index, err)
				os.Exit(1)
			}
			actual[index] = digest
		}

		indices := make([]int, 0, len(allPCRs))
		for i := range allPCRs {
			indices = append(indices, i)
		}
		sort.Ints(indices)

		pass := true
		for _, idx := range indices {
			actualVal := actual[idx]
			found := false
			for _, predicted := range allPCRs[idx] {
				if bytes.Equal(predicted, actualVal) {
					found = true
					break
				}
			}
			if found {
				fmt.Printf("[PASS] PCR[%2d] %s\n", idx, hex.EncodeToString(actualVal))
			} else {
				fmt.Printf("[FAIL] PCR[%2d] actual=%s not in predicted set\n", idx, hex.EncodeToString(actualVal))
				pass = false
			}
		}
		if !pass {
			os.Exit(1)
		}
	}
}
