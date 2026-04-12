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
	oldEventLog := flag.String("old", "", "baseline event log file")
	newEventLog := flag.String("new", "", "updated event log from the device; omit to predict from baseline only")
	rootfsImage := flag.String("rootfs", "", "squashfs rootfs image; when set PCR 13 is predicted from its content")
	eveVersion := flag.String("version", "", "target EVE version string (e.g. 16.11.0-kvm-amd64); improves PCR 8 accuracy in baseline-only mode")
	outFile := flag.String("out", "predicted_pcrs.gob", "output file for serialized PCR predictions")
	dumpEventLog := flag.String("dump-eventlog", "", "write the predicted event log to this file")
	compareFile := flag.String("compare", "", "PCR YAML file with actual values to compare against predictions; exits 1 on mismatch")
	algo := flag.String("algo", "sha256", "hash algorithm for comparisons (sha1, sha256, sha384, sha512)")
	verbose := flag.Bool("verbose", false, "print predicted PCR values")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -old <eventlog> [-new <eventlog>] [-rootfs <img>] [flags] [pcr-index:hexdigest ...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Positional args supply known PCR values.\n")
		fmt.Fprintf(os.Stderr, "  With -new: values are added to the predicted set (e.g. user-space PCR 14).\n")
		fmt.Fprintf(os.Stderr, "  Without -new: values replace the baseline prediction for that index.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *oldEventLog == "" {
		fmt.Println("error: -old is required")
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

	pcrArgs, err := parsePCRArgs(flag.Args())
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	var allPCRs map[int][][]byte
	var mergedLog []byte
	if *newEventLog != "" {
		allPCRs, mergedLog, err = epcr.PredictPCRsFromFiles(*oldEventLog, *newEventLog, rootfsHash)
		if err != nil {
			fmt.Printf("PredictPCRs failed: %v\n", err)
			os.Exit(1)
		}
		for idx, val := range pcrArgs {
			found := false
			for _, existing := range allPCRs[idx] {
				if bytes.Equal(existing, val) {
					found = true
					break
				}
			}
			if !found {
				allPCRs[idx] = append(allPCRs[idx], val)
			}
		}
	} else {
		allPCRs, mergedLog, err = epcr.PredictPCRsFromBaselineFile(*oldEventLog, rootfsHash, *eveVersion, pcrArgs)
		if err != nil {
			fmt.Printf("PredictPCRsFromBaseline failed: %v\n", err)
			os.Exit(1)
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

	if *dumpEventLog != "" {
		if len(mergedLog) == 0 {
			fmt.Fprintf(os.Stderr, "dump-eventlog: no merged event log available\n")
			os.Exit(1)
		}
		if err := os.WriteFile(*dumpEventLog, mergedLog, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "dump-eventlog: %v\n", err)
			os.Exit(1)
		}
		if *verbose {
			fmt.Printf("predicted event log written to %s\n", *dumpEventLog)
		}
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

func parsePCRArgs(args []string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(args))
	for _, arg := range args {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid PCR argument %q: expected <index>:<hexdigest>", arg)
		}
		idx, err := strconv.Atoi(parts[0])
		if err != nil || idx < 0 || idx >= 24 {
			return nil, fmt.Errorf("invalid PCR index in %q: must be 0-23", arg)
		}
		val, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid hex value in %q: %v", arg, err)
		}
		out[idx] = val
	}
	return out, nil
}
