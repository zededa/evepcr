// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	epcr "eve_pcr_prediction"
	"flag"
	"fmt"
	"os"
	"sort"
)

func main() {
	oldEventLog := flag.String("old", "", "Path to the source (currently running) event log file")
	newEventLog := flag.String("new", "", "Path to the destination (new version) event log file (any partition state)")
	rootfsImage := flag.String("rootfs", "", "Path to the destination squashfs rootfs image; when set PCR 13 is predicted from its content")
	outFile := flag.String("out", "predicted_pcrs.gob", "Output file to serialize PCR values")
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

	fmt.Printf("PCR values serialized to %s\n", *outFile)
}
