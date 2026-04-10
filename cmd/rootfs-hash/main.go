// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	epcr "github.com/zededa/evepcr"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: eve-rootfs-hash <squashfs-image>\n")
		os.Exit(1)
	}

	imgBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading image: %v\n", err)
		os.Exit(1)
	}

	hash, err := epcr.HashRootfsImage(imgBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error hashing image: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(hash))
}
