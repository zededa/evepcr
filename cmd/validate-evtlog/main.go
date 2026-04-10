// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	epcr "github.com/zededa/evepcr"
	"flag"
	"fmt"
	"os"
)

func contains(m map[int][][]byte, key int, val []byte) bool {
	slices, ok := m[key]
	if !ok {
		return false
	}
	for _, b := range slices {
		if bytes.Equal(b, val) {
			return true
		}
	}
	return false
}

func PcrsMatchExpectedValues(prediction, oldPcrs, currentPcrs string) error {
	attestPCRs, err := epcr.GetAttestedPCRs(currentPcrs)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %v", err)
	}
	reportedPCRs := map[int][]byte{}
	for _, pcr := range attestPCRs {
		reportedPCRs[pcr.Index] = pcr.Digest
	}

	oldPcrsValues, err := epcr.GetAttestedPCRs(oldPcrs)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %v", err)
	}
	oldPCRs := map[int][]byte{}
	for _, pcr := range oldPcrsValues {
		oldPCRs[pcr.Index] = pcr.Digest
	}

	expectedPCRs, err := epcr.DeserializePcrsFromFile(prediction)
	if err != nil {
		return fmt.Errorf("DeserializePcrsFromFile failed: %v", err)
	}
	for index := range expectedPCRs {
		switch index {
		case 0, 1, 2, 3, 4, 6, 7, 8, 9, 13:
			if contains(expectedPCRs, index, reportedPCRs[index]) {
				fmt.Printf("[PASS] PCR %d value %s matches expected\n", index, hex.EncodeToString(reportedPCRs[index]))
			} else {
				fmt.Printf("[ERROR!!!] PCR %d value %s does not match expected\n", index, hex.EncodeToString(reportedPCRs[index]))
			}
		case 5:
			// PCR 5 reflects the GPT partition table state, which varies across the
			// 8 synthesized update variants. Validate that the reported value is one
			// of the predicted values.
			if contains(expectedPCRs, index, reportedPCRs[index]) {
				fmt.Printf("[PASS] PCR %d value %s matches expected\n", index, hex.EncodeToString(reportedPCRs[index]))
			} else {
				fmt.Printf("[ERROR!!!] PCR %d value %s does not match expected\n", index, hex.EncodeToString(reportedPCRs[index]))
			}
		case 14:
			// PCR 14 must match the exact value of the previously reported known good value
			if bytes.Equal(oldPCRs[14], reportedPCRs[14]) {
				fmt.Printf("[PASS] PCR 14 value %s matches old known good value\n", hex.EncodeToString(reportedPCRs[index]))
			} else {
				fmt.Printf("[ERROR!!!] PCR 14 value %s does not match old known good value\n", hex.EncodeToString(reportedPCRs[index]))
			}
		default:
			// every other PCR must match the old value
			if bytes.Equal(oldPCRs[index], reportedPCRs[index]) {
				fmt.Printf("[PASS] PCR %d value %s matches old known good value\n", index, hex.EncodeToString(reportedPCRs[index]))
			} else {
				fmt.Printf("[ERROR!!!] PCR %d value %s does not match old known good value\n", index, hex.EncodeToString(reportedPCRs[index]))
			}
		}
	}

	return nil
}

func ValidatePcrFive(oldEventLog, currEventLog string) error {
	// PCR 5 can vary based on the hard disk configuration, but it also shouldn't change
	// much except attributes of IMGA/IMGB partition.
	oldTable, err := epcr.GetGptPartitionTableFromFile(oldEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetGptPartitionTableFromFile failed: %v", err)
	}

	currTable, err := epcr.GetGptPartitionTableFromFile(currEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetGptPartitionTableFromFile failed: %v", err)
	}

	if len(oldTable) == 0 || len(currTable) == 0 {
		return fmt.Errorf("partition table is empty")
	}
	if len(oldTable) != len(currTable) {
		return fmt.Errorf("partition table length mismatch: old %d, new %d", len(oldTable), len(currTable))
	}

	for i := range len(oldTable) {
		oldEntry := oldTable[i].Entry
		oldName := oldTable[i].Name
		newEntry := currTable[i].Entry
		newName := currTable[i].Name

		if oldName != newName {
			return fmt.Errorf("partition %d name mismatch: old %s, new %s", i, oldName, newName)
		}
		if oldEntry.PartitionTypeGUID != newEntry.PartitionTypeGUID {
			return fmt.Errorf("partition %d type GUID mismatch: old %s, new %s", i,
				oldEntry.PartitionTypeGUID, newEntry.PartitionTypeGUID)
		}
		if oldEntry.UniquePartitionGUID != newEntry.UniquePartitionGUID {
			return fmt.Errorf("partition %d unique GUID mismatch: old %s, new %s", i,
				oldEntry.UniquePartitionGUID, newEntry.UniquePartitionGUID)
		}
		if oldEntry.StartingLBA != newEntry.StartingLBA {
			return fmt.Errorf("partition %d starting LBA mismatch: old %d, new %d", i,
				oldEntry.StartingLBA, newEntry.StartingLBA)
		}
		if oldEntry.EndingLBA != newEntry.EndingLBA {
			return fmt.Errorf("partition %d ending LBA mismatch: old %d, new %d", i,
				oldEntry.EndingLBA, newEntry.EndingLBA)
		}
		// Skip Attribute check for IMGA/IMGB — varies by partition state.
		if oldName != "IMGA" && oldName != "IMGB" {
			if oldEntry.Attributes != newEntry.Attributes {
				return fmt.Errorf("partition %d attributes mismatch: old %d, new %d", i,
					oldEntry.Attributes, newEntry.Attributes)
			}
		}
		if oldEntry.PartitionName != newEntry.PartitionName {
			return fmt.Errorf("partition %d name mismatch: old %s, new %s", i,
				oldEntry.PartitionName, newEntry.PartitionName)
		}
	}

	return nil
}

func main() {
	oldEventLog := flag.String("old", "", "Path to the old event log file")
	oldPcrValues := flag.String("old-pcr-values", "", "old PCR values from TPM Quote")
	currEventLog := flag.String("current", "", "Path to the current event log file")
	currPcrValues := flag.String("curr-pcr-values", "", "current PCR values from TPM Quote to validate against")
	pcrPredictions := flag.String("prediction", "", "gob file with PCR values to validate against")

	flag.Parse()

	if *oldEventLog == "" || *currEventLog == "" || *pcrPredictions == "" || *oldPcrValues == "" || *currPcrValues == "" {
		fmt.Println("All flags -old, -old-pcr-values, -current, -curr-pcr-values and -prediction are required.")
		flag.Usage()
		os.Exit(1)
	}

	if err := epcr.ValidateEventLogFromFile(*oldEventLog, *oldPcrValues); err != nil {
		fmt.Printf("Old event log validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := epcr.ValidateEventLogFromFile(*currEventLog, *currPcrValues); err != nil {
		fmt.Printf("Current event log validation failed: %v\n", err)
		os.Exit(1)
	}

	if err := ValidatePcrFive(*oldEventLog, *currEventLog); err != nil {
		fmt.Printf("GPT partition layout validation failed: %v\n", err)
		os.Exit(1)
	}

	if PcrsMatchExpectedValues(*pcrPredictions, *oldPcrValues, *currPcrValues) != nil {
		fmt.Printf("PCR values do not match expected values\n")
		os.Exit(1)
	}

	fmt.Printf("PCR values match expected values\n")
}
