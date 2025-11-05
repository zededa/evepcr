package main

import (
	"bytes"
	"encoding/hex"
	epcr "eve_pcr_prediction"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-attestation/attest"
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

	// get the old pcrs too, we expect some of them to match
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
	} else {
		for index, _ := range expectedPCRs {
			switch index {
			case 0, 1, 2, 3, 4, 6, 7, 8, 9, 13:
				if contains(expectedPCRs, index, reportedPCRs[index]) {
					fmt.Printf("[PASS] PCR %d value %s matches expected", index, hex.EncodeToString(reportedPCRs[index]))
				} else {
					fmt.Printf("[ERROR!!!] PCR %d value %s does not match expected", index, hex.EncodeToString(reportedPCRs[index]))
				}
			case 5:
				// we have a special case for PCR 5, just print it for now
				fmt.Printf("[UNIMPLEMENTED] PCR 5 value: %s", hex.EncodeToString(reportedPCRs[index]))
			case 14:
				// PCR 14 must match the exact value of the previously reported known good value,
				// just print it for now
				if bytes.Equal(oldPCRs[14], reportedPCRs[14]) {
					fmt.Printf("[PASS] PCR 14 value %s matches old known good value", hex.EncodeToString(reportedPCRs[index]))
				} else {
					fmt.Printf("[ERROR!!!] PCR 14 value %s does not match old known good value", hex.EncodeToString(reportedPCRs[index]))
				}
			default:
				// every other PCR must match the old value
				if bytes.Equal(oldPCRs[index], reportedPCRs[index]) {
					fmt.Printf("[PASS] PCR %d value %s matches old known good value", index, hex.EncodeToString(reportedPCRs[index]))
				} else {
					fmt.Printf("[ERROR!!!] PCR %d value %s does not match old known good value", index, hex.EncodeToString(reportedPCRs[index]))
				}
				continue
			}
		}
	}

	return nil
}

func ValidatePcrFive(oldEventLog, currEventLog string) error {
	// PCR 5 can vary based on the hard disk configuration, but it also shouldn't change
	// much except attribues of IMAGA/IMGB partition.
	oldTable, err := epcr.GetGptPartitionTable(oldEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetGptPartitionTable failed: %v", err)
	}

	currTable, err := epcr.GetGptPartitionTable(currEventLog, nil, nil, nil, false)
	if err != nil {
		return fmt.Errorf("GetGptPartitionTable failed: %v", err)
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
		// We skip the Attribute check for IMAG/IMGB, as it can vary based on partiton state
		// being unused, updating, active, etc.
		if oldName != "IMAGA" && oldName != "IMGB" {
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

	// Parse flags
	flag.Parse()

	if *oldEventLog == "" || *currEventLog == "" || *pcrPredictions == "" || *oldPcrValues == "" || *currPcrValues == "" {
		fmt.Println("All flags -old, -old-pcr-values, -current, -curr-pcr-values and -prediction are required.")
		flag.Usage()
		os.Exit(1)
	}

	// First make sure we can trust the event logs
	if err := validatePcrs(*oldEventLog, *oldPcrValues); err != nil {
		fmt.Printf("Old event log validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := validatePcrs(*currEventLog, *currPcrValues); err != nil {
		fmt.Printf("Current event log validation failed: %v\n", err)
		os.Exit(1)
	}

	if PcrsMatchExpectedValues(*pcrPredictions, *oldPcrValues, *currPcrValues) != nil {
		fmt.Printf("PCR values do not match expected values\n")
		os.Exit(1)
	}

	fmt.Printf("PCR values match expected values\n")
}

func validatePcrs(eventLogFile, PcrsFile string) error {
	attestPCRs, err := epcr.GetAttestedPCRs(PcrsFile)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %v", err)
	}

	content, err := os.ReadFile(eventLogFile)
	if err != nil {
		return fmt.Errorf("ReadFile failed: %v", err)
	}
	eventLog, err := attest.ParseEventLog(content)
	if err != nil {
		return fmt.Errorf("ParseEventLog failed: %v", err)
	}

	// Reply the eventlog and check if end up with expected PCR values
	events, err := eventLog.Verify(attestPCRs)
	if err != nil {
		return fmt.Errorf("verify failed: %v", err)
	}

	// If we can trust the eventlog integrity, now we can validate the system
	// state using custom rules.
	if err := epcr.ValidateEventLog(events, false); err != nil {
		return fmt.Errorf("ValidateEventLog failed: %v", err)
	}

	return nil
}
