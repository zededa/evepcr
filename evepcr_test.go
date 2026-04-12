// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evepcr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/zededa/evepcr/internal/attest"
)

func TestPcrFive(t *testing.T) {
	// PCR 5 can vary based on the hard disk configuration, but it also shouldn't change
	// much except attributes of IMAGA/IMGB partition.
	oldTable, err := GetGptPartitionTableFromFile("testdata/src_version/14.5.1bcbf.bin", nil, nil, nil, false)
	if err != nil {
		t.Errorf("GetPartitionTable failed: %v", err)
	}

	newTable, err := GetGptPartitionTableFromFile("testdata/dst_version/14.5_stable.bin", nil, nil, nil, false)
	if err != nil {
		t.Errorf("GetPartitionTable failed: %v", err)
	}

	if len(oldTable) == 0 || len(newTable) == 0 {
		t.Errorf("Partition table is empty")
	}

	if len(oldTable) != len(newTable) {
		t.Errorf("Partition table length mismatch: old %d, new %d", len(oldTable), len(newTable))
	}

	for i := range len(oldTable) {
		oldEntry := oldTable[i].Entry
		oldName := oldTable[i].Name
		newEntry := newTable[i].Entry
		newName := newTable[i].Name

		if oldName != newName {
			t.Errorf("Partition %d name mismatch: old %s, new %s", i, oldName, newName)
		}

		if oldEntry.PartitionTypeGUID != newEntry.PartitionTypeGUID {
			t.Errorf("Partition %d type GUID mismatch: old %s, new %s", i,
				oldEntry.PartitionTypeGUID, newEntry.PartitionTypeGUID)
		}
		if oldEntry.UniquePartitionGUID != newEntry.UniquePartitionGUID {
			t.Errorf("Partition %d unique GUID mismatch: old %s, new %s", i,
				oldEntry.UniquePartitionGUID, newEntry.UniquePartitionGUID)
		}
		if oldEntry.StartingLBA != newEntry.StartingLBA {
			t.Errorf("Partition %d starting LBA mismatch: old %d, new %d", i,
				oldEntry.StartingLBA, newEntry.StartingLBA)
		}
		if oldEntry.EndingLBA != newEntry.EndingLBA {
			t.Errorf("Partition %d ending LBA mismatch: old %d, new %d", i,
				oldEntry.EndingLBA, newEntry.EndingLBA)
		}
		// We skip the Attribute check for IMAG/IMGB, as it can vary based on partition state
		// unused, updating, active, etc.
		if oldName != "IMGA" && oldName != "IMGB" {
			if oldEntry.Attributes != newEntry.Attributes {
				t.Errorf("Partition %d attributes mismatch: old %d, new %d", i,
					oldEntry.Attributes, newEntry.Attributes)
			}
		}
		if oldEntry.PartitionName != newEntry.PartitionName {
			t.Errorf("Partition %d name mismatch: old %s, new %s", i,
				oldEntry.PartitionName, newEntry.PartitionName)
		}
	}
}

func TestPcrPredictionFull(t *testing.T) {
	// Use a dst log that has both IMGA and IMGB so all 8 partition state
	// variants are synthesized. binary_bios_measurements_IMGB_active fits
	// because it was captured from a fully updated device with both partitions.
	allPCRs, err := PredictPCRsFromFiles("testdata/src_version/14.5.1bcbf.bin",
		"testdata/dst_version/binary_bios_measurements_IMGB_active", nil)
	if err != nil {
		t.Fatalf("PredictPCRs failed: %v", err)
	}

	// With IMGB present, all 8 variants are synthesized (2 IMGB-absent + 6 IMGB-present).
	// PCR[5] (GPT table) is the only one that differs across states, so we expect
	// 8 distinct values.
	if len(allPCRs[5]) != 8 {
		var vals []string
		for _, v := range allPCRs[5] {
			vals = append(vals, "0x"+hex.EncodeToString(v))
		}
		t.Errorf("expected 8 distinct PCR[5] values, got %d: %v", len(allPCRs[5]), vals)
	}

	if err := SerializePcrsToFile("all_pcrs.gob", allPCRs); err != nil {
		t.Errorf("SerializePcrsToFile failed: %v", err)
	}
}

func TestPcrPrediction(t *testing.T) {
	// dst has only IMGA (no IMGB) → 2 variants: IMGA-active and IMGA-updating.
	allPCRs, err := PredictPCRsFromFiles("testdata/src_version/14.5.1bcbf.bin",
		"testdata/dst_version/14.5_stable.bin", nil)
	if err != nil {
		t.Fatalf("PredictPCRs failed: %v", err)
	}

	expectedPcrs, err := ReadPCRs("testdata/dst_version/14.5_stable.pcr.yml", false)
	if err != nil {
		t.Fatalf("ReadPCRs failed: %v", err)
	}

	unsetFF := "0x" + strings.Repeat("F", 64)
	unsetZero := "0x" + strings.Repeat("0", 64)

	for i, expectedHex := range expectedPcrs.HashAlgo["sha256"] {
		if expectedHex == unsetFF || expectedHex == unsetZero {
			continue
		}
		// PCR 14 is set in user-mode and is not part of the TPM event log.
		if i == 14 {
			continue
		}

		hexStr := strings.TrimPrefix(strings.ToLower(expectedHex), "0x")
		expectedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Errorf("PCR %d: decoding expected value %q: %v", i, expectedHex, err)
			continue
		}

		predictedSet := allPCRs[i]
		if len(predictedSet) == 0 {
			t.Errorf("PCR %d: no predictions produced", i)
			continue
		}

		found := false
		for _, predicted := range predictedSet {
			if bytes.Equal(predicted, expectedBytes) {
				found = true
				break
			}
		}
		if !found {
			var predicted []string
			for _, v := range predictedSet {
				predicted = append(predicted, "0x"+strings.ToUpper(hex.EncodeToString(v)))
			}
			t.Errorf("PCR %d: expected %s not in predicted set %v",
				i, expectedHex, predicted)
		}
	}
}

func TestHashRootfsImage(t *testing.T) {
	img, err := os.ReadFile("testdata/rootfs/rootfs.img")
	if err != nil {
		t.Fatalf("reading rootfs image: %v", err)
	}

	got, err := HashRootfsImage(img)
	if err != nil {
		t.Fatalf("HashRootfsImage: %v", err)
	}

	// Expected value verified against the EV_IPL event data in tpm-event-log.bin:
	// event data = "squash4 e19fd58e...\0"
	const wantHex = "e19fd58e55a3866595b4c3df72789f60225fbffd43605f8ae94acbb1f144713f"
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("HashRootfsImage = %x, want %s", got, wantHex)
	}
}

func TestPredictPCRsWithRootfsHash(t *testing.T) {
	const eventLog = "testdata/rootfs/tpm-event-log.bin"

	img, err := os.ReadFile("testdata/rootfs/rootfs.img")
	if err != nil {
		t.Fatalf("reading rootfs image: %v", err)
	}

	rootfsHash, err := HashRootfsImage(img)
	if err != nil {
		t.Fatalf("HashRootfsImage: %v", err)
	}

	allPCRs, err := PredictPCRsFromFiles(eventLog, eventLog, rootfsHash)
	if err != nil {
		t.Fatalf("PredictPCRs: %v", err)
	}

	// Expected PCR 13 verified by direct event log replay with attest.Predict.
	const wantPCR13 = "69f9bae5df0d0976d5ed4c3f15a61556dd74585c158751f9339b126e654f4431"
	wantBytes, _ := hex.DecodeString(wantPCR13)

	candidates := allPCRs[13]
	if len(candidates) == 0 {
		t.Fatal("PCR[13]: no predictions produced")
	}
	found := false
	for _, v := range candidates {
		if bytes.Equal(v, wantBytes) {
			found = true
			break
		}
	}
	if !found {
		var got []string
		for _, v := range candidates {
			got = append(got, hex.EncodeToString(v))
		}
		t.Errorf("PCR[13]: want %s, predicted set: %v", wantPCR13, got)
	}
}

func TestEventLogValidation(t *testing.T) {
	attestPCRs, err := GetAttestedPCRs("testdata/src_version/14.5.1bcbf.pcr.yml")
	if err != nil {
		t.Fatalf("GetAttestedPCRs failed: %v", err)
	}

	// Read the PCR values received from a device, it is assumed that this PCR values
	// were TPM quoted with a valid signature.
	evntlogFile, err := os.ReadFile("testdata/src_version/14.5.1bcbf.bin")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	eventLog, err := attest.ParseEventLog(evntlogFile)
	if err != nil {
		t.Fatalf("ParseEventLog failed: %v", err)
	}

	// Reply the eventlog and check if end up with expected PCR values
	events, err := eventLog.Verify(attestPCRs)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// If we can trust the eventlog integrity, now we can validate the system
	// state using custom rules.
	if err := ValidateEventLog(events, false); err != nil {
		t.Fatalf("ValidateEventLog failed: %v", err)
	}
}

// fmtPCRSet formats a [][]byte as hex strings for test output.
func fmtPCRSet(set [][]byte) []string {
	var out []string
	for _, v := range set {
		out = append(out, fmt.Sprintf("0x%X", v))
	}
	return out
}
