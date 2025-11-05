package eve_pcr_prediction

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-attestation/attest"
)

func findEveGrubStageOne(eventlog *attest.EventLog) (int, error) {
	for i, event := range eventlog.Events(attest.HashSHA256) {
		if event.Type.String() == "EV_EFI_BOOT_SERVICES_APPLICATION" {
			if i+1 < len(eventlog.Events(DefaultAlgo)) {
				nextEvent := eventlog.Events(attest.HashSHA256)[i+1]
				if nextEvent.Type.String() == "EV_IPL" && bytes.Contains(nextEvent.Data, []byte("gptprio.next")) {
					return i, nil
				}
			}
		}
	}
	return -1, fmt.Errorf("EVE GRUB Stage 1 event not found")
}

// we need to fix grub stage one to find EV_EFI_BOOT_SERVICES_APPLICATION event
// if event after it is a EV_IPL with "gptprio.next" in its data, we need
// to replace the EV_EFI_BOOT_SERVICES_APPLICATION event in the new event log
// with the one from old event log.
func fixEveGrubStageOne(originalOld *attest.EventLog, old *attest.EventLog, new *attest.EventLog) error {
	// get the stage one data from original event log
	oldStageOneIndex, err := findEveGrubStageOne(originalOld)
	if err != nil {
		return fmt.Errorf("error finding EVE GRUB Stage 1 event: %v", err)
	}
	oldData, oldDigest, err := originalOld.GetEventData(oldStageOneIndex)
	if err != nil {
		return fmt.Errorf("error getting old EVE GRUB Stage 1 event data: %v", err)
	}
	// replace the data so the prediction will match the what is expected
	err = old.SetEventData(oldStageOneIndex, oldData, oldDigest)
	if err != nil {
		return fmt.Errorf("error setting old EVE GRUB Stage 1 event data: %v", err)
	}

	return nil
}

func TestPcrFive(t *testing.T) {
	// PCR 5 can vary based on the hard disk configuration, but it also shouldn't change
	// much except attribues of IMAGA/IMGB partition.
	oldTable, err := GetGptPartitionTable("testdata/src_version/14.5.1bcbf.bin", nil, nil, nil, false)
	if err != nil {
		t.Errorf("GetPartitionTable failed: %v", err)
	}

	newTable, err := GetGptPartitionTable("testdata/dst_version/14.5_stable.bin", nil, nil, nil, false)
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
		// We skip the Attribute check for IMAG/IMGB, as it can vary based on partiton state
		// unused, updating, active, etc.
		if oldName != "IMAGA" && oldName != "IMGB" {
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
	allPCrs, err := PredictAllPCRs("testdata/src_version/14.5.1bcbf.bin",
		"testdata/dst_version/binary_bios_measurements_IMGA_active",
		"testdata/dst_version/binary_bios_measurements_IMGA_updating",
		"testdata/dst_version/binary_bios_measurements_IMGB_active",
		"testdata/dst_version/binary_bios_measurements_IMGB_updating",
		fixEveGrubStageOne, nil, nil, nil)
	if err != nil {
		t.Errorf("PredictAllPCRs failed: %v", err)
	}

	if err := SerializePcrsToFile("all_pcrs.gob", allPCrs); err != nil {
		t.Errorf("serializePcrsToFile failed: %v", err)
	}
}

func TestPcrPrediction(t *testing.T) {
	pcrs, err := PredictPCRs("testdata/src_version/14.5.1bcbf.bin",
		"testdata/dst_version/14.5_stable.bin",
		fixEveGrubStageOne, nil, nil, nil)
	if err != nil {
		t.Errorf("PredictPCR failed: %v", err)
	}

	// Convert predicted PCR values to YAML format
	predictedPcrs := &PcrYml{
		HashAlgo: map[string]map[int]string{
			"sha256": make(map[int]string, len(pcrs)),
		},
	}
	for i, pcr := range pcrs {
		predictedPcrs.HashAlgo["sha256"][i] = "0x" + fmt.Sprintf("%X", pcr)
	}

	// Read the expected PCR values from the YAML file
	expectedPcrs, err := ReadPCRs("testdata/dst_version/14.5_stable.pcr.yml", false)
	if err != nil {
		t.Errorf("ReadPCRs failed: %v", err)
	}

	unsetFF := "0x" + strings.Repeat("F", 64)
	unsetZero := "0x" + strings.Repeat("0", 64)
	for i := range expectedPcrs.HashAlgo["sha256"] {
		// Skip the PCR if it is unset (either 0 or FF)
		if expectedPcrs.HashAlgo["sha256"][i] == unsetFF || expectedPcrs.HashAlgo["sha256"][i] == unsetZero {
			continue
		}
		// PCR 14 is set in user-mode and is not part of TPM eventlog, so skip it for now
		if i == 14 {
			continue
		}
		if predictedPcrs.HashAlgo["sha256"][i] != expectedPcrs.HashAlgo["sha256"][i] {
			t.Errorf("PCR %d mismatch: expected %s, got %s", i,
				expectedPcrs.HashAlgo["sha256"][i],
				predictedPcrs.HashAlgo["sha256"][i])
		}
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
