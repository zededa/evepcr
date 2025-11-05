package main

import (
	"bytes"
	"encoding/hex"
	epcr "eve_pcr_prediction"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/google/go-attestation/attest"
)

func main() {
	oldEventLog := flag.String("old", "", "Path to the old event log file")
	newAActive := flag.String("new-a-active", "", "Path to the new IMGA active event log file")
	newAUpdating := flag.String("new-a-updating", "", "Path to the new IMGA updating event log file")
	newBActive := flag.String("new-b-active", "", "Path to the new IMGB active event log file")
	newBUpdating := flag.String("new-b-updating", "", "Path to the new IMGB updating event log file")
	outFile := flag.String("out", "predicted_pcrs.gob", "Output file to serialize PCR values")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()
	if *oldEventLog == "" || *newAActive == "" || *newAUpdating == "" || *newBActive == "" || *newBUpdating == "" {
		fmt.Println("All flags -old, -new-a-active, -new-a-updating, -new-b-active, -new-b-updating are required.")
		flag.Usage()
		os.Exit(1)
	}

	allPCrs, err := epcr.PredictAllPCRs(*oldEventLog,
		*newAActive,
		*newAUpdating,
		*newBActive,
		*newBUpdating,
		fixEveGrubStageOne, // fix EVE GRUB Stage 1 event, it can never change
		nil,                // default hash algorithm (SHA256)
		nil,                // default event type
		nil,                // default event data
	)
	if err != nil {
		fmt.Printf("PredictAllPCRs failed: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		// Dump the final PCR values
		indices := make([]int, 0, len(allPCrs))
		for i := range allPCrs {
			indices = append(indices, i)
		}
		sort.Ints(indices)
		for _, i := range indices {
			fmt.Printf("PCR[%2d]: ", i)
			for _, v := range allPCrs[i] {
				fmt.Printf("%s ", hex.EncodeToString(v))
			}
			fmt.Println()
		}

		fmt.Println()

		// dump the gpt partition tables
		_, _ = epcr.GetGptPartitionTable(*oldEventLog, nil, nil, nil, true)
	}

	if err := epcr.SerializePcrsToFile(*outFile, allPCrs); err != nil {
		fmt.Printf("serializePcrsToFile failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("PCR values serialized to %s\n", *outFile)
}

func findEveGrubStageOne(eventlog *attest.EventLog) (int, error) {
	for i, event := range eventlog.Events(attest.HashSHA256) {
		if event.Type.String() == "EV_EFI_BOOT_SERVICES_APPLICATION" {
			if i+1 < len(eventlog.Events(epcr.DefaultAlgo)) {
				nextEvent := eventlog.Events(attest.HashSHA256)[i+1]
				if nextEvent.Type.String() == "EV_IPL" && bytes.Contains(nextEvent.Data, []byte("gptprio.next")) {
					return i, nil
				}
			}
		}
	}
	return -1, fmt.Errorf("EVE GRUB Stage 1 event not found")
}

// we need to fix grub stage one so find EV_EFI_BOOT_SERVICES_APPLICATION event
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
