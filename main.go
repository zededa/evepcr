package main

import (
	"crypto"
	"fmt"
	"os"

	"encoding/hex"

	"github.com/google/go-attestation/attest"
	"gopkg.in/yaml.v2"
)

// Refrences consulted while writing this code:
// TCG EFI Platform Specification For TPM Family 1.1 or 1.2 Specification Version 1.22 Revision 15
// TCG EFI Protocol Specification, Family “2.0” Level 00 Revision 00.13
// UNDERSTANDING THE TRUSTED BOOT CHAIN IMPLEMENTATION, Revision 1.0, December 2020

type PcrYml struct {
	HashAlgo map[string]map[int]string `yaml:"pcrs"`
}

func readPCRs(file string, verbose bool) (PcrYml, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return PcrYml{}, fmt.Errorf("error while reading PCRs YAML file: %w", err)
	}

	var pcrs PcrYml
	err = yaml.Unmarshal(f, &pcrs)
	if err != nil {
		return PcrYml{}, fmt.Errorf("error while unmarshalling PCRs YAML: %w", err)
	}

	if verbose {
		for hashAlgo, indexes := range pcrs.HashAlgo {
			fmt.Printf("%s:\n", hashAlgo)
			for index, value := range indexes {
				fmt.Printf("  %d: %s\n", index, value)
			}
		}
	}

	return pcrs, nil
}

func getHashAlgo(algo string) crypto.Hash {
	switch algo {
	case "SHA1":
		return crypto.SHA1
	case "SHA256":
		return crypto.SHA256
	case "SHA384":
		return crypto.SHA384
	case "SHA512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func getAttestPCRs(ymlPcrs PcrYml) ([]attest.PCR, error) {
	var attestPCRs []attest.PCR
	for hashAlgo, indexes := range ymlPcrs.HashAlgo {
		for index, value := range indexes {
			// remove 0x prefix
			if value[:2] == "0x" {
				value = value[2:]
			}
			// convert hex string to byte array
			digest, err := hex.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("error while decoding digest: %w", err)
			}
			attestPCRs = append(attestPCRs, attest.PCR{
				Index:     index,
				Digest:    digest,
				DigestAlg: getHashAlgo(hashAlgo),
			})
		}
	}
	return attestPCRs, nil
}

func contentMatchesDigest(ev attest.Event) bool {
	// the algo information is lost here, so lets try all
	for _, hashAlgo := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest := crypto.Hash(hashAlgo).New()
		digest.Write(ev.Data)
		if string(ev.Digest) == string(digest.Sum(nil)) {
			return true
		}
	}
	return false
}

// preValidateEventLog validates the event log, makeing sure it meets the basic
// security requirements, this must be called before any other validators like
// grub validator.
func preValidateEventLog(events []attest.Event, verbose bool) error {
	Pcr7SeperatorSeen := false
	for _, event := range events {
		// Secure feature disabling, such as DMA protection disabling and Debug
		// mode goes into PCR[7].
		if event.Index != 7 {
			continue
		}

		// event type IS NOT TRUSTED! it is not part of the digest, see with
		// your own eyes :
		// https://github.com/tianocore/edk2/blob/68d506e0d15c0c412142be68ed006c65b641560f/SecurityPkg/Tcg/Tcg2Pei/Tcg2Pei.c#L460
		// if we base our check on the event type, it will be easy to bypass the
		// validation by changing the event type. For example if we check
		// debugger presence like this :
		// if et == "EV_EFI_ACTION" && string(event.Data) == "UEFI Debug Mode" {
		// 		return fmt.Errorf("error UEFI debugger present")
		// }
		// an attacker can change the event type to EV_WHATEVER and skip the
		// check. The only way to trust the event type is to obtain a Reference
		// Integrity Manifest (RIM) form manufacturer, and check the digest of
		// the event type against the RIM. so lets just check the data,
		// regardless of the event type.
		et := event.Type.String()

		// If the DMA protection is disabled or configured to a lower security
		// state, then the platform shall measure the "DMA Protection Disabled"
		// string with EV_EFI_ACTION.
		if string(event.Data) == "DMA Protection Disabled" {
			return fmt.Errorf("error DMA Protection Disabled")
		}

		// If a platform provides a firmware debugger mode, then the platform
		// shall measure "UEFI Debug Mode" string with EV_EFI_ACTION.
		if string(event.Data) == "UEFI Debug Mode" {
			return fmt.Errorf("error UEFI debugger present")
		}

		// This is a sanity check, EV_SEPARATOR is used to draw a line between
		// the pre-boot environment and entering a post-boot environment.
		// The data within the event field of the EV_SEPARATOR event MUST be a
		//32-bit (double-word) of 0’s. We can use this value as a RIM, so we
		// can actually validate the event data to trust the event type.
		if et == "EV_SEPARATOR" {
			// EV_SEPARATOR occurs only once in the flow.
			if Pcr7SeperatorSeen {
				return fmt.Errorf("error duplicate of EV_SEPARATOR for PCR[7]")
			}

			if len(event.Data) != 4 {
				return fmt.Errorf("error EV_SEPARATOR data length is not 4")
			}

			if string(event.Data) != "\x00\x00\x00\x00" {
				return fmt.Errorf("error EV_SEPARATOR data is not 0x00000000")
			}

			// content must match the digest
			if !contentMatchesDigest(event) {
				return fmt.Errorf("error EV_SEPARATOR digest mismatch")
			}

			Pcr7SeperatorSeen = true
		}

		if verbose {
			fmt.Printf("Event: %v\n", event.Type.String())
			fmt.Printf("  PCR: %d\n", event.Index)
			fmt.Printf("  Data: %s\n", string(event.Data))
		}
	}

	// we should definitly see one.
	if !Pcr7SeperatorSeen {
		return fmt.Errorf("error no EV_SEPARATOR seen for PCR[7]")
	}

	return nil
}

// Grub validator
func ValidateEventLog(events []attest.Event) error {

	if err := preValidateEventLog(events, true); err != nil {
		return err
	}

	// TODO :
	// no duplicate of events
	// has to be weethin the start and ExitBootServices

	return nil
}

func main() {
	ymlPcrs, err := readPCRs("testdata/pcrs.yml", false)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	evntlogFile, err := os.ReadFile("testdata/eventlog.bin")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	eventLog, err := attest.ParseEventLog(evntlogFile)
	if err != nil {
		fmt.Println("Error: ", err)
	}

	attestPCRs, err := getAttestPCRs(ymlPcrs)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	events, err := eventLog.Verify(attestPCRs)
	if err != nil {
		fmt.Printf("validating event log: %v", err)
		return
	}

	if err := ValidateEventLog(events); err != nil {
		fmt.Printf("validating event log: %v", err)
		return
	}
}
