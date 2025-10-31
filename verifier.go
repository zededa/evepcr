package eve_pcr_prediction

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"encoding/binary"
	"encoding/gob"
	"encoding/hex"

	"github.com/google/go-attestation/attest"
	"gopkg.in/yaml.v2"
)

// Refrences:
// TCG EFI Platform Specification For TPM Family 1.1 or 1.2 Specification Version 1.22 Revision 15
// TCG EFI Protocol Specification, Family “2.0” Level 00 Revision 00.13
// TCG Guidance on Integrity Measurements and Event Log Processing, Version 1.0 Revision 0.118
// UNDERSTANDING THE TRUSTED BOOT CHAIN IMPLEMENTATION, Revision 1.0, December 2020 :
//	https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/

// "EFI PART\0\0" for GPT Partition Table header signature
var defaultEvent = []byte{0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54, 0x00, 0x00}

// Event type string for EFI GPT event
const (
	defaultEventString    = "EV_EFI_GPT_EVENT"
	efiPartitionHeader    = "EFI PART"
	uefiDebugMode         = "UEFI Debug Mode"
	dmaProtectionDisabled = "DMA Protection Disabled"
	eventSeparator        = "EV_SEPARATOR"
	maxPartitionCount     = 128
	maxPcrIndex           = 24
)

// Default hash algorithm for PCRs
var DefaultAlgo = attest.HashSHA256

// EventTransformer is a function that transforms the event logs, this is called
// right before the PCR prediction, give a chance to change the event log if needed.
type EventTransformer func(originalOld *attest.EventLog, old *attest.EventLog, new *attest.EventLog) error

type PcrYml struct {
	HashAlgo map[string]map[int]string `yaml:"pcrs"`
}

type EfiPartitionTableHeader struct {
	Signature                [8]byte
	Revision                 uint32
	HeaderSize               uint32
	HeaderCRC32              uint32
	Reserved                 uint32
	MyLBA                    uint64
	AlternateLBA             uint64
	FirstUsableLBA           uint64
	LastUsableLBA            uint64
	DiskGUID                 [16]byte
	PartitionEntryLBA        uint64
	NumberOfPartitionEntries uint32
	SizeOfPartitionEntry     uint32
	PartitionEntryArrayCRC32 uint32
}

type EfiPartitionEntry struct {
	PartitionTypeGUID   [16]byte
	UniquePartitionGUID [16]byte
	StartingLBA         uint64
	EndingLBA           uint64
	Attributes          uint64
	PartitionName       [72]byte // UTF-16LE (36 chars)
}

type PartitionTableEntry struct {
	Name  string
	Entry EfiPartitionEntry
}

func unionByIndex(arrays ...[][]byte) map[int][][]byte {
	result := make(map[int][][]byte)
	seen := make(map[int]map[string]bool)

	if len(arrays) == 0 {
		return result
	}

	for i := 0; i < len(arrays[0]); i++ {
		seen[i] = make(map[string]bool)
	}

	for _, arr := range arrays {
		for i, val := range arr {
			key := string(val)
			if !seen[i][key] {
				seen[i][key] = true
				result[i] = append(result[i], val)
			}
		}
	}

	return result
}

func hexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]
		fmt.Printf("%08x  ", i)
		for j := 0; j < bytesPerLine; j++ {
			if j < len(line) {
				fmt.Printf("%02x ", line[j])
			} else {
				fmt.Printf("   ")
			}
		}
		fmt.Print(" |")
		for _, b := range line {
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
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

func getContentDigest(data []byte) [][]byte {
	digests := make([][]byte, 4)
	for _, hashAlgo := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest := crypto.Hash(hashAlgo).New()
		digest.Write(data)
		digests = append(digests, digest.Sum(nil))
	}

	return digests
}

func contentMatchesDigest(ev attest.Event) bool {
	// the algo information is lost here, so lets try all
	digests := getContentDigest(ev.Data)
	for _, d := range digests {
		if string(ev.Digest) == string(d) {
			return true
		}
	}
	return false
}

func utf16LEToString(buf []byte) (string, error) {
	if len(buf)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16LE buffer length: %d", len(buf))
	}

	// 1MB sanity check
	if len(buf) > 1<<20 {
		return "", fmt.Errorf("UTF-16 buffer too large: %d bytes", len(buf))
	}

	u16 := make([]uint16, len(buf)/2)
	binary.Read(bytes.NewReader(buf), binary.LittleEndian, &u16)
	runes := utf16.Decode(u16)
	// trim any trailing nulls
	s := string(runes)
	for len(s) > 0 && s[len(s)-1] == '\x00' {
		s = s[:len(s)-1]
	}
	return s, nil
}

// getPartitionsTableEntries parses the GPT partition table from the given data
func getPartitionsTableEntries(data []byte) ([]PartitionTableEntry, error) {
	r := bytes.NewReader(data)

	// Parse GPT header
	var hdr EfiPartitionTableHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("fail to read GPT header: %w", err)
	}
	if string(hdr.Signature[:]) != efiPartitionHeader {
		return nil, fmt.Errorf("bad GPT signature: %q", hdr.Signature)
	}

	// Parse NumberOfPartitions (UINTN)
	var numParts uint64
	if err := binary.Read(r, binary.LittleEndian, &numParts); err != nil {
		return nil, fmt.Errorf("reading NumberOfPartitions: %w", err)
	}

	if numParts == 0 || numParts > maxPartitionCount {
		return nil, fmt.Errorf("unreasonable number of partitions: %d", numParts)
	}

	entries := []PartitionTableEntry{}
	for i := 0; i < int(numParts); i++ {
		var entry EfiPartitionEntry
		if err := binary.Read(r, binary.LittleEndian, &entry); err != nil {
			return nil, fmt.Errorf("reading partition %d: %w", i, err)
		}

		name, err := utf16LEToString(entry.PartitionName[:])
		if err != nil {
			return nil, fmt.Errorf("reading partition %d name: %w", i, err)
		}
		// append to entries
		entries = append(entries, PartitionTableEntry{Name: name, Entry: entry})
	}

	return entries, nil
}

// preValidateEventLog validates the event log, makeing sure it meets the basic
// security requirements, this must be called after event log verification
// and before any other validators like grub validator.
func preValidateEventLog(events []attest.Event, verbose bool) error {
	Pcr7SeperatorSeen := false
	for _, event := range events {
		// Secure feature disabling, such as DMA protection disabling and Debug
		// mode goes into PCR[7].
		if event.Index != 7 {
			continue
		}

		// "event type" IS NOT TRUSTED! it is not part of the digest, see :
		// https://github.com/tianocore/edk2/blob/68d506e0d15c0c412142be68ed006c65b641560f/SecurityPkg/Tcg/Tcg2Pei/Tcg2Pei.c#L460
		// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
		//
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

		// double check, content must match the digest
		if !contentMatchesDigest(event) {
			return fmt.Errorf("error %s digest mismatch", et)
		}

		// If the DMA protection is disabled or configured to a lower security
		// state, then the platform shall measure the "DMA Protection Disabled"
		// string with EV_EFI_ACTION.
		if string(event.Data) == dmaProtectionDisabled {
			return fmt.Errorf("error DMA Protection Disabled")
		}

		// If a platform provides a firmware debugger mode, then the platform
		// shall measure "UEFI Debug Mode" string with EV_EFI_ACTION.
		if string(event.Data) == uefiDebugMode {
			return fmt.Errorf("error UEFI debugger present")
		}

		// This is a sanity check, EV_SEPARATOR is used to draw a line between
		// the pre-boot environment and entering a post-boot environment.
		// The data within the event field of the EV_SEPARATOR event MUST be a
		//32-bit (double-word) of 0’s. We can use this value as a refrence, so we
		// can actually validate the event data to trust the event type.
		if et == eventSeparator {
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

// ReadPCRs reads PCR values from a YAML file and returns a PcrYml struct
func ReadPCRs(file string, verbose bool) (PcrYml, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return PcrYml{}, fmt.Errorf("error while reading PCRs YAML file %s: %w", file, err)
	}

	var pcrs PcrYml
	err = yaml.Unmarshal(f, &pcrs)
	if err != nil {
		return PcrYml{}, fmt.Errorf("error while unmarshalling PCRs YAML file %s: %w", file, err)
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

// GetAttestedPCRs reads PCR values from a YAML file and converts them to attest.PCR format
func GetAttestedPCRs(file string) ([]attest.PCR, error) {
	ymlPcrs, err := ReadPCRs(file, false)
	if err != nil {
		return nil, fmt.Errorf("error while reading PCR file: %w", err)
	}

	var attestPCRs []attest.PCR
	for hashAlgo, indexes := range ymlPcrs.HashAlgo {
		for index, value := range indexes {
			// remove 0x prefix
			if strings.ToLower(value[:2]) == "0x" {
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

// ValidateEventLog validates the event log against set of rules
// to detect any security issues.
func ValidateEventLog(events []attest.Event, verbose bool) error {
	if err := preValidateEventLog(events, verbose); err != nil {
		return err
	}

	// We can add more rules here
	return nil
}

func ValidateEventLogFromFile(eventLogFile, pcrYaml string) error {
	attestPCRs, err := GetAttestedPCRs(pcrYaml)
	if err != nil {
		return fmt.Errorf("GetAttestedPCRs failed: %w", err)
	}

	eventLogContent, err := os.ReadFile(eventLogFile)
	if err != nil {
		return fmt.Errorf("ReadFile failed: %w", err)
	}

	eventLog, err := attest.ParseEventLog(eventLogContent)
	if err != nil {
		return fmt.Errorf("ParseEventLog failed: %w", err)
	}

	// Reply the eventlog and check if end up with expected PCR values
	events, err := eventLog.Verify(attestPCRs)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}

	// If we can trust the eventlog integrity, now we can validate the system
	// state using custom rules.
	if err := ValidateEventLog(events, false); err != nil {
		return fmt.Errorf("validateEventLog failed: %w", err)
	}

	return nil
}

// PredictAllPCRs predicts all PCR values for the four scenarios:
// A-active, A-updating, B-active, B-updating
// and returns the union of all PCR values for each PCR index.
func PredictAllPCRs(old, newA, newAUpdating, newB, newBUpdating string, eventTransform EventTransformer, hashAlgo *attest.HashAlg, startEvent *string, startEventContent []byte) (map[int][][]byte, error) {
	aActivePcrs, err := PredictPCRs(old, newA, eventTransform, hashAlgo, startEvent, startEventContent)
	if err != nil {
		return nil, fmt.Errorf("failed to predict aActivePcrs: %w", err)
	}

	aUpdatingPcrs, err := PredictPCRs(old, newAUpdating, eventTransform, hashAlgo, startEvent, startEventContent)
	if err != nil {
		return nil, fmt.Errorf("failed to predict aUpdatingPcrs: %w", err)
	}

	bActivePcrs, err := PredictPCRs(old, newB, eventTransform, hashAlgo, startEvent, startEventContent)
	if err != nil {
		return nil, fmt.Errorf("failed to predict bActivePcrs: %w", err)
	}

	bUpdatingPcrs, err := PredictPCRs(old, newBUpdating, eventTransform, hashAlgo, startEvent, startEventContent)
	if err != nil {
		return nil, fmt.Errorf("failed to predict bUpdatingPcrs: %w", err)
	}

	union := unionByIndex(aActivePcrs, aUpdatingPcrs, bActivePcrs, bUpdatingPcrs)
	return union, nil
}

// GetGptPartitionTable extracts the partition table from the event log file,
// if startEvent and startEventContent are nil, default values will be used.
func GetGptPartitionTable(eventLogFile string, hashAlgo *attest.HashAlg, startEvent *string, startEventContent []byte, verbose bool) ([]PartitionTableEntry, error) {
	eventLog, err := os.ReadFile(eventLogFile)
	if err != nil {
		return nil, err
	}

	events, err := attest.ParseEventLog(eventLog)
	if err != nil {
		return nil, err
	}

	if startEvent == nil {
		se := defaultEventString
		startEvent = &se
	}
	if startEventContent == nil {
		startEventContent = defaultEvent
	}
	if hashAlgo == nil {
		hl := DefaultAlgo
		hashAlgo = &hl
	}

	for _, event := range events.Events(*hashAlgo) {
		if event.Type.String() == *startEvent && bytes.Contains(event.Data, startEventContent) {
			entries, err := getPartitionsTableEntries(event.Data)
			if err != nil {
				return nil, err
			}

			if verbose {
				for i, pEntry := range entries {
					entry := pEntry.Entry
					name := pEntry.Name
					fmt.Printf("\nPartition %d:\n", i)
					fmt.Printf("  Type GUID:   %x\n", entry.PartitionTypeGUID)
					fmt.Printf("  Unique GUID: %x\n", entry.UniquePartitionGUID)
					fmt.Printf("  Start LBA:   %d\n", entry.StartingLBA)
					fmt.Printf("  End LBA:     %d\n", entry.EndingLBA)
					fmt.Printf("  Attributes:  %x\n", entry.Attributes)
					fmt.Printf("  Name:        %s\n", name)
				}
			}

			return entries, nil
		}
	}

	return nil, fmt.Errorf("error no event found with data containing %s", *startEvent)
}

// PredictPCRs predicts PCR values based on old and new event logs,
// if startEvent and startEventContent are nil, default values will be used.
func PredictPCRs(oldEventLogFile, newEventLogFile string, eventTransform EventTransformer, hashAlgo *attest.HashAlg, startEvent *string, startEventContent []byte) ([][]byte, error) {
	if startEvent == nil {
		se := defaultEventString
		startEvent = &se
	}
	if startEventContent == nil {
		startEventContent = defaultEvent
	}
	if hashAlgo == nil {
		hl := DefaultAlgo
		hashAlgo = &hl
	}

	oldEventLogContents, err := os.ReadFile(oldEventLogFile)
	if err != nil {
		return nil, err
	}
	newEventLogContents, err := os.ReadFile(newEventLogFile)
	if err != nil {
		return nil, err
	}
	oldEventLog, err := attest.ParseEventLog(oldEventLogContents)
	if err != nil {
		return nil, err
	}
	newEventLog, err := attest.ParseEventLog(newEventLogContents)
	if err != nil {
		return nil, err
	}

	// make a copy of the original old events, to pass to the transformer
	originalOldEvents := oldEventLog.Clone()

	index := -1
	for i, event := range oldEventLog.Events(*hashAlgo) {
		if event.Type.String() == *startEvent && bytes.Contains(event.Data, startEventContent) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("error no event found with data containing %s", *startEvent)
	}

	// Replace the events at index with events from newEventLog
	err = oldEventLog.OverrideEvents(index, newEventLog)
	if err != nil {
		return nil, err
	}

	// apply any transformation if provided
	if eventTransform != nil {
		err = eventTransform(originalOldEvents, oldEventLog, newEventLog)
		if err != nil {
			return nil, fmt.Errorf("error transforming events: %v", err)
		}
	}

	// Predict PCRs from 0 to 24
	pcrs := make([][]byte, maxPcrIndex)
	for i := range maxPcrIndex {
		pcr := attest.PCR{Index: i, DigestAlg: crypto.SHA256, Digest: make([]byte, 32)}
		p, err := oldEventLog.Predict(pcr)
		if err != nil {
			return nil, fmt.Errorf("error predicting PCR[%d]: %v", i, err)
		}

		pcrs[i] = p
	}

	return pcrs, nil
}

// DumpEvents dumps all events in the event log file
func DumpEvents(EventLogFile string, hashAlgo *attest.HashAlg) error {
	evntlogFile, err := os.ReadFile(EventLogFile)
	if err != nil {
		return err
	}
	eventLog, err := attest.ParseEventLog(evntlogFile)
	if err != nil {
		return err
	}
	if hashAlgo == nil {
		hl := DefaultAlgo
		hashAlgo = &hl
	}
	events := eventLog.Events(*hashAlgo)
	fmt.Printf("Total %d events found\n", len(events))

	// dump all the events
	for _, event := range events {
		fmt.Printf("Event: %v\n", event.Type.String())
		fmt.Printf("  PCR: %d\n", event.Index)
		fmt.Printf("  Digest: %x\n", event.Digest)
		fmt.Printf("  Data :\n")
		hexDump(event.Data)
	}

	return nil
}

// SerializePcrsToFile serializes the PCRs map to a file using gob encoding
func SerializePcrsToFile(filename string, data map[int][][]byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	return encoder.Encode(data)
}

// DeserializePcrsFromFile deserializes the PCRs map from a file using gob encoding
func DeserializePcrsFromFile(filename string) (map[int][][]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data map[int][][]byte
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
