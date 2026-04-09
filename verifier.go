// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evepcr

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/zededa/evepcr/internal/attest"

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

// Default hash algorithm for PCRs
var DefaultAlgo = attest.HashSHA256

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

// squashfs superblock constants, matching GRUB's grub_squash_digest.
const (
	squashfsMagic           = uint32(0x73717368) // little-endian "sqsh"
	squashfsTotalSizeOffset = 40                 // byte offset of total_size (uint64 LE) in superblock
	measurefsFSName         = "squash4"          // fs name emitted by GRUB measurefs for squashfs
	pcrMeasurefs            = 13                 // PCR index GRUB measures the rootfs into
)

// GPT partition entry layout constants (TCG EFI spec / UEFI spec).
const (
	gptHeaderSize    = 92  // sizeof(EfiPartitionTableHeader)
	gptNumPartsSize  = 8   // UINT64 NumberOfPartitions in UEFI_GPT_DATA
	gptEntrySize     = 128 // sizeof(EfiPartitionEntry)
	gptEntryAttrOff  = 48  // byte offset of Attributes within EfiPartitionEntry
	gptEntryNameOff  = 56  // byte offset of PartitionName within EfiPartitionEntry
	gptEntryNameSize = 72  // byte size of PartitionName (UTF-16LE, 36 chars)
)

// EVE gptprio partition attribute values for each boot state.
// Layout of the Attributes uint64 (TCG / UEFI spec bits 48-56):
//
//	bits 48-51: PRIORITY (4 bits)
//	bits 52-55: TRIES_LEFT (4 bits)
//	bit  56:    SUCCESSFUL (1 bit)
const (
	gptAttrActive   = uint64(0x0102000000000000) // priority=2, tries_left=0, successful=1
	gptAttrUpdating = uint64(0x0013000000000000) // priority=3, tries_left=1, successful=0
	gptAttrInactive = uint64(0x0003000000000000) // priority=3, tries_left=0, successful=0
	gptAttrZero     = uint64(0x0000000000000000) // not yet installed / no state
)

type gptVariant struct {
	imgaAttr    uint64
	imgbAttr    uint64
	requireIMGB bool
}

// gptVariants lists all EVE partition states that affect PCR[5].
//
// EVE update cycle state machine (IMGA=src, IMGB=dst as example):
//
//	Normal update path:
//	  IMGA active + IMGB unused  →  SetOtherPartitionStateUpdating  →  IMGA active   + IMGB updating  [state 3]
//	  IMGA active + IMGB updating →  reboot+GRUB boots IMGB          →  IMGA active   + IMGB inprogress (on disk)
//	  After EVE marks success     →  MarkCurrentPartitionStateActive  →  IMGA unused   + IMGB active    [state 4]
//	  IMGA unused + IMGB active   →  SetOtherPartitionStateUpdating  →  IMGA updating  + IMGB active    [state 7]
//	  ... GRUB boots IMGA, EVE marks success → IMGA active + IMGB unused [state 1]
//
//	Fallback path (update attempt fails, tries_left hits 0):
//	  IMGA active + IMGB inprogress →  reboot (IMGB not bootable)    →  IMGA active   + IMGB inprogress [state 8]
//	  IMGA inprogress + IMGB active →  (IMGA failed, fallback)        →  IMGA inprogress+ IMGB active    [state 5]
//	  IMGA inprogress + IMGB active →  SetOtherPartitionStateUpdating →  IMGA inprogress+ IMGB updating  [state 6]
//
//	Single-partition or IMGB-absent variants:
//	  IMGA active   + no IMGB  [state 1a]
//	  IMGA updating + no IMGB  [state 2]
var gptVariants = []gptVariant{
	// IMGB absent / unused
	{gptAttrActive, gptAttrZero, false},   // state 1a/1: IMGA active,   IMGB absent/unused
	{gptAttrUpdating, gptAttrZero, false}, // state 2:    IMGA updating, IMGB absent/unused
	// Normal update path
	{gptAttrActive, gptAttrUpdating, true}, // state 3: IMGA active,    IMGB first-boot update
	{gptAttrZero, gptAttrActive, true},     // state 4: IMGA unused,    IMGB active (post-success)
	{gptAttrUpdating, gptAttrActive, true}, // state 7: IMGA updating,  IMGB active (forcefallback/re-update)
	// Failure path
	{gptAttrActive, gptAttrInactive, true},   // state 8: IMGA active,    IMGB inprogress/failed
	{gptAttrInactive, gptAttrActive, true},   // state 5: IMGA inprogress,IMGB active
	{gptAttrInactive, gptAttrUpdating, true}, // state 6: IMGA inprogress,IMGB updating
}

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
	digests := make([][]byte, 0, 4)
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
	if len(buf) < 2 || len(buf)%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16LE buffer length: %d", len(buf))
	}

	u16 := make([]uint16, len(buf)/2)
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &u16); err != nil {
		return "", fmt.Errorf("reading UTF-16LE buffer: %w", err)
	}
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

// ValidateEventLogFromBytes verifies that the event log replays correctly against
// the provided PCR values (indexed by PCR index, SHA-256 digest as []byte).
// Returns the parsed and verified events on success.
func ValidateEventLogFromBytes(eventLogBytes []byte, pcrValues map[int][]byte) ([]attest.Event, error) {
	var attestPCRs []attest.PCR
	for index, digest := range pcrValues {
		attestPCRs = append(attestPCRs, attest.PCR{
			Index:     index,
			Digest:    digest,
			DigestAlg: crypto.SHA256,
		})
	}

	eventLog, err := attest.ParseEventLog(eventLogBytes)
	if err != nil {
		return nil, fmt.Errorf("ParseEventLog failed: %w", err)
	}

	events, err := eventLog.Verify(attestPCRs)
	if err != nil {
		return nil, fmt.Errorf("event log replay failed: %w", err)
	}

	if err := ValidateEventLog(events, false); err != nil {
		return nil, fmt.Errorf("event log validation failed: %w", err)
	}

	return events, nil
}

// ValidateEventLogFromFile replays the event log at eventLogFile against the
// PCR values in pcrYaml (YAML format), then runs the security validation rules.
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

// findGPTEventIndex returns the index of the first EV_EFI_GPT_EVENT that
// contains the EFI partition table signature in the event log.
func findGPTEventIndex(el *attest.EventLog) (int, error) {
	for i, ev := range el.Events(DefaultAlgo) {
		if ev.Type.String() == defaultEventString && bytes.Contains(ev.Data, defaultEvent) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("GPT event not found in event log")
}

// hasPartitionInGPT returns true if the raw GPT event data contains a partition
// entry with the given UTF-16LE name.
func hasPartitionInGPT(gptData []byte, name string) bool {
	if len(gptData) < gptHeaderSize+gptNumPartsSize {
		return false
	}
	numParts := binary.LittleEndian.Uint64(gptData[gptHeaderSize:])
	base := gptHeaderSize + gptNumPartsSize
	for i := 0; i < int(numParts); i++ {
		off := base + i*gptEntrySize
		if off+gptEntrySize > len(gptData) {
			break
		}
		n, err := utf16LEToString(gptData[off+gptEntryNameOff : off+gptEntryNameOff+gptEntryNameSize])
		if err == nil && n == name {
			return true
		}
	}
	return false
}

// patchGPTAttributes returns a copy of gptData with IMGA and IMGB Attributes
// fields set to imgaAttr and imgbAttr respectively.
func patchGPTAttributes(gptData []byte, imgaAttr, imgbAttr uint64) []byte {
	out := make([]byte, len(gptData))
	copy(out, gptData)
	if len(out) < gptHeaderSize+gptNumPartsSize {
		return out
	}
	numParts := binary.LittleEndian.Uint64(out[gptHeaderSize:])
	base := gptHeaderSize + gptNumPartsSize
	for i := 0; i < int(numParts); i++ {
		off := base + i*gptEntrySize
		if off+gptEntrySize > len(out) {
			break
		}
		n, err := utf16LEToString(out[off+gptEntryNameOff : off+gptEntryNameOff+gptEntryNameSize])
		if err != nil {
			continue
		}
		switch n {
		case "IMGA":
			binary.LittleEndian.PutUint64(out[off+gptEntryAttrOff:], imgaAttr)
		case "IMGB":
			binary.LittleEndian.PutUint64(out[off+gptEntryAttrOff:], imgbAttr)
		}
	}
	return out
}

// findGrubStageOne returns the index of the EVE GRUB stage 1 load event.
// It identifies this as the EV_EFI_BOOT_SERVICES_APPLICATION event immediately
// followed by an EV_IPL event containing "gptprio.next".
func findGrubStageOne(el *attest.EventLog) (int, error) {
	events := el.Events(DefaultAlgo)
	for i, ev := range events {
		if ev.Type.String() != "EV_EFI_BOOT_SERVICES_APPLICATION" {
			continue
		}
		if i+1 < len(events) {
			next := events[i+1]
			if next.Type.String() == "EV_IPL" && bytes.Contains(next.Data, []byte("gptprio.next")) {
				return i, nil
			}
		}
	}
	return -1, fmt.Errorf("GRUB stage 1 event not found")
}

// predictVariant predicts PCR values for one gpt partition state variant.
// It clones dst, patches its GPT event attributes, merges with src at gptIdx,
// restores the original GRUB stage 1 hash, then predicts all PCR values.
// If rootfsHash is non-nil it is used compute the value of PCR 13.
func predictVariant(originalSrc, src, dst *attest.EventLog, gptIdx int, v gptVariant, rootfsHash []byte) ([][]byte, error) {
	// Clone dst and patch its GPT event for this variant.
	dstClone := dst.Clone()
	gptData, _, err := dstClone.GetEventData(gptIdx)
	if err != nil {
		return nil, fmt.Errorf("getting dst GPT event: %w", err)
	}
	patched := patchGPTAttributes(gptData, v.imgaAttr, v.imgbAttr)
	if err := dstClone.PatchEventData(gptIdx, patched); err != nil {
		return nil, fmt.Errorf("patching GPT event: %w", err)
	}

	// Merge: src events up to gptIdx, then patched dst events from gptIdx onward.
	merged := src.Clone()
	if err := merged.OverrideEvents(gptIdx, dstClone); err != nil {
		return nil, fmt.Errorf("merging event logs: %w", err)
	}

	// Restore the GRUB stage 1 binary hash from the original source log.
	if grubIdx, err := findGrubStageOne(originalSrc); err == nil {
		data, digests, err := originalSrc.GetEventData(grubIdx)
		if err == nil {
			_ = merged.SetEventData(grubIdx, data, digests)
		}
	}

	// If a rootfs image hash is provided, patch the measurefs EV_IPL event so
	// PCR 13 is derived from the known image content.
	if len(rootfsHash) > 0 {
		if measIdx, err := findMeasurefsEventIndex(merged); err == nil {
			eventData := []byte(fmt.Sprintf("%s %s\x00", measurefsFSName, hex.EncodeToString(rootfsHash)))
			var newDigests []attest.Digest
			for _, alg := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				if !alg.Available() {
					continue
				}
				h := alg.New()
				h.Write(rootfsHash)
				newDigests = append(newDigests, attest.NewDigest(alg, h.Sum(nil)))
			}
			if err := merged.SetEventData(measIdx, eventData, newDigests); err != nil {
				return nil, fmt.Errorf("setting measurefs event: %w", err)
			}
		}
	}

	// Predict all PCRs.
	pcrs := make([][]byte, maxPcrIndex)
	for i := range maxPcrIndex {
		pcr := attest.PCR{Index: i, DigestAlg: crypto.SHA256, Digest: make([]byte, 32)}
		p, err := merged.Predict(pcr)
		if err != nil {
			return nil, fmt.Errorf("predicting PCR[%d]: %w", i, err)
		}
		pcrs[i] = p
	}
	return pcrs, nil
}

// PredictPCRs predicts the full set of PCR values that a device will have after
// updating from the firmware captured in srcLog to the firmware in dstLog.
//
// srcLog is the baseline event log bytes from the device's last known-good boot.
// dstLog is the incoming event log bytes received from the device during attestation.
//
// If rootfsHash is non-nil it is used compute the value of PCR 13.
// Returns the union of predicted PCR values across all synthesized states.
func PredictPCRs(srcLog, dstLog []byte, rootfsHash []byte) (map[int][][]byte, error) {
	src, err := attest.ParseEventLog(srcLog)
	if err != nil {
		return nil, fmt.Errorf("parsing src event log: %w", err)
	}
	dst, err := attest.ParseEventLog(dstLog)
	if err != nil {
		return nil, fmt.Errorf("parsing dst event log: %w", err)
	}

	gptIdx, err := findGPTEventIndex(src)
	if err != nil {
		return nil, err
	}

	dstGPTData, _, err := dst.GetEventData(gptIdx)
	if err != nil {
		return nil, fmt.Errorf("getting dst GPT event: %w", err)
	}
	hasIMGB := hasPartitionInGPT(dstGPTData, "IMGB")

	originalSrc := src.Clone()

	var allPCRSets [][][]byte
	for _, v := range gptVariants {
		if v.requireIMGB && !hasIMGB {
			continue
		}
		pcrSet, err := predictVariant(originalSrc, src, dst, gptIdx, v, rootfsHash)
		if err != nil {
			return nil, fmt.Errorf("variant prediction: %w", err)
		}
		allPCRSets = append(allPCRSets, pcrSet)
	}

	if len(allPCRSets) == 0 {
		return nil, fmt.Errorf("no variants produced: IMGA partition not found in dst event log")
	}

	result := unionByIndex(allPCRSets...)

	// For PCRs with no predicted final value, include both all-zeros
	// and all-0xFF (TPMs pre-initialise PCR values).
	allZero := make([]byte, 32)
	allFF := bytes.Repeat([]byte{0xFF}, 32)
	for i := 0; i < maxPcrIndex; i++ {
		hasValue := false
		for _, v := range result[i] {
			if len(v) > 0 {
				hasValue = true
				break
			}
		}
		if !hasValue {
			result[i] = [][]byte{allZero, allFF}
		}
	}

	return result, nil
}

// PredictPCRsFromFiles is a wrapper around PredictPCRs
func PredictPCRsFromFiles(srcFile, dstFile string, rootfsHash []byte) (map[int][][]byte, error) {
	srcBytes, err := os.ReadFile(srcFile)
	if err != nil {
		return nil, fmt.Errorf("reading src event log: %w", err)
	}
	dstBytes, err := os.ReadFile(dstFile)
	if err != nil {
		return nil, fmt.Errorf("reading dst event log: %w", err)
	}
	return PredictPCRs(srcBytes, dstBytes, rootfsHash)
}

// GetGptPartitionTable extracts the partition table from the event log bytes.
// If startEvent and startEventContent are nil, default values will be used.
func GetGptPartitionTable(eventLogBytes []byte, hashAlgo *attest.HashAlg, startEvent *string, startEventContent []byte, verbose bool) ([]PartitionTableEntry, error) {
	events, err := attest.ParseEventLog(eventLogBytes)
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

// GetGptPartitionTableFromFile is a convenience wrapper around GetGptPartitionTable
// for tools that work with files on disk.
func GetGptPartitionTableFromFile(eventLogFile string, hashAlgo *attest.HashAlg, startEvent *string, startEventContent []byte, verbose bool) ([]PartitionTableEntry, error) {
	data, err := os.ReadFile(eventLogFile)
	if err != nil {
		return nil, err
	}
	return GetGptPartitionTable(data, hashAlgo, startEvent, startEventContent, verbose)
}

// DumpEvents dumps all events in the event log bytes.
func DumpEvents(eventLogBytes []byte, hashAlgo *attest.HashAlg) error {
	eventLog, err := attest.ParseEventLog(eventLogBytes)
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

// DumpEventsFromFile is a wrapper around DumpEvents
func DumpEventsFromFile(eventLogFile string, hashAlgo *attest.HashAlg) error {
	data, err := os.ReadFile(eventLogFile)
	if err != nil {
		return err
	}
	return DumpEvents(data, hashAlgo)
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

// HashRootfsImage computes the SHA-256 digest of a squashfs rootfs image in
// exactly the same way GRUB's measurefs command does before extending PCR 13,
// which basically is <fs_name> <hex_hash>\0".
//
// The returned hash should be passed to PredictPCRs as rootfsHash.
func HashRootfsImage(imageBytes []byte) ([]byte, error) {
	if len(imageBytes) < squashfsTotalSizeOffset+4 {
		return nil, fmt.Errorf("image too small for squashfs superblock (%d bytes)", len(imageBytes))
	}

	magic := binary.LittleEndian.Uint32(imageBytes[0:4])
	if magic != squashfsMagic {
		return nil, fmt.Errorf("not a squashfs image: magic 0x%08x (expected 0x%08x)", magic, squashfsMagic)
	}

	totalSize := uint64(binary.LittleEndian.Uint32(imageBytes[squashfsTotalSizeOffset : squashfsTotalSizeOffset+4]))
	if totalSize == 0 {
		return nil, fmt.Errorf("squashfs total_size is zero")
	}
	if uint64(len(imageBytes)) < totalSize {
		return nil, fmt.Errorf("image truncated: squashfs declares %d bytes, only %d available", totalSize, len(imageBytes))
	}

	h := crypto.SHA256.New()
	h.Write(imageBytes[:totalSize])
	return h.Sum(nil), nil
}

// findMeasurefsEventIndex returns the index of the GRUB measurefs EV_IPL
// event in PCR 13. The event data has the form "<fs_name> <hex_hash>\0".
func findMeasurefsEventIndex(el *attest.EventLog) (int, error) {
	prefix := []byte(measurefsFSName + " ")
	for i, ev := range el.Events(DefaultAlgo) {
		if ev.Index == pcrMeasurefs &&
			ev.Type.String() == "EV_IPL" &&
			bytes.HasPrefix(ev.Data, prefix) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("measurefs EV_IPL event not found in PCR %d", pcrMeasurefs)
}
