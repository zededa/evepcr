// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Rewriting a GPT event so it stays internally consistent.
//
// Changing a partition's gptprio attributes changes two checksums in the GPT header:
// the CRC32 over the partition entry array and the CRC32 over the header itself.
// Firmware measures the header as it reads it, so both have to be repaired.
//
// The header checksum covers the 92 header bytes, which the event carries in full.
// The array checksum covers the whole on-disk entry array, typically 128 slots of
// 128 bytes, while the event lists only the slots that hold a partition and does not
// say which slots those are.

package evepcr

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	gptHeaderCRCOff  = 16 // CRC32 of the header, with this field zeroed
	gptHeaderSizeOff = 12 // bytes of header the CRC covers
	gptNumEntriesOff = 80 // slots in the on-disk entry array
	gptEntrySizeOff  = 84 // bytes per slot
	gptArrayCRCOff   = 88 // CRC32 of the whole on-disk entry array
	gptMinEntrySize  = 128
	gptMaxEntrySize  = 4096
	gptMaxNumSlots   = 512
)

// gptEventLayout describes a parsed GPT event.
type gptEventLayout struct {
	header    []byte   // the 92-byte partition table header
	entries   [][]byte // the partitions the event lists, in order
	slots     []int    // the on-disk slot each entry occupies
	numSlots  int      // slots in the on-disk array
	entrySize int      // bytes per slot
	arrayCRC  uint32   // the array CRC the header carries
	headerLen int      // bytes of header the header CRC covers
}

// eveGPTSlots is the partition numbering EVE uses, from the PART_OFFSET
// constants in pkg/mkimage-raw-efi/make-raw. They are fixed, so a partition's
// name gives its slot.
//
// Numbers there are 1-based partition numbers; slots are one lower. "EFI System"
// appears twice because EVE writes a second ESP at partition 7. Entries are in
// slot order.
var eveGPTSlots = []struct {
	name string
	slot int
}{
	{"EFI System", 0}, // partition 1
	{"IMGA", 1},       // partition 2
	{"IMGB", 2},       // partition 3
	{"CONFIG", 3},     // partition 4
	{"INVENTORY", 4},  // partition 5
	{"EFI System", 6}, // partition 7, the second ESP
	{"P3", 8},         // partition 9, persist
}

// parseGPTEvent reads a UEFI_GPT_DATA event and solves which on-disk slots its
// partitions occupy.
func parseGPTEvent(gptData []byte) (*gptEventLayout, error) {
	if len(gptData) < gptHeaderSize+gptNumPartsSize {
		return nil, fmt.Errorf("GPT event is %d bytes, too short for a header", len(gptData))
	}

	numSlots := int(binary.LittleEndian.Uint32(gptData[gptNumEntriesOff:]))
	entrySize := int(binary.LittleEndian.Uint32(gptData[gptEntrySizeOff:]))
	arrayCRC := binary.LittleEndian.Uint32(gptData[gptArrayCRCOff:])
	numParts := int(binary.LittleEndian.Uint64(gptData[gptHeaderSize:]))

	// These all came out of the event, so they are bounded before being used to
	// allocate or to index.
	if entrySize < gptMinEntrySize || entrySize > gptMaxEntrySize {
		return nil, fmt.Errorf("GPT event declares a %d byte partition entry", entrySize)
	}
	if entrySize < gptEntryNameOff+gptEntryNameSize {
		return nil, fmt.Errorf("GPT entry size %d is too small to hold a partition name", entrySize)
	}
	if numSlots < 1 || numSlots > gptMaxNumSlots {
		return nil, fmt.Errorf("GPT event declares %d slots in the partition array", numSlots)
	}
	if numParts < 1 || numParts > numSlots {
		return nil, fmt.Errorf("GPT event lists %d partitions in %d slots", numParts, numSlots)
	}

	base := gptHeaderSize + gptNumPartsSize
	// numParts and entrySize are both bounded above, so this cannot overflow.
	if base+numParts*entrySize > len(gptData) {
		return nil, fmt.Errorf("GPT event is %d bytes, too short for %d entries of %d bytes",
			len(gptData), numParts, entrySize)
	}

	headerLen := int(binary.LittleEndian.Uint32(gptData[gptHeaderSizeOff:]))
	if headerLen < gptHeaderSize || headerLen > len(gptData) {
		return nil, fmt.Errorf("GPT header declares a size of %d bytes", headerLen)
	}

	layout := &gptEventLayout{
		header:    gptData[:gptHeaderSize],
		numSlots:  numSlots,
		entrySize: entrySize,
		arrayCRC:  arrayCRC,
		headerLen: headerLen,
	}
	for i := 0; i < numParts; i++ {
		off := base + i*entrySize
		layout.entries = append(layout.entries, gptData[off:off+entrySize])
	}

	slots, err := solveGPTSlots(layout)
	if err != nil {
		return nil, err
	}
	layout.slots = slots
	return layout, nil
}

// solveGPTSlots works out which on-disk slots the event's partitions occupy, from
// EVE's numbering, and checks the result against the array checksum in the header.
func solveGPTSlots(layout *gptEventLayout) ([]int, error) {
	slots := make([]int, 0, len(layout.entries))
	next := 0
	for _, entry := range layout.entries {
		name, err := utf16LEToString(entry[gptEntryNameOff : gptEntryNameOff+gptEntryNameSize])
		if err != nil {
			return nil, fmt.Errorf("unreadable partition name: %w", err)
		}
		for next < len(eveGPTSlots) && eveGPTSlots[next].name != name {
			next++
		}
		if next >= len(eveGPTSlots) {
			return nil, fmt.Errorf("partition %q is not in EVE's layout", name)
		}
		if eveGPTSlots[next].slot >= layout.numSlots {
			return nil, fmt.Errorf("EVE places %q at slot %d but the array has %d slots",
				name, eveGPTSlots[next].slot, layout.numSlots)
		}
		slots = append(slots, eveGPTSlots[next].slot)
		next++
	}

	if got := crc32.ChecksumIEEE(buildGPTArray(layout, layout.entries, slots)); got != layout.arrayCRC {
		return nil, fmt.Errorf("GPT array CRC is 0x%08x, EVE's partition layout gives 0x%08x",
			layout.arrayCRC, got)
	}
	return slots, nil
}

// buildGPTArray lays the entries out at their slots in an otherwise empty
// on-disk partition array.
func buildGPTArray(layout *gptEventLayout, entries [][]byte, slots []int) []byte {
	array := make([]byte, layout.numSlots*layout.entrySize)
	for i, slot := range slots {
		if i >= len(entries) || slot < 0 || slot >= layout.numSlots {
			continue
		}
		copy(array[slot*layout.entrySize:], entries[i])
	}
	return array
}

// patchGPTAttributesConsistent sets IMGA and IMGB gptprio attributes and repairs
// both checksums, returning an event a device with those partition states would
// actually measure.
func patchGPTAttributesConsistent(gptData []byte, imgaAttr, imgbAttr uint64) ([]byte, error) {
	layout, err := parseGPTEvent(gptData)
	if err != nil {
		return nil, err
	}

	// Patch attributes on copies of the entries.
	entries := make([][]byte, len(layout.entries))
	for i, entry := range layout.entries {
		e := make([]byte, len(entry))
		copy(e, entry)
		name, err := utf16LEToString(e[gptEntryNameOff : gptEntryNameOff+gptEntryNameSize])
		if err == nil {
			switch name {
			case "IMGA":
				binary.LittleEndian.PutUint64(e[gptEntryAttrOff:], imgaAttr)
			case "IMGB":
				binary.LittleEndian.PutUint64(e[gptEntryAttrOff:], imgbAttr)
			}
		}
		entries[i] = e
	}

	// Rebuild the on-disk array with the patched entries and checksum it.
	arrayCRC := crc32.ChecksumIEEE(buildGPTArray(layout, entries, layout.slots))

	out := make([]byte, len(gptData))
	copy(out, gptData)
	binary.LittleEndian.PutUint32(out[gptArrayCRCOff:], arrayCRC)

	// The header checksum covers headerLen bytes with its own field zeroed. The
	// entries go in first: a header longer than the 92 bytes in use overlaps the
	// entry area, so checksumming before the write-back would cover stale bytes.
	base := gptHeaderSize + gptNumPartsSize
	for i, e := range entries {
		copy(out[base+i*layout.entrySize:], e)
	}

	binary.LittleEndian.PutUint32(out[gptHeaderCRCOff:], 0)
	binary.LittleEndian.PutUint32(out[gptHeaderCRCOff:], crc32.ChecksumIEEE(out[:layout.headerLen]))
	return out, nil
}
