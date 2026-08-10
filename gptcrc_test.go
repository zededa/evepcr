// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evepcr

import (
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"
	"unicode/utf16"
)

// buildGPTEvent assembles a UEFI_GPT_DATA event with the given header fields and
// partition names, so the parser can be fed values a device could lie about.
func buildGPTEvent(numSlots, entrySize uint32, names []string, slots []int) []byte {
	header := make([]byte, gptHeaderSize)
	copy(header, "EFI PART")
	binary.LittleEndian.PutUint32(header[gptHeaderSizeOff:], gptHeaderSize)
	binary.LittleEndian.PutUint32(header[gptNumEntriesOff:], numSlots)
	binary.LittleEndian.PutUint32(header[gptEntrySizeOff:], entrySize)

	// The header may claim a hostile entry size; the bytes that follow stay
	// small, which is exactly the shape of a malicious event.
	bodySize := int(entrySize)
	if bodySize < 1 || bodySize > gptMaxEntrySize {
		bodySize = gptMinEntrySize
	}
	entries := make([][]byte, len(names))
	for i, n := range names {
		e := make([]byte, bodySize)
		if bodySize >= gptEntryNameOff+gptEntryNameSize {
			for j, u := range utf16.Encode([]rune(n)) {
				binary.LittleEndian.PutUint16(e[gptEntryNameOff+j*2:], u)
			}
		}
		entries[i] = e
	}

	// a CRC over the array as laid out at the given slots, so a well-formed
	// event verifies and a malformed one still parses far enough to be rejected
	if numSlots > 0 && numSlots <= gptMaxNumSlots && entrySize >= gptMinEntrySize && entrySize <= gptMaxEntrySize {
		array := make([]byte, int(numSlots)*bodySize)
		for i, slot := range slots {
			if slot >= 0 && slot < int(numSlots) && i < len(entries) {
				copy(array[slot*bodySize:], entries[i])
			}
		}
		binary.LittleEndian.PutUint32(header[gptArrayCRCOff:], crc32.ChecksumIEEE(array))
	}
	binary.LittleEndian.PutUint32(header[gptHeaderCRCOff:], 0)
	binary.LittleEndian.PutUint32(header[gptHeaderCRCOff:], crc32.ChecksumIEEE(header))

	out := append([]byte{}, header...)
	count := make([]byte, gptNumPartsSize)
	binary.LittleEndian.PutUint64(count, uint64(len(names)))
	out = append(out, count...)
	for _, e := range entries {
		out = append(out, e...)
	}
	return out
}

// eveNames is EVE's own partition set, at the slots make-raw assigns.
var eveNames = []string{"EFI System", "IMGA", "IMGB", "CONFIG", "P3"}
var eveSlotNums = []int{0, 1, 2, 3, 8}

func TestParseGPTEventAcceptsEveLayout(t *testing.T) {
	ev := buildGPTEvent(128, 128, eveNames, eveSlotNums)

	layout, err := parseGPTEvent(ev)
	if err != nil {
		t.Fatalf("parseGPTEvent on EVE's own layout: %v", err)
	}
	for i, want := range eveSlotNums {
		if layout.slots[i] != want {
			t.Errorf("%s placed at slot %d, want %d", eveNames[i], layout.slots[i], want)
		}
	}
}

// The header's values come from an event log, so each one has to be rejected
// rather than used to size an allocation or index a slice. Every case here
// panicked before these bounds existed.
func TestParseGPTEventRejectsHostileHeaders(t *testing.T) {
	cases := []struct {
		name      string
		numSlots  uint32
		entrySize uint32
		names     []string
		wantErr   string
	}{
		{"more partitions than slots", 4, 128, eveNames, "5 partitions in 4 slots"},
		// EVE puts persist at slot 8, so an array of 6 slots cannot hold it even
		// though the partition count fits.
		{"slot beyond the array", 6, 128, eveNames, "the array has 6 slots"},
		{"entry too small for a name", 128, 64, eveNames, "64 byte partition entry"},
		{"entry size zero", 128, 0, eveNames, "0 byte partition entry"},
		{"entry size overflows", 128, 0xFFFFFFFF, eveNames, "partition entry"},
		{"slot count absurd", 0xFFFFFFFF, 128, eveNames, "slots in the partition array"},
		{"slot count zero", 0, 128, eveNames, "slots in the partition array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// must not panic, must not allocate wildly, must return an error
			_, err := parseGPTEvent(buildGPTEvent(tc.numSlots, tc.entrySize, tc.names, eveSlotNums))
			if err == nil {
				t.Fatalf("accepted a hostile GPT event")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseGPTEventRejectsTruncated(t *testing.T) {
	full := buildGPTEvent(128, 128, eveNames, eveSlotNums)
	for _, n := range []int{0, 1, 50, gptHeaderSize, gptHeaderSize + gptNumPartsSize, len(full) - 1} {
		if _, err := parseGPTEvent(full[:n]); err == nil {
			t.Errorf("accepted a GPT event truncated to %d bytes", n)
		}
	}
}

// A disk EVE did not create must be refused, not predicted from a guess.
func TestParseGPTEventRejectsForeignLayout(t *testing.T) {
	ev := buildGPTEvent(128, 128, []string{"EFI System", "rootfs", "data"}, []int{0, 1, 2})

	if _, err := parseGPTEvent(ev); err == nil {
		t.Error("accepted a partition layout that is not EVE's")
	}
}

// Patching attributes must leave both checksums consistent, or no device will
// ever report the predicted value.
func TestPatchGPTAttributesKeepsChecksumsConsistent(t *testing.T) {
	ev := buildGPTEvent(128, 128, eveNames, eveSlotNums)

	patched, err := patchGPTAttributesConsistent(ev, 0x0102000000000000, 0x0013000000000000)
	if err != nil {
		t.Fatalf("patchGPTAttributesConsistent: %v", err)
	}

	// re-parsing verifies the array CRC against the rebuilt array
	if _, err := parseGPTEvent(patched); err != nil {
		t.Errorf("patched event no longer self-consistent: %v", err)
	}
	// and the header CRC must cover the new array CRC
	hdr := append([]byte{}, patched[:gptHeaderSize]...)
	want := binary.LittleEndian.Uint32(hdr[gptHeaderCRCOff:])
	binary.LittleEndian.PutUint32(hdr[gptHeaderCRCOff:], 0)
	if got := crc32.ChecksumIEEE(hdr); got != want {
		t.Errorf("header CRC = 0x%08x, recomputes to 0x%08x", want, got)
	}
}
