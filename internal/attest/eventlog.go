// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
//
// This file is derived from https://github.com/google/go-attestation (attest/eventlog.go).
// Modifications:
//   - Removed dependency on github.com/google/go-tpm (validateQuote method removed,
//     HashAlg algorithm resolution now uses hardcoded TCG constants in types.go).
//   - Added Clone, OverrideEvents, ReplaceEvent, Predict, GetEventData, SetEventData
//     methods to EventLog.
//   - Refactored replayPCR to use extendPCREvents helper.
//   - Added extendEvents for PCR value prediction without digest validation.

package attest

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA384 and SHA512 implementations
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ReplayError describes the parsed events that failed to verify against
// a particular PCR.
type ReplayError struct {
	Events []Event
	// InvalidPCRs reports the set of PCRs where the event log replay failed.
	InvalidPCRs []int
}

func (e ReplayError) affected(pcr int) bool {
	for _, p := range e.InvalidPCRs {
		if p == pcr {
			return true
		}
	}
	return false
}

// Error returns a human-friendly description of replay failures.
func (e ReplayError) Error() string {
	return fmt.Sprintf("event log failed to verify: the following registers failed to replay: %v", e.InvalidPCRs)
}

// EventType indicates what kind of data an event is reporting.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
type EventType uint32

var eventTypeStrings = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}

// String returns the Spec name of the EventType, for example "EV_ACTION". If
// unknown, it returns a formatted string of the EventType value.
func (e EventType) String() string {
	if s, ok := eventTypeStrings[uint32(e)]; ok {
		return s
	}
	return fmt.Sprintf("EventType(0x%08x)", uint32(e))
}

// Event is a single event from a TCG event log. This reports discrete items such
// as BIOS measurements or EFI states.
//
// There are many pitfalls for using event log events correctly to determine the
// state of a machine[1]. In general it's much safer to only rely on the raw PCR
// values and use the event log for debugging.
//
// [1] https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
type Event struct {
	// order of the event in the event log.
	sequence int
	// Index of the PCR that this event was replayed against.
	Index int
	// Untrusted type of the event. This value is not verified by event log replays
	// and can be tampered with. It should NOT be used without additional context,
	// and unrecognized event types should result in errors.
	Type EventType

	// Data of the event. For certain kinds of events, this must match the event
	// digest to be valid.
	Data []byte
	// Digest is the verified digest of the event data. While an event can have
	// multiple for different hash values, this is the one that was matched to the
	// PCR value.
	Digest []byte
}

func (e *Event) digestEquals(b []byte) error {
	if len(e.Digest) == 0 {
		return errors.New("no digests present")
	}

	switch len(e.Digest) {
	case crypto.SHA256.Size():
		s := sha256.Sum256(b)
		if bytes.Equal(s[:], e.Digest) {
			return nil
		}
	case crypto.SHA1.Size():
		s := sha1.Sum(b)
		if bytes.Equal(s[:], e.Digest) {
			return nil
		}
	default:
		return fmt.Errorf("cannot compare hash of length %d", len(e.Digest))
	}

	return fmt.Errorf("digest (len %d) does not match", len(e.Digest))
}

// EventLog is a parsed measurement log. This contains unverified data representing
// boot events that must be replayed against PCR values to determine authenticity.
type EventLog struct {
	// Algs holds the set of algorithms that the event log uses.
	Algs []HashAlg

	rawEvents   []rawEvent
	specIDEvent *specIDEvent
}

func (e *EventLog) Clone() *EventLog {
	out := EventLog{
		Algs:      make([]HashAlg, len(e.Algs)),
		rawEvents: make([]rawEvent, len(e.rawEvents)),
	}
	copy(out.Algs, e.Algs)
	copy(out.rawEvents, e.rawEvents)
	if e.specIDEvent != nil {
		dupe := *e.specIDEvent
		out.specIDEvent = &dupe
	}

	return &out
}

// Serialize encodes the EventLog back to its binary TCG2 on-disk format.
func (e *EventLog) Serialize() ([]byte, error) {
	if e.specIDEvent == nil {
		return nil, errors.New("cannot serialize TPM 1.2 (SHA1-only) event logs")
	}

	algToID := func(h crypto.Hash) (uint16, error) {
		switch h {
		case crypto.SHA1:
			return uint16(HashSHA1), nil
		case crypto.SHA256:
			return uint16(HashSHA256), nil
		case crypto.SHA384:
			return uint16(HashSHA384), nil
		case crypto.SHA512:
			return uint16(HashSHA512), nil
		default:
			return 0, fmt.Errorf("unsupported hash algorithm %v", h)
		}
	}

	var buf bytes.Buffer

	spec := e.specIDEvent
	specHdr := specIDEventHeader{
		Signature:     wantSignature,
		PlatformClass: spec.platformClass,
		VersionMinor:  spec.versionMinor,
		VersionMajor:  spec.versionMajor,
		Errata:        spec.errata,
		UintnSize:     spec.uintnSize,
		NumAlgs:       uint32(len(spec.algs)),
	}
	var specData bytes.Buffer
	binary.Write(&specData, binary.LittleEndian, specHdr)
	for _, alg := range spec.algs {
		binary.Write(&specData, binary.LittleEndian, alg)
	}
	binary.Write(&specData, binary.LittleEndian, uint8(len(spec.vendorInfo)))
	specData.Write(spec.vendorInfo)

	firstEvHdr := rawEventHeader{
		PCRIndex:  0,
		Type:      uint32(eventTypeNoAction),
		Digest:    [20]byte{},
		EventSize: uint32(specData.Len()),
	}
	binary.Write(&buf, binary.LittleEndian, firstEvHdr)
	buf.Write(specData.Bytes())

	// write all rawEvents in TCG2 crypto-agile format.
	for _, ev := range e.rawEvents {
		binary.Write(&buf, binary.LittleEndian, rawEvent2Header{
			PCRIndex: uint32(ev.index),
			Type:     uint32(ev.typ),
		})
		binary.Write(&buf, binary.LittleEndian, uint32(len(ev.digests)))
		for _, d := range ev.digests {
			algID, err := algToID(d.hash)
			if err != nil {
				return nil, fmt.Errorf("event PCR%d: %w", ev.index, err)
			}
			binary.Write(&buf, binary.LittleEndian, algID)
			buf.Write(d.data)
		}
		binary.Write(&buf, binary.LittleEndian, uint32(len(ev.data)))
		buf.Write(ev.data)
	}

	return buf.Bytes(), nil
}

// Events returns events that have not been replayed against the PCR values and
// are therefore unverified. The returned events contain the digest that matches
// the provided hash algorithm, or are empty if that event didn't contain a
// digest for that hash.
//
// This method is insecure and should only be used for debugging.
func (e *EventLog) Events(hash HashAlg) []Event {
	var events []Event
	for _, re := range e.rawEvents {
		ev := Event{
			Index:    re.index,
			Type:     re.typ,
			Data:     re.data,
			sequence: re.sequence,
		}

		for _, digest := range re.digests {
			if h, err := hash.cryptoHash(); h != digest.hash || err != nil {
				continue
			}
			ev.Digest = digest.data
			break
		}
		events = append(events, ev)
	}
	return events
}

func (e *EventLog) OverrideEvents(index int, el *EventLog) error {
	if index < 0 || index >= len(e.rawEvents) || index >= len(el.rawEvents) {
		return fmt.Errorf("index %d out of bounds", index)
	}

	e.rawEvents = e.rawEvents[:index]
	e.rawEvents = append(e.rawEvents, el.rawEvents[index:]...)
	return nil
}

func (e *EventLog) SetEventData(index int, data []byte, di []Digest) error {
	if index < 0 || index >= len(e.rawEvents) {
		return fmt.Errorf("index %d out of bounds", index)
	}

	e.rawEvents[index].data = data
	e.rawEvents[index].digests = di
	return nil
}

func (e *EventLog) GetEventData(index int) ([]byte, []Digest, error) {
	if index < 0 || index >= len(e.rawEvents) {
		return nil, nil, fmt.Errorf("index %d out of bounds", index)
	}

	data := e.rawEvents[index].data
	digests := e.rawEvents[index].digests
	return data, digests, nil
}

func (e *EventLog) ReplaceEvent(index int, el *EventLog) error {
	if index < 0 || index >= len(e.rawEvents) || index >= len(el.rawEvents) {
		return fmt.Errorf("index %d out of bounds", index)
	}

	e.rawEvents[index] = rawEvent{
		sequence: el.rawEvents[index].sequence,
		index:    el.rawEvents[index].index,
		typ:      el.rawEvents[index].typ,
		data:     el.rawEvents[index].data,
		digests:  el.rawEvents[index].digests,
	}

	return nil
}

// PatchEventData replaces the data for the event at index and recomputes all
// digests using the hash algorithms declared in the event log.
func (e *EventLog) PatchEventData(index int, data []byte) error {
	if index < 0 || index >= len(e.rawEvents) {
		return fmt.Errorf("index %d out of bounds", index)
	}
	e.rawEvents[index].data = data

	var newDigests []Digest
	for _, alg := range e.Algs {
		hash, err := alg.cryptoHash()
		if err != nil {
			return fmt.Errorf("unknown algorithm %v: %w", alg, err)
		}
		h := hash.New()
		h.Write(data)
		newDigests = append(newDigests, Digest{hash: hash, data: h.Sum(nil)})
	}
	e.rawEvents[index].digests = newDigests
	return nil
}

func (e *EventLog) Predict(pcr PCR) ([]byte, error) {
	predict, err := extendEvents(e.rawEvents, pcr)
	if err != nil {
		return nil, fmt.Errorf("failed to predict PCR %d: %w", pcr.Index, err)
	}

	return predict, nil
}

// Verify replays the event log against a TPM's PCR values, returning the
// events which could be matched to a provided PCR value.
//
// PCRs provide no security guarantees unless they're attested to have been
// generated by a TPM. Verify does not perform these checks.
//
// An error is returned if the replayed digest for events with a given PCR
// index do not match any provided value for that PCR index.
func (e *EventLog) Verify(pcrs []PCR) ([]Event, error) {
	events, err := e.verify(pcrs)
	// If there were any issues replaying the PCRs, try each of the workarounds
	// in turn.
	if rErr, isReplayErr := err.(ReplayError); isReplayErr {
		for _, wkrd := range eventlogWorkarounds {
			if !rErr.affected(wkrd.affectedPCR) {
				continue
			}
			el := e.Clone()
			if err := wkrd.apply(el); err != nil {
				return nil, fmt.Errorf("failed applying workaround %q: %v", wkrd.id, err)
			}
			if events, err := el.verify(pcrs); err == nil {
				return events, nil
			}
		}
	}

	return events, err
}

func (e *EventLog) verify(pcrs []PCR) ([]Event, error) {
	events, err := replayEvents(e.rawEvents, pcrs)
	if err != nil {
		if _, isReplayErr := err.(ReplayError); isReplayErr {
			return nil, err
		}
		return nil, fmt.Errorf("pcrs failed to replay: %v", err)
	}
	return events, nil
}

func extend(pcr PCR, replay []byte, e rawEvent, locality byte) (pcrDigest []byte, eventDigest []byte, err error) {
	h := pcr.DigestAlg

	for _, digest := range e.digests {
		if digest.hash != pcr.DigestAlg {
			continue
		}
		if len(digest.data) != len(pcr.Digest) {
			return nil, nil, fmt.Errorf("digest data length (%d) doesn't match PCR digest length (%d)", len(digest.data), len(pcr.Digest))
		}
		hash := h.New()
		if len(replay) != 0 {
			hash.Write(replay)
		} else {
			b := make([]byte, h.Size())
			b[h.Size()-1] = locality
			hash.Write(b)
		}
		hash.Write(digest.data)
		return hash.Sum(nil), digest.data, nil
	}
	return nil, nil, fmt.Errorf("no event digest matches pcr algorithm: %v", pcr.DigestAlg)
}

func extendPCREvents(rawEvents []rawEvent, pcr PCR) ([]Event, []byte, error) {
	var (
		replay    []byte
		outEvents []Event
		locality  byte
	)

	for _, e := range rawEvents {
		if e.index != pcr.Index {
			continue
		}
		// If TXT is enabled then the first event for PCR0
		// should be a StartupLocality event. The final byte
		// of this event indicates the locality from which
		// TPM2_Startup() was issued. The initial value of
		// PCR0 is equal to the locality.
		if e.typ == eventTypeNoAction {
			if pcr.Index == 0 && len(e.data) == 17 && strings.HasPrefix(string(e.data), "StartupLocality") {
				locality = e.data[len(e.data)-1]
			}
			continue
		}
		replayValue, digest, err := extend(pcr, replay, e, locality)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extend PCR %d with event %d: %w", pcr.Index, e.sequence, err)
		}
		replay = replayValue
		outEvents = append(outEvents, Event{sequence: e.sequence, Data: e.data, Digest: digest, Index: pcr.Index, Type: e.typ})
	}

	return outEvents, replay, nil
}

// replayPCR replays the event log for a specific PCR, using pcr and
// event digests with the algorithm in pcr. An error is returned if the
// replayed values do not match the final PCR digest, or any event tagged
// with that PCR does not possess an event digest with the specified algorithm.
func replayPCR(rawEvents []rawEvent, pcr PCR) ([]Event, bool) {
	outEvents, replay, err := extendPCREvents(rawEvents, pcr)
	if err != nil {
		return nil, false
	}

	if len(outEvents) > 0 && !bytes.Equal(replay, pcr.Digest) {
		return nil, false
	}
	return outEvents, true
}

type pcrReplayResult struct {
	events     []Event
	successful bool
}

func extendEvents(rawEvents []rawEvent, pcr PCR) ([]byte, error) {
	_, replay, err := extendPCREvents(rawEvents, pcr)
	if err != nil {
		return nil, fmt.Errorf("failed to extend PCR %d: %w", pcr.Index, err)
	}

	return replay, nil
}

func replayEvents(rawEvents []rawEvent, pcrs []PCR) ([]Event, error) {
	var (
		invalidReplays []int
		verifiedEvents []Event
		allPCRReplays  = map[int][]pcrReplayResult{}
	)

	// Replay the event log for every PCR and digest algorithm combination.
	for _, pcr := range pcrs {
		events, ok := replayPCR(rawEvents, pcr)
		allPCRReplays[pcr.Index] = append(allPCRReplays[pcr.Index], pcrReplayResult{events, ok})
	}

	// Record PCR indices which do not have any successful replay. Record the
	// events for a successful replay.
pcrLoop:
	for i, replaysForPCR := range allPCRReplays {
		for _, replay := range replaysForPCR {
			if replay.successful {
				verifiedEvents = append(verifiedEvents, replay.events...)
				continue pcrLoop
			}
		}
		invalidReplays = append(invalidReplays, i)
	}

	if len(invalidReplays) > 0 {
		events := make([]Event, 0, len(rawEvents))
		for _, e := range rawEvents {
			events = append(events, Event{e.sequence, e.index, e.typ, e.data, nil})
		}
		sort.Ints(invalidReplays)
		return nil, ReplayError{
			Events:      events,
			InvalidPCRs: invalidReplays,
		}
	}

	sort.Slice(verifiedEvents, func(i int, j int) bool {
		return verifiedEvents[i].sequence < verifiedEvents[j].sequence
	})
	return verifiedEvents, nil
}

// EV_NO_ACTION is a special event type that indicates information to the parser
// instead of holding a measurement. For TPM 2.0, this event type is used to signal
// switching from SHA1 format to a variable length digest.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
const eventTypeNoAction = 0x03

// ParseEventLog parses an unverified measurement log.
func ParseEventLog(measurementLog []byte) (*EventLog, error) {
	var specID *specIDEvent
	r := bytes.NewBuffer(measurementLog)
	parseFn := parseRawEvent
	var el EventLog
	e, err := parseFn(r, specID)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	if e.typ == eventTypeNoAction && len(e.data) >= binary.Size(specIDEventHeader{}) {
		specID, err = parseSpecIDEvent(e.data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spec ID event: %v", err)
		}
		for _, alg := range specID.algs {
			el.Algs = append(el.Algs, HashAlg(alg.ID))
		}
		// Switch to parsing crypto agile events. Don't include this in the
		// replayed events since it intentionally doesn't extend the PCRs.
		parseFn = parseRawEvent2
		el.specIDEvent = specID
	} else {
		el.Algs = []HashAlg{HashSHA1}
		el.rawEvents = append(el.rawEvents, e)
	}
	sequence := 1
	for r.Len() != 0 {
		e, err := parseFn(r, specID)
		if err != nil {
			return nil, err
		}
		e.sequence = sequence
		sequence++
		el.rawEvents = append(el.rawEvents, e)
	}
	return &el, nil
}

type specIDEvent struct {
	platformClass uint32
	versionMinor  uint8
	versionMajor  uint8
	errata        uint8
	uintnSize     uint8
	algs          []specAlgSize
	vendorInfo    []byte
}

type specAlgSize struct {
	ID   uint16
	Size uint16
}

// Expected values for various Spec ID Event fields.
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=19
var wantSignature = [16]byte{0x53, 0x70,
	0x65, 0x63, 0x20, 0x49,
	0x44, 0x20, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x30,
	0x33, 0x00} // "Spec ID Event03\0"

const (
	wantMajor  = 2
	wantMinor  = 0
	wantErrata = 0
)

type specIDEventHeader struct {
	Signature     [16]byte
	PlatformClass uint32
	VersionMinor  uint8
	VersionMajor  uint8
	Errata        uint8
	UintnSize     uint8
	NumAlgs       uint32
}

// parseSpecIDEvent parses a TCG_EfiSpecIDEventStruct structure from the reader.
//
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
func parseSpecIDEvent(b []byte) (*specIDEvent, error) {
	r := bytes.NewReader(b)
	var header specIDEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading event header: %w: %X", err, b)
	}
	if header.Signature != wantSignature {
		return nil, fmt.Errorf("invalid spec id signature: %x", header.Signature)
	}
	if header.VersionMajor != wantMajor {
		return nil, fmt.Errorf("invalid spec major version, got %02x, wanted %02x",
			header.VersionMajor, wantMajor)
	}
	if header.VersionMinor != wantMinor {
		return nil, fmt.Errorf("invalid spec minor version, got %02x, wanted %02x",
			header.VersionMajor, wantMinor)
	}

	specAlg := specAlgSize{}
	e := specIDEvent{
		platformClass: header.PlatformClass,
		versionMinor:  header.VersionMinor,
		versionMajor:  header.VersionMajor,
		errata:        header.Errata,
		uintnSize:     header.UintnSize,
	}
	for i := 0; i < int(header.NumAlgs); i++ {
		if err := binary.Read(r, binary.LittleEndian, &specAlg); err != nil {
			return nil, fmt.Errorf("reading algorithm: %v", err)
		}
		e.algs = append(e.algs, specAlg)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, fmt.Errorf("reading vender info size: %v", err)
	}
	if r.Len() != int(vendorInfoSize) {
		return nil, fmt.Errorf("reading vendor info, expected %d remaining bytes, got %d", vendorInfoSize, r.Len())
	}
	if vendorInfoSize > 0 {
		e.vendorInfo = make([]byte, vendorInfoSize)
		if _, err := io.ReadFull(r, e.vendorInfo); err != nil {
			return nil, fmt.Errorf("reading vendor info: %v", err)
		}
	}
	return &e, nil
}

// Digest holds the hash algorithm and value for a single event digest.
type Digest struct {
	hash crypto.Hash
	data []byte
}

// NewDigest constructs a Digest from a hash algorithm and pre-computed value.
func NewDigest(hash crypto.Hash, value []byte) Digest {
	return Digest{hash: hash, data: value}
}

type rawEvent struct {
	sequence int
	index    int
	typ      EventType
	data     []byte
	digests  []Digest
}

// TPM 1.2 event log format. See "5.1 SHA1 Event Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

type eventSizeErr struct {
	eventSize uint32
	logSize   int
}

func (e *eventSizeErr) Error() string {
	return fmt.Sprintf("event data size (%d bytes) is greater than remaining measurement log (%d bytes)", e.eventSize, e.logSize)
}

func parseRawEvent(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEventHeader
	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, fmt.Errorf("header deserialization error: %w", err)
	}
	if h.EventSize > uint32(r.Len()) {
		return event, &eventSizeErr{h.EventSize, r.Len()}
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, fmt.Errorf("reading data error: %w", err)
	}

	digests := []Digest{{hash: crypto.SHA1, data: h.Digest[:]}}

	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: digests,
	}, nil
}

// TPM 2.0 event log format. See "5.2 Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

func parseRawEvent2(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEvent2Header

	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	event.typ = EventType(h.Type)
	event.index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest Digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if r.Len() < int(alg.Size) {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.data = make([]byte, alg.Size)
			digest.hash, err = HashAlg(alg.ID).cryptoHash()
			if err != nil {
				return event, fmt.Errorf("unknown algorithm ID %x: %v", algID, err)
			}
		}
		if len(digest.data) == 0 {
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.data); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err = binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize > uint32(r.Len()) {
		return event, &eventSizeErr{eventSize, r.Len()}
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, err
}

// AppendEvents takes a series of TPM 2.0 event logs and combines
// them into a single sequence of events with a single header.
//
// Additional logs must not use a digest algorithm which was not
// present in the original log.
func AppendEvents(base []byte, additional ...[]byte) ([]byte, error) {
	baseLog, err := ParseEventLog(base)
	if err != nil {
		return nil, fmt.Errorf("base: %v", err)
	}
	if baseLog.specIDEvent == nil {
		return nil, errors.New("tpm 1.2 event logs cannot be combined")
	}

	outBuff := make([]byte, len(base))
	copy(outBuff, base)
	out := bytes.NewBuffer(outBuff)

	for i, l := range additional {
		log, err := ParseEventLog(l)
		if err != nil {
			return nil, fmt.Errorf("log %d: %v", i, err)
		}
		if log.specIDEvent == nil {
			return nil, fmt.Errorf("log %d: cannot use tpm 1.2 event log as a source", i)
		}

	algCheck:
		for _, alg := range log.specIDEvent.algs {
			for _, baseAlg := range baseLog.specIDEvent.algs {
				if baseAlg == alg {
					continue algCheck
				}
			}
			return nil, fmt.Errorf("log %d: cannot use digest (%+v) not present in base log. Base log has digests: %+v", i, alg, baseLog.specIDEvent.algs)
		}

		for x, e := range log.rawEvents {
			// Serialize header (PCR index, event type, number of digests)
			binary.Write(out, binary.LittleEndian, rawEvent2Header{
				PCRIndex: uint32(e.index),
				Type:     uint32(e.typ),
			})
			binary.Write(out, binary.LittleEndian, uint32(len(e.digests)))

			// Serialize digests
			for _, d := range e.digests {
				var algID uint16
				switch d.hash {
				case crypto.SHA256:
					algID = uint16(HashSHA256)
				case crypto.SHA1:
					algID = uint16(HashSHA1)
				default:
					return nil, fmt.Errorf("log %d: event %d: unhandled hash function %v", i, x, d.hash)
				}

				binary.Write(out, binary.LittleEndian, algID)
				out.Write(d.data)
			}

			// Serialize event data
			binary.Write(out, binary.LittleEndian, uint32(len(e.data)))
			out.Write(e.data)
		}
	}

	return out.Bytes(), nil
}
