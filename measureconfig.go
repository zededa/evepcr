// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Predicting PCR 14 from a measure-config event log.
//
// EVE's measure-config service extends PCR 14 in user-space, once per file under
// /config, and writes its own event log, separate from the boot event log and the
// quote. It is predicted from the log captured on the reference machine.
//
// Each event extends PCR 14 with SHA-256 of a line describing one config file:
//
//	file:<path> exist:true content-hash:<sha256 of contents>   for measured files
//	file:<path> exist:<bool>                                   for the rest
//
// Keys, certificates and serials are recorded by presence only.
//
// /config/origin.<date>.<version> is an empty stamp written when the config
// partition is built and never changed; its name carries the install version. After
// an update the device keeps its install-version stamp while the target reference
// carries the target version's, so PredictPCR14ForUpdatedDevice substitutes the
// device's origin event.

package evepcr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// measureConfigPCR is the PCR that EVE's measure-config service extends.
const measureConfigPCR = 14

// configOriginPrefix begins the measured line for the /config origin stamp.
const configOriginPrefix = "file:/config/origin."

// TPM algorithm identifiers and their digest lengths, for skipping banks other
// than SHA-256 in a crypto-agile event.
const (
	tpmAlgSHA1   = 0x0004
	tpmAlgSHA256 = 0x000b
	tpmAlgSHA384 = 0x000c
	tpmAlgSHA512 = 0x000d
	tpmAlgSM3    = 0x0012
)

var tpmAlgDigestLen = map[uint16]int{
	tpmAlgSHA1:   20,
	tpmAlgSHA256: 32,
	tpmAlgSHA384: 48,
	tpmAlgSHA512: 64,
	tpmAlgSM3:    32,
}

// measureConfigEvent is one parsed measure-config event.
type measureConfigEvent struct {
	pcr    uint32
	digest []byte
	data   []byte
}

// PredictPCR14FromMeasureConfigLog replays a measure-config log as it stands and
// returns the SHA-256 PCR 14 value it produces. Use this for a reference whose
// own /config is being predicted, where nothing is substituted.
func PredictPCR14FromMeasureConfigLog(log []byte) ([]byte, error) {
	return replayMeasureConfig(log, "")
}

// PredictPCR14ForUpdatedDevice predicts the PCR 14 a device reports after an
// update. targetLog is the measure-config log captured for the version being
// predicted; installOriginBasename is the basename of the device's /config origin
// file, reported in its quote. The origin event is rebuilt with that basename
// before the target log is replayed.
func PredictPCR14ForUpdatedDevice(targetLog []byte, installOriginBasename string) ([]byte, error) {
	if installOriginBasename == "" {
		return nil, fmt.Errorf("no install origin basename to substitute")
	}
	return replayMeasureConfig(targetLog, installOriginBasename)
}

// replayMeasureConfig extends PCR 14 with every PCR 14 event in the log. If
// installOriginBasename is set, the origin event is rebuilt with that basename,
// keeping the recorded presence and content hash, and extended with the rebuilt
// line's digest. It is then an error for the log to have no origin event.
func replayMeasureConfig(log []byte, installOriginBasename string) ([]byte, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("measure-config event log is empty")
	}

	pcr := make([]byte, sha256.Size)
	off := 0
	events := 0
	overrode := false
	for off < len(log) {
		ev, next, err := parseMeasureConfigEvent(log, off)
		if err != nil {
			return nil, err
		}
		off = next
		if ev.pcr != measureConfigPCR {
			continue
		}

		digest := ev.digest
		if installOriginBasename != "" && bytes.HasPrefix(ev.data, []byte(configOriginPrefix)) {
			rebuilt, err := rebuildOriginEvent(ev.data, installOriginBasename)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(rebuilt)
			digest = sum[:]
			overrode = true
		}

		h := sha256.New()
		h.Write(pcr)
		h.Write(digest)
		pcr = h.Sum(nil)
		events++
	}
	if events == 0 {
		return nil, fmt.Errorf("measure-config event log has no PCR %d events", measureConfigPCR)
	}
	if installOriginBasename != "" && !overrode {
		return nil, fmt.Errorf("measure-config event log has no /config origin event to substitute")
	}
	return pcr, nil
}

// rebuildOriginEvent replaces the filename in a measured origin line with basename,
// keeping the " exist:... content-hash:..." tail.
func rebuildOriginEvent(originData []byte, basename string) ([]byte, error) {
	tail := bytes.Index(originData, []byte(" exist:"))
	if tail < 0 {
		return nil, fmt.Errorf("origin event %q has no expected format", originData)
	}
	out := append([]byte("file:/config/"+basename), originData[tail:]...)
	return out, nil
}

// parseMeasureConfigEvent reads one event starting at off and returns it and the
// offset of the next event. The event is a TCG crypto-agile TPM2_PCR_EVENT2 with
// no spec-ID header, exactly as measure-config writes it.
func parseMeasureConfigEvent(log []byte, off int) (measureConfigEvent, int, error) {
	// PcrIndex (u32) + EventType (u32) + digest Count (u32).
	if off+12 > len(log) {
		return measureConfigEvent{}, 0, fmt.Errorf("measure-config log truncated in event header at offset %d", off)
	}
	ev := measureConfigEvent{pcr: binary.LittleEndian.Uint32(log[off:])}
	count := binary.LittleEndian.Uint32(log[off+8:])
	off += 12

	for i := uint32(0); i < count; i++ {
		if off+2 > len(log) {
			return measureConfigEvent{}, 0, fmt.Errorf("measure-config log truncated in digest header at offset %d", off)
		}
		alg := binary.LittleEndian.Uint16(log[off:])
		off += 2
		dlen, ok := tpmAlgDigestLen[alg]
		if !ok {
			return measureConfigEvent{}, 0, fmt.Errorf("measure-config log has unknown digest algorithm 0x%04x", alg)
		}
		if off+dlen > len(log) {
			return measureConfigEvent{}, 0, fmt.Errorf("measure-config log truncated in digest at offset %d", off)
		}
		if alg == tpmAlgSHA256 {
			ev.digest = log[off : off+dlen]
		}
		off += dlen
	}

	// EventSize (u32) then the event bytes, bounds-checked in uint64.
	if off+4 > len(log) {
		return measureConfigEvent{}, 0, fmt.Errorf("measure-config log truncated in event size at offset %d", off)
	}
	evSize := uint64(binary.LittleEndian.Uint32(log[off:]))
	off += 4
	if uint64(off)+evSize > uint64(len(log)) {
		return measureConfigEvent{}, 0, fmt.Errorf("measure-config log truncated in event data at offset %d", off)
	}
	ev.data = log[off : off+int(evSize)]
	off += int(evSize)

	if ev.pcr == measureConfigPCR && ev.digest == nil {
		return measureConfigEvent{}, 0, fmt.Errorf("measure-config PCR %d event carries no SHA-256 digest", measureConfigPCR)
	}
	return ev, off, nil
}
