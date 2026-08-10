// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Deciding whether a device is running the image a controller published.

package evepcr

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"

	"github.com/lf-edge/eve-api/go/attest"
	eventlog "github.com/zededa/evepcr/internal/attest"
)

// maxEventLogSize bounds a decompressed event log. Real ones are tens of kilobytes.
const maxEventLogSize = 16 << 20

// PCRSelection names the PCRs a verdict rests on, supplied by the caller.
type PCRSelection struct {
	// Compared are the PCRs whose values the verdict matches against the
	// prediction, and which the quote must sign.
	Compared []int
	// BootLog are the PCRs the boot event log must contain events for. They are a
	// subset of Compared; the rest are measured after the boot log ends.
	BootLog []int
}

// SignedPCRs holds PCR values covered by a verified quote signature. Values outside
// the signed selection must not be put here.
type SignedPCRs struct {
	values map[int][]byte
}

// Verdict is the outcome of a check, and says why.
type Verdict struct {
	// OK is true only if every check passed.
	OK bool
	// Reason explains the outcome in one line, suitable for a log.
	Reason string
	// Checked lists the PCR indices the verdict rests on.
	Checked []int
	// Mismatch names the first PCR that did not match, when OK is false.
	Mismatch int
}

// NewSignedPCRs records SHA-256 PCR values whose signature the caller has already
// verified, keyed by PCR index.
func NewSignedPCRs(values map[int][]byte) (SignedPCRs, error) {
	if len(values) == 0 {
		return SignedPCRs{}, fmt.Errorf("no PCR values")
	}
	copied := make(map[int][]byte, len(values))
	for idx, v := range values {
		if len(v) != 32 {
			return SignedPCRs{}, fmt.Errorf("PCR[%d] is %d bytes, want a 32 byte SHA-256 digest", idx, len(v))
		}
		d := make([]byte, len(v))
		copy(d, v)
		copied[idx] = d
	}
	return SignedPCRs{values: copied}, nil
}

// Value returns the signed value for a PCR index.
func (s SignedPCRs) Value(index int) ([]byte, bool) {
	v, ok := s.values[index]
	return v, ok
}

// Indices returns the PCR indices present, in ascending order.
func (s SignedPCRs) Indices() []int {
	out := make([]int, 0, len(s.values))
	for idx := range s.values {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out
}

func (s SignedPCRs) asMap() map[int][]byte {
	out := make(map[int][]byte, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

// failed builds the Verdict for a check that did not pass, naming the PCR that
// decided it.
func failed(mismatch int, format string, args ...any) *Verdict {
	return &Verdict{OK: false, Reason: fmt.Sprintf(format, args...), Mismatch: mismatch}
}

// VerifyBaselineCandidate reports whether a log may be trusted as a device's
// baseline: that it is a truthful account of the boot the TPM signed.
//
// It says nothing about which image the device is running.
//
// The caller must have verified the quote's signature against the device's key.
func VerifyBaselineCandidate(quote *attest.ZAttestQuote, expectedNonce []byte, sel PCRSelection) (*Verdict, error) {
	quoted, err := SignedPCRsFromQuote(quote.GetAttestData(), quote.GetPcrValues(), expectedNonce)
	if err != nil {
		return failed(-1, "%s", err), nil
	}
	raw, err := DecompressEventLog(quote.GetTpmBinaryEventLog())
	if err != nil {
		return nil, err
	}
	if v := replaysAndCovers(raw, quoted, sel); !v.OK {
		return v, nil
	}
	checked := make([]int, len(sel.Compared))
	copy(checked, sel.Compared)
	return &Verdict{
		OK: true,
		Reason: fmt.Sprintf("event log replays to the signed values and accounts for all %d boot PCRs",
			len(sel.BootLog)),
		Checked: checked,
	}, nil
}

// VerifyUpdatedBoot reports whether a device is running the image the controller
// published, after the boot it reports no longer matches its baseline.
//
// baselineLog is the device's last trusted boot. referenceLog and
// referenceMeasureConfigLog were captured by booting the published image on a
// machine the controller controls: the firmware boot log and the measure-config
// log respectively. rootfsHash is the hash of that image. installOriginBasename is
// the basename of the device's /config origin file, which the device reports in
// its quote and which supplies its fixed origin stamp. quote is what the device
// just sent, and expectedNonce is the nonce issued for it.
//
// The caller must have verified the quote's signature against the device's key.
//
// The device's log is not an input to the prediction. It is checked: it must replay
// to the signed values and account for the PCRs the verdict rests on. The values
// compared against come from the baseline, the reference measurements and the
// published hash. PCR 14 is predicted from the target reference's measure-config
// log with the device's own origin stamp substituted in.
func VerifyUpdatedBoot(baselineLog, referenceLog, rootfsHash, referenceMeasureConfigLog []byte,
	installOriginBasename string, sel PCRSelection, quote *attest.ZAttestQuote, expectedNonce []byte) (*Verdict, error) {

	quoted, err := SignedPCRsFromQuote(quote.GetAttestData(), quote.GetPcrValues(), expectedNonce)
	if err != nil {
		return failed(-1, "%s", err), nil
	}

	switch {
	case len(baselineLog) == 0:
		return nil, fmt.Errorf("no baseline event log")
	case len(referenceLog) == 0:
		return nil, fmt.Errorf("no reference event log: an image with no reference measurement cannot be predicted")
	case len(rootfsHash) == 0:
		return nil, fmt.Errorf("no rootfs hash: PCR 13 would have nothing to anchor to")
	}

	raw, err := DecompressEventLog(quote.GetTpmBinaryEventLog())
	if err != nil {
		return nil, err
	}
	if v := replaysAndCovers(raw, quoted, sel); !v.OK {
		return v, nil
	}

	carryForward := map[int][]byte{}
	if len(referenceMeasureConfigLog) > 0 {
		var pcr14 []byte
		if installOriginBasename != "" {
			pcr14, err = PredictPCR14ForUpdatedDevice(referenceMeasureConfigLog, installOriginBasename)
		} else {
			// Without a reported install origin, the target reference's own /config
			// is used.
			pcr14, err = PredictPCR14FromMeasureConfigLog(referenceMeasureConfigLog)
		}
		if err != nil {
			return nil, fmt.Errorf("predicting PCR 14 for the updated device: %w", err)
		}
		carryForward[measureConfigPCR] = pcr14
	}

	predicted, _, err := PredictPCRsFromReference(baselineLog, referenceLog, rootfsHash, carryForward)
	if err != nil {
		return nil, fmt.Errorf("predicting the PCR values for the published image: %w", err)
	}

	for _, idx := range sel.Compared {
		want, ok := quoted.Value(idx)
		if !ok {
			return failed(idx, "the TPM did not sign PCR[%d], which the verdict depends on", idx), nil
		}
		// Only same-length candidates; an empty prediction is not a candidate.
		var candidates [][]byte
		for _, c := range predicted[idx] {
			if len(c) == len(want) {
				candidates = append(candidates, c)
			}
		}
		if len(candidates) == 0 {
			return failed(idx, "no value could be predicted for PCR[%d]", idx), nil
		}
		matched := false
		for _, c := range candidates {
			if bytes.Equal(c, want) {
				matched = true
				break
			}
		}
		if !matched {
			return failed(idx, "PCR[%d] is %x, which is not among the %d predicted value(s)",
				idx, want, len(candidates)), nil
		}
	}

	checked := make([]int, len(sel.Compared))
	copy(checked, sel.Compared)
	return &Verdict{
		OK:      true,
		Reason:  fmt.Sprintf("all %d checked PCR values match the published image", len(sel.Compared)),
		Checked: checked,
	}, nil
}

// replaysAndCovers checks that a log replays to the signed PCR values, that its
// digests match the data beside them, that the quote signs every Compared PCR, and
// that the log has events for every BootLog PCR.
func replaysAndCovers(raw []byte, quoted SignedPCRs, sel PCRSelection) *Verdict {
	events, err := VerifyEventLogFromBytes(raw, quoted.asMap())
	if err != nil {
		return failed(-1, "event log does not replay to the signed PCR values: %s", err)
	}

	// Replay never reads an event's data, so verify each derivable digest against
	// its own data.
	for _, ev := range events {
		want, ok := digestCoversData(ev)
		if !ok {
			continue
		}
		got := sha256.Sum256(want)
		if !bytes.Equal(got[:], ev.Digest) {
			return failed(ev.Index, "PCR[%d] event %q carries a digest that does not match its own contents",
				ev.Index, summarise(ev.Data))
		}
	}

	for _, idx := range sel.Compared {
		if _, ok := quoted.Value(idx); !ok {
			return failed(idx, "PCR[%d] must be signed but the quote did not sign it", idx)
		}
	}

	measured := make(map[int]bool, len(events))
	for _, ev := range events {
		measured[ev.Index] = true
	}
	for _, idx := range sel.BootLog {
		value, ok := quoted.Value(idx)
		if !ok {
			return failed(idx, "PCR[%d] must be signed but the quote did not sign it", idx)
		}
		if measured[idx] || isResetPCRValue(value) {
			continue
		}
		return failed(idx, "PCR[%d] is %x but the event log contains no events for it", idx, value)
	}
	return &Verdict{OK: true}
}

// digestCoversData returns the bytes an event's digest is defined over, and whether
// it is defined for this kind of event. Image loads and file measurements are
// digested over content not in the log, so they return false.
func digestCoversData(ev eventlog.Event) ([]byte, bool) {
	switch ev.Type.String() {
	case "EV_EFI_GPT_EVENT":
		return ev.Data, true
	case "EV_IPL":
		return grubEVIPLDigestData(ev.Data)
	}
	return nil, false
}

// summarise renders the printable part of an event for a message.
func summarise(data []byte) string {
	out := make([]byte, 0, 48)
	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			out = append(out, b)
		}
		if len(out) == 48 {
			break
		}
	}
	return string(out)
}

// isResetPCRValue reports whether a value is what an untouched PCR holds. A SHA-256
// PCR resets to zero; unimplemented ones are sometimes left all-ones.
func isResetPCRValue(v []byte) bool {
	if len(v) == 0 {
		return true
	}
	zero, ones := true, true
	for _, b := range v {
		if b != 0x00 {
			zero = false
		}
		if b != 0xff {
			ones = false
		}
	}
	return zero || ones
}

// DecompressEventLog accepts an event log gzipped or not, which is how devices send
// it, and bounds the result.
func DecompressEventLog(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("event log is empty")
	}
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		if len(data) > maxEventLogSize {
			return nil, fmt.Errorf("event log is %d bytes, over the %d byte limit", len(data), maxEventLogSize)
		}
		return data, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("event log is not valid gzip: %w", err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(io.LimitReader(zr, maxEventLogSize+1))
	if err != nil {
		return nil, fmt.Errorf("decompressing the event log: %w", err)
	}
	if len(raw) > maxEventLogSize {
		return nil, fmt.Errorf("decompressed event log exceeds the %d byte limit", maxEventLogSize)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("event log decompressed to nothing")
	}
	return raw, nil
}
