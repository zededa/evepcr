// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evepcr

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// testdata/measurefs_tpm_event_log is EVE's own measure-config test fixture. An
// independent replay of it (start at zero, extend PCR 14 with each event's
// SHA-256 digest) yields the value below.
const measureConfigFixturePCR14 = "90f8ca2930f70193bc5e706794473d7c39b5937c58dc5b4504a086e925966db0"

func fixtureLog(t *testing.T) []byte {
	t.Helper()
	log, err := os.ReadFile("testdata/measurefs_tpm_event_log")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return log
}

// measureConfigEventBytes builds one PCR 14 measure-config event for a line.
func measureConfigEventBytes(line string) []byte {
	digest := sha256.Sum256([]byte(line))
	var b bytes.Buffer
	le := func(v uint32) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le(measureConfigPCR) // PcrIndex
	le(0x80000007)       // EventType (EV_EFI_ACTION)
	le(1)                // digest count
	_ = binary.Write(&b, binary.LittleEndian, uint16(tpmAlgSHA256))
	b.Write(digest[:])
	le(uint32(len(line)))
	b.WriteString(line)
	return b.Bytes()
}

func TestPredictPCR14FromMeasureConfigLog(t *testing.T) {
	pcr, err := PredictPCR14FromMeasureConfigLog(fixtureLog(t))
	if err != nil {
		t.Fatalf("PredictPCR14FromMeasureConfigLog: %v", err)
	}
	if got := hex.EncodeToString(pcr); got != measureConfigFixturePCR14 {
		t.Fatalf("PCR14 = %s, want %s", got, measureConfigFixturePCR14)
	}
}

// fixtureOriginBasename is the basename of the origin event in the fixture.
const fixtureOriginBasename = "origin.2023-11-20.0.0.0-measureconf_eventlog-62179e5c-dirty-2023-11-20.16.11"

// Substituting the fixture's own origin basename back in changes nothing.
func TestPredictPCR14ForUpdatedDevice_SelfIsNoOp(t *testing.T) {
	pcr, err := PredictPCR14ForUpdatedDevice(fixtureLog(t), fixtureOriginBasename)
	if err != nil {
		t.Fatalf("PredictPCR14ForUpdatedDevice: %v", err)
	}
	if got := hex.EncodeToString(pcr); got != measureConfigFixturePCR14 {
		t.Fatalf("self-substitution changed PCR14 to %s, want %s", got, measureConfigFixturePCR14)
	}
}

// A different install-version origin yields a different, deterministic value.
func TestPredictPCR14ForUpdatedDevice_DifferentOrigin(t *testing.T) {
	pcr, err := PredictPCR14ForUpdatedDevice(fixtureLog(t), "origin.2026-08-05.16.0.1-lts")
	if err != nil {
		t.Fatalf("PredictPCR14ForUpdatedDevice: %v", err)
	}
	if got := hex.EncodeToString(pcr); got == measureConfigFixturePCR14 {
		t.Fatalf("a different origin should change PCR14, but it stayed %s", got)
	}
	again, _ := PredictPCR14ForUpdatedDevice(fixtureLog(t), "origin.2026-08-05.16.0.1-lts")
	if !bytes.Equal(pcr, again) {
		t.Fatalf("substitution is not deterministic")
	}
}

// An empty basename is rejected.
func TestPredictPCR14ForUpdatedDevice_EmptyBasename(t *testing.T) {
	if _, err := PredictPCR14ForUpdatedDevice(fixtureLog(t), ""); err == nil {
		t.Fatalf("expected an error for an empty basename")
	}
}

// A log with no origin event cannot be substituted.
func TestPredictPCR14ForUpdatedDevice_NoOriginInLog(t *testing.T) {
	log := measureConfigEventBytes("file:/config/server exist:true content-hash:00")
	if _, err := PredictPCR14ForUpdatedDevice(log, "origin.x"); err == nil {
		t.Fatalf("expected an error when the log has no origin event")
	}
}

func TestPredictPCR14RejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":             {},
		"truncated header":  {0x0e, 0x00, 0x00},
		"truncated digest":  {0x0e, 0, 0, 0, 7, 0, 0, 0x80, 1, 0, 0, 0, 0x0b, 0x00, 0x01},
		"unknown algorithm": {0x0e, 0, 0, 0, 7, 0, 0, 0x80, 1, 0, 0, 0, 0xff, 0xff},
	}
	for name, in := range cases {
		if _, err := PredictPCR14FromMeasureConfigLog(in); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
