// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Prediction from a reference measurement, for a controller verifying a device
// it does not trust.
//
// The reference measurement is captured by the controller booting the image itself;
// the device's own log is never an input to the prediction.

package evepcr

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"unicode/utf16"

	"github.com/zededa/evepcr/internal/attest"
)

// What GRUB puts in front of the kernel path when it fills the LoadOptions buffer
// it hands to the kernel, and the name Linux's stub logs that measurement under.
const (
	loadOptionsPrefix    = "BOOT_IMAGE="
	loadOptionsEventName = "LOADED_IMAGE::LoadOptions"
)

// errPartitionNotOnDisk marks a target partition the device's disk does not have,
// which makes a variant inapplicable rather than a failure.
var errPartitionNotOnDisk = errors.New("partition not on this disk")

// pcrEvent is one event's measured content, lifted out of a log.
type pcrEvent struct {
	data    []byte
	digests []attest.Digest
}

// findRootfsBootloader returns the index of the second EV_EFI_BOOT_SERVICES_APPLICATION
// measured into PCR 4, which is where the ESP hands control to the rootfs.
//
// EVE boots GRUB twice. The firmware loads the copy on the ESP, which runs
// gptprio.next to pick the active partition and chainloads the copy inside that
// partition. Everything up to the second load describes the disk the device was
// installed from; everything after it comes out of the rootfs image.
func findRootfsBootloader(el *attest.EventLog) (int, error) {
	seen := 0
	for i, ev := range el.Events(DefaultAlgo) {
		if ev.Index != 4 || ev.Type.String() != "EV_EFI_BOOT_SERVICES_APPLICATION" {
			continue
		}
		seen++
		if seen == 2 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no rootfs bootloader load found in PCR 4")
}

// findESPBootCommand returns the index of the ESP bootloader's last command.
//
// GRUB measures "chainloader", then loads the image it names, then measures
// "boot" before handing control over. So the ESP's own commands bracket the
// rootfs image load, and everything the ESP contributes ends at this event.
func findESPBootCommand(el *attest.EventLog, rootfsLoadIdx int) (int, error) {
	for i, ev := range el.Events(DefaultAlgo) {
		if i <= rootfsLoadIdx || ev.Index != 8 || ev.Type.String() != "EV_IPL" {
			continue
		}
		if cmd, ok := grubCommandPayload(ev.Data); ok && cmd == "boot" {
			return i, nil
		}
		return -1, fmt.Errorf("the first PCR 8 command after the rootfs load is not boot: %q", ev.Data)
	}
	return -1, fmt.Errorf("no boot command found after the rootfs load")
}

// grubCommandPayload returns the command GRUB logged, without the tag it prefixes
// and without the terminator, and whether the event was a command at all.
func grubCommandPayload(data []byte) (string, bool) {
	for _, prefix := range []string{"grub_cmd: ", "grub_cmd "} {
		if bytes.HasPrefix(data, []byte(prefix)) {
			return string(trimTrailingNUL(data[len(prefix):])), true
		}
	}
	return "", false
}

// otherEvePartition returns EVE's other rootfs partition.
func otherEvePartition(p string) string {
	switch p {
	case "gpt2":
		return "gpt3"
	case "gpt3":
		return "gpt2"
	}
	return ""
}

// PredictPCRsFromReference predicts the PCR values a device will report after
// updating to the image described by referenceLog.
//
// baselineLog is the device's last trusted boot. referenceLog was captured by
// booting the new image on a machine the controller controls. rootfsHash is the
// hash of the image the controller published, and sets PCR 13. carryForward
// supplies values for registers no boot log describes (PCR 14), set by the caller.
//
// The two logs are spliced where the ESP hands over to the rootfs:
//
//	baseline    firmware, GPT, ESP bootloader, its config and its commands
//	reference   rootfs bootloader, kernel, their commands, measurefs
//
// An update replaces the rootfs and nothing else, so the disk it runs on stays the
// device's: its GPT layout in PCR 5, the bootloader written to its ESP at install
// time in PCR 4, and that bootloader's own commands and config in PCR 8 and 9. A
// reference machine has a different disk, and its ESP holds the new image's
// bootloader.
//
// Returns the union of predicted values across partition states, and the merged
// log of the first variant for debugging.
func PredictPCRsFromReference(baselineLog, referenceLog, rootfsHash []byte,
	carryForward map[int][]byte) (map[int][][]byte, []byte, error) {
	baseline, err := attest.ParseEventLog(baselineLog)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing baseline event log: %w", err)
	}
	reference, err := attest.ParseEventLog(referenceLog)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing reference event log: %w", err)
	}

	baseHandoff, err := findRootfsBootloader(baseline)
	if err != nil {
		return nil, nil, fmt.Errorf("baseline: %w", err)
	}
	refHandoff, err := findRootfsBootloader(reference)
	if err != nil {
		return nil, nil, fmt.Errorf("reference: %w", err)
	}

	// The GPT event comes from the baseline (the device's own partition table).
	gptIdx, err := findGPTEventIndex(baseline)
	if err != nil {
		return nil, nil, err
	}
	if gptIdx >= baseHandoff {
		return nil, nil, fmt.Errorf("GPT event at %d is not before the rootfs handoff at %d", gptIdx, baseHandoff)
	}
	gptData, _, err := baseline.GetEventData(gptIdx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting baseline GPT event: %w", err)
	}
	hasIMGB := hasPartitionInGPT(gptData, "IMGB")

	// Both halves must name the same partition before they are spliced.
	if bp, rp := detectBaselinePartition(baseline), detectBaselinePartition(reference); bp != rp {
		return nil, nil, fmt.Errorf("the baseline boots %s but the reference measurement was captured on %s, "+
			"which this cannot splice", bp, rp)
	}

	espBoot, err := findESPBootCommand(baseline, baseHandoff)
	if err != nil {
		return nil, nil, fmt.Errorf("baseline: %w", err)
	}
	refESPBoot, err := findESPBootCommand(reference, refHandoff)
	if err != nil {
		return nil, nil, fmt.Errorf("reference: %w", err)
	}
	// Predict both partitions: the other one (an update) and the current one (a reboot).
	targets := []string{detectBaselinePartition(baseline)}
	if other := otherEvePartition(targets[0]); other != "" {
		targets = append(targets, other)
	}

	var (
		allPCRSets [][][]byte
		firstLog   []byte
		lastErr    error
	)
	for _, target := range targets {
		for _, v := range gptVariants {
			if v.requireIMGB && !hasIMGB {
				continue
			}
			pcrs, merged, err := predictFromReferenceVariant(
				baseline, reference, baseHandoff, espBoot, refHandoff, refESPBoot,
				gptIdx, target, v, rootfsHash)
			if err != nil {
				// A target partition the disk does not have is skipped; any other
				// failure is reported.
				if errors.Is(err, errPartitionNotOnDisk) {
					lastErr = err
					continue
				}
				return nil, nil, err
			}
			allPCRSets = append(allPCRSets, pcrs)
			// Keep the log for the partition being switched to, which is the boot
			// the prediction is about. The same-partition variant comes first.
			if firstLog == nil || target != detectBaselinePartition(baseline) {
				if serialized, err := merged.Serialize(); err == nil {
					firstLog = serialized
				}
			}
		}
	}
	if len(allPCRSets) == 0 {
		if lastErr != nil {
			return nil, nil, fmt.Errorf("no variants produced: %w", lastErr)
		}
		return nil, nil, fmt.Errorf("no variants produced: IMGA not found in the baseline GPT")
	}

	result := unionByIndex(allPCRSets...)

	// Registers no boot log describes (PCR 14) are injected from carryForward.
	for idx, v := range carryForward {
		if idx >= 0 && idx < maxPcrIndex && len(v) > 0 {
			result[idx] = [][]byte{v}
		}
	}
	return result, firstLog, nil
}

// predictFromReferenceVariant builds one partition-state variant and predicts
// its PCR values.
func predictFromReferenceVariant(baseline, reference *attest.EventLog,
	srcHandoff, srcESPBoot, refHandoff, refESPBoot, gptIdx int, target string,
	v gptVariant, rootfsHash []byte) ([][]byte, *attest.EventLog, error) {

	merged := baseline.Clone()

	// The rootfs bootloader is the one measurement before the handoff that the
	// update replaces, so it comes from the reference while the ESP commands
	// around it stay the device's.
	refLoad, refDigests, err := reference.GetEventData(refHandoff)
	if err != nil {
		return nil, nil, fmt.Errorf("getting reference rootfs bootloader: %w", err)
	}
	if err := merged.SetEventData(srcHandoff, refLoad, refDigests); err != nil {
		return nil, nil, fmt.Errorf("setting rootfs bootloader: %w", err)
	}

	// Everything after the ESP's last command belongs to the new image, with one
	// exception: firmware measures the partition table twice, and its later
	// entries fall after the handoff. Those describe the device's own disk, so
	// they are taken from the baseline like the rest of PCR 5.
	tailPCR5, err := eventsForPCR(baseline, gptEventPCR, srcESPBoot+1)
	if err != nil {
		return nil, nil, err
	}
	if err := merged.SpliceEvents(srcESPBoot+1, reference, refESPBoot+1); err != nil {
		return nil, nil, fmt.Errorf("splicing after the ESP boot command: %w", err)
	}
	if err := replacePCREvents(merged, gptEventPCR, srcESPBoot+1, tailPCR5); err != nil {
		return nil, nil, fmt.Errorf("restoring the device's partition table events: %w", err)
	}

	// Point every partition reference at the partition being predicted. On the
	// merged log this covers the ESP's commands and the paths the new image reads
	// in one pass, against the device's own partition table.
	if detectBaselinePartition(merged) != target {
		alt, err := cloneWithAltPartition(merged, gptIdx)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: switching to %s: %s", errPartitionNotOnDisk, target, err)
		}
		merged = alt
	}

	// Patch the device's GPT for this boot state, checksums included.
	gptData, _, err := merged.GetEventData(gptIdx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting GPT event: %w", err)
	}
	patched, err := patchGPTAttributesConsistent(gptData, v.imgaAttr, v.imgbAttr)
	if err != nil {
		return nil, nil, fmt.Errorf("rewriting GPT event: %w", err)
	}
	if err := merged.PatchEventData(gptIdx, patched); err != nil {
		return nil, nil, fmt.Errorf("patching GPT event: %w", err)
	}

	// The LoadOptions measurement covers bytes no log carries, so rebuild it
	// from the command line now that the partition references are final.
	if err := fixLoadOptionsDigest(merged, reference); err != nil {
		return nil, nil, fmt.Errorf("rebuilding the LoadOptions measurement: %w", err)
	}

	// PCR 13 is anchored to the published image's rootfs hash, not to either log. A
	// log with no measurefs event to hold it is an error.
	if len(rootfsHash) > 0 {
		measIdx, err := findMeasurefsEventIndex(merged)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot anchor PCR 13: %w", err)
		}
		eventData := []byte(fmt.Sprintf("%s %s\x00", measurefsFSName, hex.EncodeToString(rootfsHash)))
		var digests []attest.Digest
		for _, alg := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if !alg.Available() {
				continue
			}
			h := alg.New()
			h.Write(rootfsHash)
			digests = append(digests, attest.NewDigest(alg, h.Sum(nil)))
		}
		if err := merged.SetEventData(measIdx, eventData, digests); err != nil {
			return nil, nil, fmt.Errorf("setting measurefs event: %w", err)
		}
	}

	pcrs := make([][]byte, maxPcrIndex)
	for i := range maxPcrIndex {
		p, err := merged.Predict(attest.PCR{Index: i, DigestAlg: crypto.SHA256, Digest: make([]byte, 32)})
		if err != nil {
			return nil, nil, fmt.Errorf("predicting PCR[%d]: %w", i, err)
		}
		pcrs[i] = p
	}
	return pcrs, merged, nil
}

// kernelCmdlineFromLog returns the kernel command line GRUB recorded, without its
// log tag or terminator.
func kernelCmdlineFromLog(el *attest.EventLog) ([]byte, error) {
	for _, ev := range el.Events(DefaultAlgo) {
		if ev.Index != 8 || ev.Type.String() != "EV_IPL" {
			continue
		}
		for _, prefix := range []string{"kernel_cmdline: ", "grub_kernel_cmdline "} {
			if bytes.HasPrefix(ev.Data, []byte(prefix)) {
				return trimTrailingNUL(ev.Data[len(prefix):]), nil
			}
		}
	}
	return nil, fmt.Errorf("no kernel command line found in PCR 8")
}

// fixLoadOptionsDigest recomputes the LOADED_IMAGE::LoadOptions measurement.
//
// Linux's EFI stub measures the LoadOptions buffer it was launched with, and logs
// only a tag and a description for it, so the measured bytes are not in the log. The
// buffer holds the kernel command line, which names the partition being booted, so
// the reference's digest cannot be carried over either.
//
// GRUB writes the command line into LoadOptions as UTF-16, prefixed with BOOT_IMAGE=
// and with no terminator, and the command line itself is recorded in PCR 8, where the
// partition has already been rewritten for the boot being predicted.
func fixLoadOptionsDigest(el, reference *attest.EventLog) error {
	// Releases before this measurement existed have no such event.
	idx := -1
	var data []byte
	for i, ev := range el.Events(DefaultAlgo) {
		if ev.Index == 9 && bytes.Contains(ev.Data, []byte(loadOptionsEventName)) {
			idx, data = i, ev.Data
			break
		}
	}
	if idx < 0 {
		return nil
	}

	// Self-check: rebuilt from the reference's own command line, the recipe must
	// reproduce the digest the reference recorded.
	if refCmdline, err := kernelCmdlineFromLog(reference); err == nil {
		want, err := loadOptionsDigestFrom(reference)
		if err != nil {
			return err
		}
		got := sha256.Sum256(utf16LEBytes(loadOptionsPrefix + string(refCmdline)))
		if !bytes.Equal(got[:], want) {
			return fmt.Errorf("cannot rebuild the %s measurement: the reference recorded %x, "+
				"but its own command line gives %x", loadOptionsEventName, want, got[:])
		}
	}

	cmdline, err := kernelCmdlineFromLog(el)
	if err != nil {
		return fmt.Errorf("%s is measured but %w", loadOptionsEventName, err)
	}
	return el.SetEventData(idx, data, recomputeDigests(utf16LEBytes(loadOptionsPrefix+string(cmdline)), el.Algs))
}

// loadOptionsDigestFrom returns the SHA-256 LoadOptions digest a log recorded.
func loadOptionsDigestFrom(el *attest.EventLog) ([]byte, error) {
	for _, ev := range el.Events(DefaultAlgo) {
		if ev.Index == 9 && bytes.Contains(ev.Data, []byte(loadOptionsEventName)) {
			return ev.Digest, nil
		}
	}
	return nil, fmt.Errorf("the reference has no %s measurement to check against", loadOptionsEventName)
}

// eventsForPCR collects the data and digests of a PCR's events from index
// onwards, so they can be put back after a splice replaced them.
func eventsForPCR(el *attest.EventLog, pcr, from int) ([]pcrEvent, error) {
	var out []pcrEvent
	for i, ev := range el.Events(DefaultAlgo) {
		if i < from || ev.Index != pcr {
			continue
		}
		data, digests, err := el.GetEventData(i)
		if err != nil {
			return nil, fmt.Errorf("reading PCR[%d] event %d: %w", pcr, i, err)
		}
		out = append(out, pcrEvent{data: data, digests: digests})
	}
	return out, nil
}

// replacePCREvents overwrites a PCR's events from index onwards with saved ones. The
// counts have to match: a difference means the two logs disagree about how many times
// the firmware touched that PCR.
func replacePCREvents(el *attest.EventLog, pcr, from int, saved []pcrEvent) error {
	var at []int
	for i, ev := range el.Events(DefaultAlgo) {
		if i >= from && ev.Index == pcr {
			at = append(at, i)
		}
	}
	if len(at) != len(saved) {
		return fmt.Errorf("the merged log has %d PCR[%d] events after the handoff but the baseline has %d",
			len(at), pcr, len(saved))
	}
	for n, i := range at {
		if err := el.SetEventData(i, saved[n].data, saved[n].digests); err != nil {
			return fmt.Errorf("restoring PCR[%d] event %d: %w", pcr, i, err)
		}
	}
	return nil
}

// utf16LEBytes encodes s as UTF-16LE, without a terminator.
func utf16LEBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range utf16.Encode([]rune(s)) {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
