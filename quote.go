// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Working out which PCR values a TPM quote vouches for.
//
// A quote carries a list of PCR values next to a signature that covers only some of
// them. The ones it does not cover look identical.

package evepcr

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/lf-edge/eve-api/go/attest"
)

// maxPlatformPCR is the highest PCR that describes how the platform booted. PCR 16
// is a debug register and 17 upwards belong to applications and localities.
const maxPlatformPCR = 15

// SignedPCRsFromQuote returns the PCR values a quote's TPM signature covers.
//
// verifiedAttestData must be the quote's TPMS_ATTEST blob whose signature the caller
// has already checked against the device's signing key. expectedNonce is the nonce
// the caller issued for this attestation.
//
// Requires that the nonce inside the signed blob is the one issued, that every PCR
// the signature covers is present as a SHA-256 value, and that the digest of exactly
// those values matches the digest inside the signature.
//
// PCRs the device reported but did not ask the TPM to sign are dropped.
func SignedPCRsFromQuote(verifiedAttestData []byte, pcrValues []*attest.TpmPCRValue,
	expectedNonce []byte) (SignedPCRs, error) {

	if len(verifiedAttestData) == 0 {
		return SignedPCRs{}, fmt.Errorf("quote carries no attestation data")
	}
	if len(expectedNonce) == 0 {
		return SignedPCRs{}, fmt.Errorf("no nonce to match, so this quote could be a replay of an older one")
	}

	attestData, err := tpm2.DecodeAttestationData(verifiedAttestData)
	if err != nil {
		return SignedPCRs{}, fmt.Errorf("cannot decode the attestation data: %w", err)
	}
	if attestData.Type != tpm2.TagAttestQuote {
		return SignedPCRs{}, fmt.Errorf("attestation data is not a quote")
	}
	if attestData.AttestedQuoteInfo == nil {
		return SignedPCRs{}, fmt.Errorf("quote carries no PCR information")
	}

	// The nonce is inside the signed blob.
	if !bytes.Equal(attestData.ExtraData, expectedNonce) {
		return SignedPCRs{}, fmt.Errorf("quote answers a different nonce")
	}

	selection := attestData.AttestedQuoteInfo.PCRSelection
	if selection.Hash != tpm2.AlgSHA256 {
		return SignedPCRs{}, fmt.Errorf("quote selected %s, and only SHA-256 is supported", selection.Hash)
	}
	if len(selection.PCRs) == 0 {
		return SignedPCRs{}, fmt.Errorf("quote signed an empty PCR selection")
	}

	// Anything that is not SHA-256 is not what the quote selected.
	sent := make(map[int][]byte, len(pcrValues))
	for _, pcr := range pcrValues {
		if pcr.GetHashAlgo() != attest.TpmHashAlgo_TPM_HASH_ALGO_SHA256 {
			continue
		}
		idx := int(pcr.GetIndex())
		if _, seen := sent[idx]; seen {
			return SignedPCRs{}, fmt.Errorf("quote carries PCR[%d] twice", idx)
		}
		sent[idx] = pcr.GetValue()
	}

	// Only what the signature covers.
	signed := make(map[int][]byte, len(selection.PCRs))
	for _, i := range selection.PCRs {
		v, ok := sent[i]
		if !ok {
			return SignedPCRs{}, fmt.Errorf("quote signed PCR[%d] but carries no SHA-256 value for it", i)
		}
		signed[i] = v
	}

	// The signature covers a digest of the selected values in selection order.
	digest := sha256.New()
	for _, i := range selection.PCRs {
		if _, err := digest.Write(signed[i]); err != nil {
			return SignedPCRs{}, fmt.Errorf("hashing PCR[%d]: %w", i, err)
		}
	}
	if !bytes.Equal(digest.Sum(nil), attestData.AttestedQuoteInfo.PCRDigest) {
		return SignedPCRs{}, fmt.Errorf("the PCR values do not match the digest the TPM signed")
	}

	// The digest above covered every PCR the TPM signed; only the platform ones are
	// returned.
	values := make(map[int][]byte, len(signed))
	for idx, v := range signed {
		if idx >= 0 && idx <= maxPlatformPCR {
			values[idx] = v
		}
	}
	if len(values) == 0 {
		return SignedPCRs{}, fmt.Errorf("quote signed no PCR in the platform range 0 to %d", maxPlatformPCR)
	}
	return NewSignedPCRs(values)
}
