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
// This file is derived from https://github.com/google/go-attestation (attest/attest.go).
// Modifications: removed dependency on github.com/google/go-tpm by hardcoding TPM_ALG_ID
// constants from the TCG specification, and removed TPM hardware interaction code.

package attest

import (
	"crypto"
	"fmt"
)

// HashAlg identifies a hashing Algorithm.
// Values correspond to TPM_ALG_ID constants from the TCG specification.
type HashAlg uint8

// Known valid hash algorithms.
// Numeric values are TPM_ALG_ID constants per TCG Algorithm Registry.
var (
	HashSHA1   = HashAlg(0x04) // TPM_ALG_SHA1
	HashSHA256 = HashAlg(0x0B) // TPM_ALG_SHA256
	HashSHA384 = HashAlg(0x0C) // TPM_ALG_SHA384
	HashSHA512 = HashAlg(0x0D) // TPM_ALG_SHA512
)

func (a HashAlg) cryptoHash() (crypto.Hash, error) {
	switch a {
	case HashSHA1:
		return crypto.SHA1, nil
	case HashSHA256:
		return crypto.SHA256, nil
	case HashSHA384:
		return crypto.SHA384, nil
	case HashSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: 0x%02x", uint8(a))
	}
}

// String returns a human-friendly representation of the hash algorithm.
func (a HashAlg) String() string {
	switch a {
	case HashSHA1:
		return "SHA1"
	case HashSHA256:
		return "SHA256"
	case HashSHA384:
		return "SHA384"
	case HashSHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("HashAlg(0x%02x)", uint8(a))
	}
}

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash

	// quoteVerified is true if the PCR was verified against a quote.
	quoteVerified bool
}

// QuoteVerified returns true if the value of this PCR was previously verified
// against a Quote.
func (p *PCR) QuoteVerified() bool {
	return p.quoteVerified
}
