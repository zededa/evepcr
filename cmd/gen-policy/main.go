// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// gen-policy generates a TPM EA authorization digest and one or more signed
// policies, packaged as a JSON bundle.
//
// Set SWTPM_PATH to a swtpm Unix socket to use a software TPM.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	tpmea "github.com/lf-edge/eve-tpmea"
)

type bundle struct {
	AuthDigest []byte            `json:"authDigest"`
	Policies   []signedPolicyOut `json:"policies"`
}

type signedPolicyOut struct {
	Digest       []byte       `json:"digest"`
	CounterCheck uint64       `json:"counterCheck,omitempty"`
	Sig          policySigOut `json:"sig"`
}

type policySigOut struct {
	RSASignature  []byte `json:"rsaSig,omitempty"`
	ECCSignatureR []byte `json:"eccSigR,omitempty"`
	ECCSignatureS []byte `json:"eccSigS,omitempty"`
}

func main() {
	keyFile := flag.String("key", "", "PEM private key (RSA or ECDSA)")
	algo := flag.String("algo", "sha256", "PCR hash algorithm: sha1, sha256, sha384, sha512")
	counterIndex := flag.String("counter-index", "0", "NV counter handle hex (e.g. 0x01000001) or decimal; 0 disables rollback protection")
	counterVal := flag.Uint64("counter-val", 0, "exact counter check value to embed in the policy")
	predictGob := flag.String("predict-gob", "", "PCR prediction gob file from eve-predict; generates one policy per PCR combination")
	pcrIndexes := flag.String("pcr-indexes", "", "comma-separated PCR indexes to select from -predict-gob (e.g. 0,4,14)")
	outFile := flag.String("out", "", "write JSON bundle to this file instead of stdout")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Single policy: %s -key k.pem [flags] <idx:hex> [...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Bundle:        %s -key k.pem -predict-gob pred.gob -pcr-indexes 0,4,14 [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Set SWTPM_PATH to a swtpm socket when no real TPM is present.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "error: -key is required")
		flag.Usage()
		os.Exit(1)
	}
	if *predictGob == "" && flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "error: provide PCR <index:hex> arguments or -predict-gob")
		flag.Usage()
		os.Exit(1)
	}
	if *predictGob != "" && *pcrIndexes == "" {
		fmt.Fprintln(os.Stderr, "error: -pcr-indexes is required with -predict-gob")
		flag.Usage()
		os.Exit(1)
	}

	if path := os.Getenv("SWTPM_PATH"); path != "" {
		tpmea.ConnectToSwtpm(path)
	}

	priv, err := loadPrivateKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading key: %v\n", err)
		os.Exit(1)
	}
	pub, err := publicKeyOf(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error extracting public key: %v\n", err)
		os.Exit(1)
	}

	pcrAlgo, err := parseAlgo(*algo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	handle, err := parseHandle(*counterIndex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing -counter-index: %v\n", err)
		os.Exit(1)
	}
	var rbp tpmea.RBP
	if handle != 0 {
		rbp = tpmea.RBP{Counter: handle, Check: *counterVal}
	}

	var pcrLists []tpmea.PCRList

	if *predictGob != "" {
		idxs, err := parseIntList(*pcrIndexes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing -pcr-indexes: %v\n", err)
			os.Exit(1)
		}
		predictions, err := loadPredictions(*predictGob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading prediction gob: %v\n", err)
			os.Exit(1)
		}
		combos := cartesian(predictions, idxs)
		if len(combos) == 0 {
			fmt.Fprintln(os.Stderr, "error: no PCR combinations produced - check -pcr-indexes vs gob content")
			os.Exit(1)
		}
		for _, pcrs := range combos {
			pcrLists = append(pcrLists, tpmea.PCRList{Algo: pcrAlgo, Pcrs: tpmea.PCRS(pcrs)})
		}
		fmt.Fprintf(os.Stderr, "info: generating %d polic(ies) from %d PCR combination(s)\n",
			len(pcrLists), len(pcrLists))
		for i, pl := range pcrLists {
			parts := make([]string, 0, len(pl.Pcrs))
			for _, p := range pl.Pcrs {
				d := p.Digest
				if len(d) > 4 {
					d = d[:4]
				}
				parts = append(parts, fmt.Sprintf("PCR%d=%x...", p.Index, d))
			}
			fmt.Fprintf(os.Stderr, "  policy %d/%d: %s\n", i+1, len(pcrLists), strings.Join(parts, "  "))
		}
	} else {
		pl, err := parsePCRs(flag.Args(), *algo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing PCR values: %v\n", err)
			os.Exit(1)
		}
		pcrLists = []tpmea.PCRList{pl}
	}

	// generate auth digest once
	authDigest, err := tpmea.GenerateAuthDigest(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating auth digest: %v\n", err)
		os.Exit(1)
	}

	// generate one signed policy per PCR combination
	out := bundle{AuthDigest: authDigest}
	for i, pl := range pcrLists {
		sp, err := tpmea.GenerateSignedPolicy(priv, pl, rbp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating policy %d: %v\n", i, err)
			os.Exit(1)
		}
		entry := signedPolicyOut{Digest: sp.Digest, CounterCheck: rbp.Check}
		if sp.Sig != nil {
			entry.Sig = policySigOut{
				RSASignature:  sp.Sig.RSASignature,
				ECCSignatureR: sp.Sig.ECCSignatureR,
				ECCSignatureS: sp.Sig.ECCSignatureS,
			}
		}
		out.Policies = append(out.Policies, entry)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling output: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outFile, err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(data)
	}
}

func loadPredictions(path string) (map[int][][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var data map[int][][]byte
	return data, gob.NewDecoder(f).Decode(&data)
}

// cartesian computes the Cartesian product of PCR value lists for the given
// indexes.
func cartesian(byIndex map[int][][]byte, indexes []int) [][]tpmea.PCR {
	if len(indexes) == 0 {
		return [][]tpmea.PCR{{}}
	}
	idx := indexes[0]
	vals, ok := byIndex[idx]
	if !ok || len(vals) == 0 {
		fmt.Fprintf(os.Stderr, "warning: PCR %d has no predicted values, skipping\n", idx)
		return cartesian(byIndex, indexes[1:])
	}
	sub := cartesian(byIndex, indexes[1:])
	out := make([][]tpmea.PCR, 0, len(vals)*len(sub))
	for _, v := range vals {
		for _, combo := range sub {
			entry := make([]tpmea.PCR, 0, 1+len(combo))
			entry = append(entry, tpmea.PCR{Index: idx, Digest: v})
			entry = append(entry, combo...)
			out = append(out, entry)
		}
	}
	return out
}

// parsePCRs converts "<index>:<hexdigest>" arguments into a tpmea.PCRList.
func parsePCRs(args []string, algo string) (tpmea.PCRList, error) {
	pcrAlgo, err := parseAlgo(algo)
	if err != nil {
		return tpmea.PCRList{}, err
	}
	pcrs := make(tpmea.PCRS, 0, len(args))
	for _, arg := range args {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			return tpmea.PCRList{}, fmt.Errorf("invalid PCR argument %q: want <index>:<hexdigest>", arg)
		}
		idx, err := strconv.Atoi(parts[0])
		if err != nil || idx < 0 || idx > 23 {
			return tpmea.PCRList{}, fmt.Errorf("invalid PCR index %q: must be 0-23", parts[0])
		}
		digest, err := hex.DecodeString(parts[1])
		if err != nil {
			return tpmea.PCRList{}, fmt.Errorf("invalid digest for PCR %d: %v", idx, err)
		}
		pcrs = append(pcrs, tpmea.PCR{Index: idx, Digest: digest})
	}
	return tpmea.PCRList{Algo: pcrAlgo, Pcrs: pcrs}, nil
}

// parseAlgo maps an algorithm name to tpmea.PCRHashAlgo.
func parseAlgo(s string) (tpmea.PCRHashAlgo, error) {
	switch s {
	case "sha1":
		return tpmea.AlgoSHA1, nil
	case "sha256":
		return tpmea.AlgoSHA256, nil
	case "sha384":
		return tpmea.AlgoSHA384, nil
	case "sha512":
		return tpmea.AlgoSHA512, nil
	default:
		return 0, fmt.Errorf("unknown algorithm %q, want sha1, sha256, sha384, or sha512", s)
	}
}

// parseHandle parses a TPM handle as decimal or 0x-prefixed hex into uint32.
func parseHandle(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	var val uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err = strconv.ParseUint(s[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(s, 10, 32)
	}
	if err != nil {
		return 0, fmt.Errorf("parse %q: %v", s, err)
	}
	return uint32(val), nil
}

// parseIntList parses a comma-separated list of integers.
func parseIntList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %w", p, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// loadPrivateKey reads a PEM file and returns the private key.
func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// publicKeyOf extracts the public key from an RSA or ECDSA private key.
func publicKeyOf(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", priv)
	}
}
