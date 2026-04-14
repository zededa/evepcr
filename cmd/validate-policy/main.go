// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// validate-policy exercises the seal/unseal lifecycle against a policy bundle
// produced by gen-policy.
//
// Set SWTPM_PATH to a swtpm Unix socket to use a software TPM.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	tpmea "github.com/lf-edge/eve-tpmea"
)

type bundle struct {
	AuthDigest []byte        `json:"authDigest"`
	Policies   []policyEntry `json:"policies"`
}

type policyEntry struct {
	Digest       []byte     `json:"digest"`
	CounterCheck uint64     `json:"counterCheck,omitempty"`
	Sig          policySigJ `json:"sig"`
}

type policySigJ struct {
	RSASignature  []byte `json:"rsaSig,omitempty"`
	ECCSignatureR []byte `json:"eccSigR,omitempty"`
	ECCSignatureS []byte `json:"eccSigS,omitempty"`
}

func main() {
	policyPath := flag.String("policy", "", "JSON bundle produced by gen-policy (required unless -local)")
	local := flag.Bool("local", false, "load bundle from the active squashfs partition")
	pubPath := flag.String("pub", "", "PEM public key matching the private key used in gen-policy ")
	nvIndexStr := flag.String("nv-index", "", "NV handle for the sealed secret, hex (e.g. 0x1500016) or decimal")
	counterStr := flag.String("counter-index", "0", "NV monotonic counter handle; 0 disables rollback protection")
	algo := flag.String("algo", "sha256", "PCR hash algorithm: sha1, sha256, sha384, sha512")
	secretStr := flag.String("secret", "test-secret", "secret to seal on first run")
	verbose := flag.Bool("verbose", false, "print actual PCR values from the TPM before unsealing")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-policy <file> | -local] -pub <key.pem> -nv-index <handle> [flags] [pcr-index ...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "PCR index arguments: integers matching those passed to gen-policy, e.g.  0 4 14\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	for _, f := range []struct{ name, val string }{
		{"pub", *pubPath},
		{"nv-index", *nvIndexStr},
	} {
		if f.val == "" {
			fmt.Fprintf(os.Stderr, "error: -%s is required\n", f.name)
			flag.Usage()
			os.Exit(1)
		}
	}
	if !*local && *policyPath == "" {
		fmt.Fprintf(os.Stderr, "error: -policy is required (or use -local)\n")
		flag.Usage()
		os.Exit(1)
	}

	if path := os.Getenv("SWTPM_PATH"); path != "" {
		tpmea.ConnectToSwtpm(path)
	}

	nvIndex, err := parseHandle(*nvIndexStr)
	if err != nil {
		log.Fatalf("parse -nv-index: %v", err)
	}
	counterIndex, err := parseHandle(*counterStr)
	if err != nil {
		log.Fatalf("parse -counter-index: %v", err)
	}

	pcrIndexes, err := parsePCRIndexes(flag.Args())
	if err != nil {
		log.Fatalf("parse PCR indexes: %v", err)
	}

	var b bundle
	if *local {
		dev, err := findRootSquashfsDev()
		if err != nil {
			log.Fatalf("find root squashfs device: %v", err)
		}
		log.Printf("loading bundle from active partition %s", dev)
		b, err = readBundleFromDevice(dev)
		if err != nil {
			log.Fatalf("load bundle from partition: %v", err)
		}
	} else {
		var err error
		b, err = loadBundle(*policyPath)
		if err != nil {
			log.Fatalf("load policy bundle: %v", err)
		}
	}
	if len(b.Policies) == 0 {
		log.Fatalf("policy bundle contains no policies")
	}
	// all policies in a bundle must share the same counterCheck value
	for i := 1; i < len(b.Policies); i++ {
		if b.Policies[i].CounterCheck != b.Policies[0].CounterCheck {
			log.Fatalf("bundle counterCheck mismatch: policy 0 has %d, policy %d has %d",
				b.Policies[0].CounterCheck, i, b.Policies[i].CounterCheck)
		}
	}

	pub, err := loadPublicKey(*pubPath)
	if err != nil {
		log.Fatalf("load public key: %v", err)
	}

	pcrAlgo, err := parseAlgo(*algo)
	if err != nil {
		log.Fatalf("%v", err)
	}
	sel := tpmea.PCRSelection{Algo: pcrAlgo, Indexes: pcrIndexes}

	// decide seal vs unseal based on whether the NV index already exists
	_, existErr := tpmea.ReadNVAuthDigest(nvIndex)
	if existErr != nil {
		sealPath(nvIndex, counterIndex, b.AuthDigest, []byte(*secretStr))
	} else {
		unsealPath(nvIndex, counterIndex, pub, b.Policies, sel, *verbose)
	}
}

// sealPath creates the NV index and seals the secret under authDigest.
func sealPath(nvIndex, counterIndex uint32, authDigest, secret []byte) {
	log.Printf("NV index 0x%x not found - sealing", nvIndex)

	if counterIndex != 0 {
		val, err := tpmea.DefineMonotonicCounter(tpmea.RBP{Counter: counterIndex})
		if err != nil {
			log.Fatalf("define counter 0x%x: %v", counterIndex, err)
		}
		log.Printf("counter 0x%x value: %d", counterIndex, val)
	}

	if err := tpmea.SealSecret(nvIndex, authDigest, secret); err != nil {
		log.Fatalf("seal secret: %v", err)
	}
	log.Printf("secret sealed to NV index 0x%x", nvIndex)
}

// unsealPath reads the current counter value, increments it if needed,
// then tries each policy until one unseals successfully.
func unsealPath(nvIndex, counterIndex uint32, pub crypto.PublicKey, policies []policyEntry, sel tpmea.PCRSelection, verbose bool) {
	log.Printf("NV index 0x%x found - trying %d polic(ies)", nvIndex, len(policies))

	currentCounter := uint64(0)
	if counterIndex != 0 {
		val, err := tpmea.DefineMonotonicCounter(tpmea.RBP{Counter: counterIndex})
		if err != nil {
			log.Fatalf("read counter 0x%x: %v", counterIndex, err)
		}
		currentCounter = val
		log.Printf("counter 0x%x current value: %d", counterIndex, val)
	}

	if verbose {
		logPCRs(sel)
	}

	for i, entry := range policies {
		sp := tpmea.SignedPolicy{
			Digest: entry.Digest,
			Sig: &tpmea.PolicySignature{
				RSASignature:  entry.Sig.RSASignature,
				ECCSignatureR: entry.Sig.ECCSignatureR,
				ECCSignatureS: entry.Sig.ECCSignatureS,
			},
		}

		var rbp tpmea.RBP
		if counterIndex != 0 && entry.CounterCheck != 0 {
			if currentCounter > entry.CounterCheck {
				log.Printf("policy %d/%d: counter %d > check %d, skipping",
					i+1, len(policies), currentCounter, entry.CounterCheck)
				continue
			}
			rbp = tpmea.RBP{Counter: counterIndex, Check: entry.CounterCheck}
		}

		secret, err := tpmea.UnsealSecret(nvIndex, pub, sp, sel, rbp)
		if err != nil {
			log.Printf("policy %d/%d: unseal failed (%v)", i+1, len(policies), err)
			continue
		}

		log.Printf("policy %d/%d: unseal succeeded - secret: %q", i+1, len(policies), secret)

		// After a successful unseal, increment the counter to the check
		// value so that older policies with lower counter values can no
		// longer unseal (rollback protection).
		if counterIndex != 0 && entry.CounterCheck != 0 && currentCounter < entry.CounterCheck {
			for currentCounter < entry.CounterCheck {
				val, err := tpmea.IncreaseMonotonicCounter(tpmea.RBP{Counter: counterIndex})
				if err != nil {
					log.Fatalf("increment counter 0x%x: %v", counterIndex, err)
				}
				currentCounter = val
			}
			log.Printf("counter 0x%x incremented to %d", counterIndex, currentCounter)
		}
		return
	}

	log.Fatalf("all %d policies failed to unseal", len(policies))
}

func logPCRs(sel tpmea.PCRSelection) {
	pcrs, err := tpmea.ReadPCRs(sel.Indexes, sel.Algo)
	if err != nil {
		log.Printf("debug: could not read PCRs from TPM: %v", err)
		return
	}
	log.Printf("actual PCR values (%d indexes):", len(pcrs.Pcrs))
	for _, p := range pcrs.Pcrs {
		log.Printf("  PCR[%2d] = %s", p.Index, hex.EncodeToString(p.Digest))
	}
}

func parsePCRIndexes(args []string) ([]int, error) {
	out := make([]int, 0, len(args))
	for _, a := range args {
		n, err := strconv.Atoi(strings.TrimSpace(a))
		if err != nil || n < 0 || n > 23 {
			return nil, fmt.Errorf("invalid PCR index %q: must be 0-23", a)
		}
		out = append(out, n)
	}
	return out, nil
}

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

// findRootSquashfsDev returns the block device backing the squashfs rootfs.
func findRootSquashfsDev() (string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}
	fallback := ""
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[2] != "squashfs" {
			continue
		}
		if f[1] == "/" {
			return f[0], nil
		}
		if fallback == "" {
			fallback = f[0]
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("no squashfs mount found in /proc/mounts")
}

// readBundleFromDevice reads the size-prefixed JSON bundle appended
// squashfs rootfs on the given device.
func readBundleFromDevice(dev string) (bundle, error) {
	f, err := os.Open(dev)
	if err != nil {
		return bundle{}, err
	}
	defer f.Close()

	var b4 [4]byte
	if _, err := f.ReadAt(b4[:], 40); err != nil {
		return bundle{}, fmt.Errorf("read squashfs total_size from %s: %w", dev, err)
	}
	totalSize := int64(binary.LittleEndian.Uint32(b4[:]))
	log.Printf("squashfs total_size = %d bytes", totalSize)

	var b8 [8]byte
	if _, err := f.ReadAt(b8[:], totalSize); err != nil {
		return bundle{}, fmt.Errorf("read bundle size at offset %d: %w", totalSize, err)
	}
	jsonSize := int64(binary.LittleEndian.Uint64(b8[:]))
	if jsonSize <= 0 || jsonSize > 16<<20 {
		return bundle{}, fmt.Errorf("invalid bundle size %d at offset %d", jsonSize, totalSize)
	}

	jsonBuf := make([]byte, jsonSize)
	if _, err := f.ReadAt(jsonBuf, totalSize+8); err != nil {
		return bundle{}, fmt.Errorf("read bundle JSON at offset %d: %w", totalSize+8, err)
	}

	var b bundle
	if err := json.Unmarshal(jsonBuf, &b); err != nil {
		return bundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	return b, nil
}

func loadBundle(path string) (bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return bundle{}, err
	}
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return bundle{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return b, nil
}

func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
		}
		return pub, nil
	}
}
