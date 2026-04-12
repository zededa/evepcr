# Tools

Command-line tools for TPM PCR prediction and EA policy management on EVE OS.

All tools read the `SWTPM_PATH` environment variable. When set to a Unix
socket path, the tool talks to a software TPM instead of `/dev/tpmrm0`.

## predict

Predicts post-update TPM PCR values from event logs.

Two modes of operation:

- **Delta mode** (`-old` + `-new`): compares a baseline event log against one
  captured after an update. Positional `index:hex` args are added to the
  predicted set.
- **Baseline-only mode** (`-old` only): works from a single event log.
  Positional `index:hex` args replace the baseline prediction for that PCR.

Writes a gob-encoded map of predicted PCR values. Optionally dumps the
predicted binary event log (`-dump-eventlog`) and compares against a YAML
file of actual values (`-compare`), exiting non-zero on mismatch.

```
predict -old baseline.bin -new updated.bin -rootfs rootfs.img -out pred.gob -verbose
predict -old baseline.bin -version 16.2.0-kvm-amd64 -rootfs rootfs.img 14:abcd...
```

## gen-policy

Generates a TPM EA authorization digest and signed policies, output as a
JSON bundle.

Takes either explicit `index:hex` PCR values on the command line, or a
gob file from `predict` (`-predict-gob`) with a set of PCR indexes
(`-pcr-indexes`). In the latter case it produces one signed policy per
PCR combination in the prediction set.

Supports an NV monotonic counter for rollback protection
(`-counter-index` + `-counter-val`).

```
gen-policy -key signing.pem -predict-gob pred.gob -pcr-indexes 0,4,13,14 -out bundle.json
gen-policy -key signing.pem -counter-index 0x1500017 -counter-val 5 0:abcd... 4:ef01...
```

## validate-policy

Tests the seal/unseal lifecycle against a policy bundle from `gen-policy`.

On first run (NV index does not exist), it defines the NV index,
optionally defines a monotonic counter, and seals a secret under the
authorization digest. On subsequent runs, it tries each policy in the
bundle until one successfully unseals the secret. Exits non-zero if all
policies fail.

Can load the bundle from a file (`-policy`) or from the active squashfs
partition (`-local`).

```
validate-policy -policy bundle.json -pub key.pub.pem -nv-index 0x1500016 0 4 13 14
validate-policy -local -pub key.pub.pem -nv-index 0x1500016 -counter-index 0x1500017 -verbose 0 4 13 14
```

## rootfs-hash

Computes the hash of a squashfs rootfs image, matching what EVE's
`measurefs` extends into PCR 13. Takes one argument (the image path) and
prints the hex digest to stdout.

```
rootfs-hash /path/to/rootfs.img
```

## validate-evtlog

Validates TPM event logs against actual PCR values from TPM quotes.
Replays both an old and current event log, checks GPT table consistency
between them, and compares predicted PCR values (from a gob file) against
the reported quote values. Prints per-PCR pass/fail results.

```
validate-evtlog \
  -old baseline.bin \
  -old-pcr-values old_pcrs.txt \
  -current current.bin \
  -curr-pcr-values current_pcrs.txt \
  -prediction pred.gob
```
