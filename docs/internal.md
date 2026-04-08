# The problem we are solving

EVE devices use a TPM chip to record what software ran during boot. Each measurement gets folded into one of 24 registers called PCRs (Platform Configuration Registers). The folding operation is a hash extend: `PCR = SHA256(PCR || new_measurement)`. Because extend is one-way, a PCR value is a fingerprint of the entire sequence of measurements that produced it.

When the remote verifier (controller) wants to know whether a device booted trusted software, it asks the device for its current PCR values along with a signature proving they came from the TPM. That is called a TPM quote. The remote verifier then checks the values against a known-good set. If they match, the device is considered trustworthy.

The problem is that after an OS update, the PCR values change, because new OS components get measured. The remote verifier needs to know what the new values should be before it will accept quotes from updated devices. We cannot just trust whatever value the updated device reports, because a compromised device could report anything.

This tool solves that by computing predicted PCR values on demand, using the device's own baseline event log (saved before the update) and the event log the device submits after updating.

## What a TPM event log is

Every time UEFI measures something into a PCR, it also appends a record to the event log. The event log lives at `/sys/kernel/security/tpm0/binary_bios_measurements` on Linux. Each record contains:

- which PCR index received the measurement
- the event type (a number describing what kind of thing was measured)
- the SHA256 digest that was extended into the PCR
- the raw data that was hashed

Because the event log records every extend operation in order, you can replay it from scratch and arrive at the same PCR values the device has. That replay is how attestation works: the remote verifier replays the log and checks that it matches the quoted values. If it does, the log is trustworthy and you can inspect the individual events.

## How PCR values are predicted

The core prediction works like this:

1. Parse both the baseline event log (saved from the device before the update) and the received event log (submitted by the same device after the update).
2. Find the GPT event in the baseline log. This is the point where UEFI measured the partition table. Everything before this event is the same between old and new boots, because UEFI itself is not replaced by an EVE OS update. Everything from this event onward reflects the new OS.
3. Splice the logs: take events 0 through GPT-index-minus-1 from the baseline, then take events from GPT-index onward from the received log.
4. The merged log represents what the device measured during its post-update boot. Replay it to predict PCR values.

Step 3 works because UEFI itself (which produces the pre-GPT events) is not replaced by an EVE OS update. Only the IMGA or IMGB partition is replaced. So the early boot measurements stay the same, and the measurements from GPT onward reflect the new OS.

There is one additional fix needed in step 3. GRUB (the bootloader) lives on the EFI System Partition, which is also not updated during an EVE OS update. But GRUB gets measured by UEFI after the GPT event, so after the splice, the merged log carries the GRUB hash from the received log. In normal cases this is the same hash as in the baseline because GRUB did not change. As a safety net, the code explicitly restores the GRUB event digest from the baseline log to guarantee the prediction matches what the device actually measured.

The code for all of this is in `predictVariant` in [verifier.go](../verifier.go).

## How GRUB is identified in the event log

GRUB is identified by looking for an `EV_EFI_BOOT_SERVICES_APPLICATION` event immediately followed by an `EV_IPL` event whose data contains the string `gptprio.next`.

The reason this works: EVE's embedded GRUB config (`pkg/grub/embedded.cfg`) runs `gptprio.next` as its very first action to pick which partition to boot. GRUB measures each config command it executes into PCR[8] as an `EV_IPL` event. So the sequence of GRUB load followed immediately by the gptprio command is a reliable fingerprint for the EVE GRUB binary.

By finding and restoring the baseline GRUB event, the prediction stays correct even if the received log was captured at a point when GRUB happened to differ, and it also makes the test fixtures work reliably across devices with different GRUB builds.

## The GPT partition state problem

PCR[5] is where UEFI measures the GPT partition table. The GPT entry for each partition includes an Attributes field, and EVE uses bits in that field to track partition boot state (priority, tries remaining, whether the last boot was successful). These bits are read and written by GRUB's `gptprio` module.

Because the Attributes field is part of what gets measured, PCR[5] changes every time the partition state changes. During an EVE update cycle, the device goes through several distinct states, each producing a different PCR[5] value.

We need to predict all of them. If we only predict one, the remote verifier will reject attestation quotes from devices that are in any other valid state.

## The gptprio attribute encoding

The Attributes field in a GPT partition entry is a 64-bit integer. The `gptprio` module uses bits 48 through 56:

```text
bits 48-51  PRIORITY (4 bits, 0-15)
bits 52-55  TRIES_LEFT (4 bits, 0-15)
bit  56     SUCCESSFUL (1 bit)
```

GRUB selects the partition with the highest PRIORITY among partitions where either TRIES_LEFT is greater than zero or SUCCESSFUL is set. If the selected partition has tries remaining, GRUB decrements the count and writes it back to disk before handing off to the OS.

EVE's zboot tooling uses three meaningful states:

- `active` (cgpt value `0x102`): priority=2, tries=0, successful=1. This is the normal running state after a boot has been confirmed successful.
- `updating` (cgpt value `0x13`): priority=3, tries=1, successful=0. This is set when a new image has been written to the partition and the device needs to attempt booting it.
- `inprogress` (cgpt value `0x03`): priority=3, tries=0, successful=0. This is what `updating` becomes after GRUB decrements tries. If the OS does not call `MarkCurrentPartitionStateActive` before the next reboot, GRUB will not attempt to boot this partition again.
- `unused` (cgpt value `0x0`): priority=0. GRUB ignores this partition entirely.

In the full 64-bit Attributes field, these become:

```text
active     0x0102000000000000
updating   0x0013000000000000
inprogress 0x0003000000000000
unused     0x0000000000000000
```

## The eight partition state variants

Both IMGA and IMGB can be in various states at the time UEFI measures the GPT. We synthesize all the combinations that can actually occur during a normal update cycle, including failure and fallback paths.

When only IMGA is present (or IMGB is unused), two variants apply:

| IMGA | IMGB | When |
| --- | --- | --- |
| active | unused | Normal running state, IMGB not yet set up |
| updating | unused | IMGA is being updated, IMGB not yet set up |

When IMGB is present, six more variants apply:

| IMGA | IMGB | When |
| --- | --- | --- |
| active | updating | Normal first reboot after IMGB is installed |
| unused | active | Steady state after a successful IMGB update (MarkCurrentPartitionStateActive set IMGA to unused) |
| updating | active | IMGA is being updated while IMGB is the running partition |
| active | inprogress | IMGB's tries ran out, device fell back to IMGA |
| inprogress | active | IMGA's tries ran out, device fell back to IMGB |
| inprogress | updating | IMGA failed previously, now retrying IMGB |

Each of these produces a different set of bytes in the GPT event, which produces a different PCR[5] value after the SHA256 extend.

The variants are defined in `gptVariants` in [verifier.go](../verifier.go). For each variant, the code patches the IMGA and IMGB attribute fields in a clone of the destination GPT event, recomputes the event digest (since the digest is SHA256 of the event data), splices the patched log with the source log, restores the GRUB event, and replays to get PCR values.

The final output is a union across all variants: for each PCR index, the set of all distinct predicted values.

## GPT event patching

The GPT event data is a binary structure: a 92-byte EFI partition table header, followed by an 8-byte partition count, followed by 128-byte entries for each partition. The Attributes field sits at byte offset 48 within each partition entry, and the partition name (UTF-16LE, 72 bytes) starts at byte offset 56.

To patch the attributes, the code scans the entry list looking for partitions named "IMGA" and "IMGB" (by decoding the UTF-16LE name), then overwrites the 8-byte Attributes field for each one with the target value.

After patching the raw data, `PatchEventData` recomputes the event digest as SHA256 of the new event data for each hash bank. This is necessary because the TPM event digest is expected to equal the hash of the event data, and attestation replay will check that.

## PCR[13] prediction and the rootfs image

PCR[13] is extended by GRUB's `measurefs` command, which hashes the squashfs rootfs image and measures the result. The event log entry is an `EV_IPL` event in PCR[13] with event data of the form `"squash4 <hex_hash>\0"`.

GRUB computes `rawHash = SHA256(squashfs[:total_size])` and passes the raw 32 bytes directly to `EFI_TCG2_PROTOCOL.HashLogExtendEvent`. The firmware then computes the final digest as `SHA256(rawHash)`.

## The event log parser

The event log parser lives in `internal/attest/`. It was adapted from the Google `go-attestation` library. The parser handles the TCG2 binary event log format, supports SHA1, SHA256, SHA384, and SHA512 digest banks, and exposes methods for cloning a log, overriding events starting from a given index, getting and setting raw event data, and replaying the log to compute PCR values.

## Security validation

Beyond PCR value prediction, `eve-validate` also checks the event log for security-relevant conditions before accepting it. The checks are in `preValidateEventLog` in [verifier.go](../verifier.go):

- The `EV_SEPARATOR` event for PCR[7] must appear exactly once, and its data must be four zero bytes. This confirms the separator is present and well-formed.
- If any event in PCR[7] has data equal to `"UEFI Debug Mode"`, the log is rejected. UEFI measures this string when UEFI debug mode is active.
- If any event in PCR[7] has data equal to `"DMA Protection Disabled"`, the log is rejected.

These checks rely on event data rather than event type, because the event type field is not covered by the digest and could be forged. The data is what gets hashed into the PCR, so it can be trusted once the event log replay succeeds.
