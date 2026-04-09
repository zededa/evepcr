# PCR Prediction Test

This document describes the end-to-end test that validates TPM PCR prediction across an EVE OS update.

## Goal

The test verifies that the prediction tool can correctly forecast which TPM PCR values will change after an EVE OS update, and what those new values will be. This is important because sealed secrets and remote attestation depend on knowing the expected PCR values in advance.

## Assumptions

TPM PCRs record measurements of software and configuration components at boot time. When EVE OS updates, only a subset of PCRs change. The test is built on the following assumptions:

- **PCR 5** reflects the GPT partition table layout. During an update, EVE writes a new rootfs image to the inactive partition, which changes the partition table and therefore changes PCR 5.
- **PCR 13** reflects the rootfs image itself. When a new rootfs is written, its measurement changes, so PCR 13 changes.
- **All other PCRs** are expected to remain stable across the update. This includes firmware PCRs (0 through 7), the bootloader, kernel command line, and configuration PCRs. PCR 14 in particular, must not change.

The prediction tool takes these assumptions as input and produces a set of predicted post-update PCR values that can be compared against the values actually measured after the update.

## Test Flow

The test proceeds through the following stages:

### 1. Boot EVE Version 1

The first EVE version is booted in a QEMU virtual machine with a software TPM. The virtual machine connects to the controller and completes onboarding. After onboarding, the system is rebooted so that all PCRs reflect the steady-state boot of the fully configured device.

### 4. Capture Baseline Measurements

After the reboot, the TPM event log and PCR values are captured from the running system. These serve as the baseline: they represent the known-good state before any update has occurred.

### 5. Simulate an Update

The rootfs image for the second EVE version is written to the inactive partition. This mirrors what the EVE update process does in production. The system is then rebooted into the new partition.

### 6. Capture Post-Update Measurements

After rebooting into the updated version, the TPM event log and PCR values are captured again. These are the ground-truth post-update measurements that the prediction will be compared against.

### 7. Predict and Validate

The prediction tool is given:
- The baseline event log (pre-update boot measurements)
- The post-update event log (ground-truth post-update measurements)
- The new rootfs image (to compute the new rootfs hash)
- The expected value of PCR 14 from the baseline (carried forward unchanged)

The tool produces a predicted set of PCR values and compares them against the ground-truth post-update measurements. Each PCR is reported as either matching or mismatching. The test passes only if all predicted values match the actual measured values.

## What Success Means

A passing test confirms that:
1. The prediction tool correctly identifies which PCRs change during an update.
2. The predicted values for PCR 5 and PCR 13 match what the TPM actually measured after the update.
3. All stable PCRs, including PCR 14, are correctly carried forward unchanged.
