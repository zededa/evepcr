# evepcr

This tool and library predicts and validates TPM PCR values across EVE OS updates.

## Background

EVE uses a TPM to measure the boot chain into Platform Configuration Registers (PCRs). The measurements are recorded in an event log (`/sys/kernel/security/tpm0/binary_bios_measurements`) during each boot. To attest a device, a remote verifier (controller) replays the event log and checks that it produces the PCR values the device reported.

## Building

```sh
go build ./...
```

Binaries are written to the current directory: `eve-predict` and `eve-validate`.
