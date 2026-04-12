# evepcr

Go library and CLI tools for predicting and validating TPM PCR values
across [EVE OS](https://github.com/lf-edge/eve) updates.

## What this solves

EVE measures its boot chain into TPM Platform Configuration Registers and
records the measurements in an event log. A remote controller can replay
that log to verify the device booted trusted software.

The problem comes after an OS update: the PCR values change (new rootfs,
different partition layout, updated GRUB commands), so the controller
needs to know what the new values will be *before* the device reboots.
This library predicts those values by parsing and splicing event logs,
patching the entries that differ between versions, and replaying the
result.

## Building

```sh
make build
```

This compiles the library and the CLI tools under `cmd/`. See
[cmd/README.md](cmd/README.md) for a description of each tool.

## Testing

```sh
make test
```

Downloads a rootfs test fixture on first run, then runs `go test ./...`.

End-to-end integration tests live in `script/` and boot real EVE images
in QEMU with a software TPM. See [docs/tests.md](docs/tests.md) for
details.
