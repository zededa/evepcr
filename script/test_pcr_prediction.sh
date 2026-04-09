#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# test_pcr_prediction.sh — end-to-end test for TPM PCR prediction across EVE OS updates.
#
# Boots two consecutive EVE versions in QEMU (TPM enabled), captures TPM
# measurements before and after an update, then validates that the prediction
# tool correctly forecasts the post-update PCR values.
#
# Usage: ./test_pcr_prediction.sh [--skip-build] [--predict]
#

set -euo pipefail

# ── option parsing ─────────────────────────────────────────────────────────────
SKIP_BUILD=false
PREDICT_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --skip-build)  SKIP_BUILD=true ;;
        --predict)     PREDICT_ONLY=true ;;
        *) echo "[ERROR] Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# ── configuration ─────────────────────────────────────────────────────────────
# Two consecutive EVE release tags to test.
EVE_VERSION_1="16.1.0"
EVE_VERSION_2="16.11.0"

EVE_SERIAL="shahshah"
SSH_PORT=2222

EVE_REPO_URL="https://github.com/lf-edge/eve.git"
EVE_RELEASES_URL="https://github.com/lf-edge/eve/releases/download"
ROOTFS_ASSET="amd64.kvm.generic.rootfs.img"

# Working directory
WORK_DIR="$PWD/out/pcrpred-test-workdir"

# ── derived paths ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EVE_DIR="$WORK_DIR/eve"
ROOTFS_DIR="$WORK_DIR/rootfs"
MEASUREMENTS_DIR="$WORK_DIR/measurements"
SSH_KEY="$WORK_DIR/eve_key"

ROOTFS_V1="$ROOTFS_DIR/${EVE_VERSION_1}.img"
ROOTFS_V2="$ROOTFS_DIR/${EVE_VERSION_2}.img"

EVE_PREDICT="$REPO_ROOT/cmd/eve-predict/eve-predict"
EVE_VALIDATE="$REPO_ROOT/cmd/eve-validate/eve-validate"
EVE_ROOTFS_HASH="$REPO_ROOT/cmd/eve-rootfs-hash/eve-rootfs-hash"

BASELINE_EVENTLOG="$MEASUREMENTS_DIR/baseline_eventlog"
BASELINE_PCRS="$MEASUREMENTS_DIR/baseline_pcrs.yaml"
UPDATED_EVENTLOG="$MEASUREMENTS_DIR/updated_eventlog"
UPDATED_PCRS="$MEASUREMENTS_DIR/updated_pcrs.yaml"
PREDICTIONS_GOB="$MEASUREMENTS_DIR/predictions.gob"

ADAM_REPO_URL="https://github.com/shjala/adam.git"
ADAM_BRANCH="MinimalistAdam"
ADAM_DIR="$WORK_DIR/adam"
ADAM_BUILD_LOG="$WORK_DIR/adam_build.log"
ADAM_RUN_LOG="$WORK_DIR/adam_run.log"

QEMU_PID=""
ADAM_PID=""
EVE_RUN_LOG=""

# ── helpers ───────────────────────────────────────────────────────────────────

log_info()  { echo "[INFO]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }

ssh_cmd() {
    ssh -i "$SSH_KEY" -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=5 \
        root@localhost "$@"
}

scp_to_eve() {
    # Use ssh+cat pipe instead of scp to avoid SFTP subsystem issues with
    # EVE's dropbear (older dropbear resets the connection at kex when scp
    # negotiates the SFTP subsystem).
    ssh_cmd "cat > $2" < "$1"
}

require_tool() {
    command -v "$1" &>/dev/null || { log_error "Required tool not found: $1"; exit 1; }
}

wait_for_ssh() {
    log_info "Waiting for SSH on port $SSH_PORT..."
    local attempts=0
    while ! ssh_cmd "echo ok" &>/dev/null; do
        sleep 5
        attempts=$((attempts + 1))
        if [ $((attempts % 12)) -eq 0 ]; then
            log_info "  Still waiting for SSH... ($((attempts * 5))s elapsed)"
        fi
    done
    log_info "SSH is up."
}

wait_for_onboard() {
    log_info "Waiting for EVE to onboard (checking /run/diag.out)..."
    while true; do
        if ssh_cmd "grep -q 'Connected to EV Controller and onboarded' /run/diag.out 2>/dev/null"; then
            log_info "EVE is onboarded."
            break
        fi
        sleep 15
    done
}

reboot_and_wait() {
    log_info "Rebooting EVE..."
    ssh_cmd "reboot" || true
    sleep 15
    wait_for_ssh
}

cleanup() {
    if [ -n "$ADAM_PID" ] && kill -0 "$ADAM_PID" 2>/dev/null; then
        log_info "Stopping Adam (PID $ADAM_PID)..."
        kill "$ADAM_PID" || true
    fi
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        log_info "Stopping QEMU (PID $QEMU_PID)..."
        kill "$QEMU_PID" || true
    fi
}
trap cleanup EXIT

if $PREDICT_ONLY; then
    log_info "=== --predict: skipping to step 14 ==="
    # Jump straight to the prediction step; measurements must already exist.
    for f in "$BASELINE_EVENTLOG" "$UPDATED_EVENTLOG" "$UPDATED_PCRS" "$BASELINE_PCRS" "$ROOTFS_V2"; do
        if [ ! -f "$f" ]; then
            log_error "Required file not found: $f (run without --predict first)"
            exit 1
        fi
    done
    # Still need the Go tools built.
    for tool_name in eve-predict eve-validate eve-rootfs-hash; do
        log_info "Building $tool_name..."
        (cd "$REPO_ROOT/cmd/$tool_name" && go build -o "$tool_name" .)
    done
else

# ── step 1: prerequisites and directory setup ─────────────────────────────────

log_info "=== Step 1: Prerequisites ==="

require_tool curl
require_tool git
require_tool go
require_tool ssh
require_tool scp
require_tool ssh-keygen

mkdir -p "$WORK_DIR" "$ROOTFS_DIR" "$MEASUREMENTS_DIR"

# Build Go tools.
for tool_name in eve-predict eve-validate eve-rootfs-hash; do
    log_info "Building $tool_name..."
    (cd "$REPO_ROOT/cmd/$tool_name" && go build -o "$tool_name" .)
done

# ── step 2: fetch EVE source ───────────────────────────────────────────────────

log_info "=== Step 2: Fetch EVE source ==="

if [ ! -d "$EVE_DIR/.git" ]; then
    log_info "Cloning EVE repository to $EVE_DIR ..."
    git clone --quiet "$EVE_REPO_URL" "$EVE_DIR"
else
    log_info "EVE repository already cloned."
fi

pushd "$EVE_DIR" > /dev/null
log_info "Fetching all tags..."
git fetch --tags --quiet
popd > /dev/null

# ── step 3: download rootfs images for both versions ──────────────────────────

log_info "=== Step 3: Download rootfs images ==="

for version in "$EVE_VERSION_1" "$EVE_VERSION_2"; do
    dest="$ROOTFS_DIR/${version}.img"
    if [ ! -f "$dest" ]; then
        url="${EVE_RELEASES_URL}/${version}/${ROOTFS_ASSET}"
        log_info "Downloading rootfs for $version ..."
        curl -fL --progress-bar -o "$dest" "$url"
    else
        log_info "Rootfs for $version already present."
    fi
done

# ── step 4: switch EVE repo to version 1 ──────────────────────────────────────

log_info "=== Step 4: Switch EVE to $EVE_VERSION_1 ==="

pushd "$EVE_DIR" > /dev/null
git checkout "$EVE_VERSION_1"
popd > /dev/null

# ── step 5: generate SSH key and install into EVE conf ────────────────────────

log_info "=== Step 5: SSH key setup ==="

if [ ! -f "$SSH_KEY" ]; then
    log_info "Generating SSH key at $SSH_KEY ..."
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
else
    log_info "SSH key already exists."
fi

mkdir -p "$EVE_DIR/conf"
cp "${SSH_KEY}.pub" "$EVE_DIR/conf/authorized_keys"
log_info "Public key installed to $EVE_DIR/conf/authorized_keys"

# ── step 6: set up Adam controller ───────────────────────────────────────────

log_info "=== Step 6: Set up Adam controller ==="

if [ ! -d "$ADAM_DIR/.git" ]; then
    log_info "Cloning Adam repository to $ADAM_DIR ..."
    git clone --quiet "$ADAM_REPO_URL" "$ADAM_DIR"
else
    log_info "Adam repository already cloned."
fi

pushd "$ADAM_DIR" > /dev/null
git checkout "$ADAM_BRANCH"
popd > /dev/null

log_info "Building Adam (branch $ADAM_BRANCH) → $ADAM_BUILD_LOG"
pushd "$ADAM_DIR" > /dev/null
make > "$ADAM_BUILD_LOG" 2>&1
popd > /dev/null
log_info "Adam built."

log_info "Running bootstrap.sh → $ADAM_RUN_LOG"
pushd "$ADAM_DIR" > /dev/null
EVE_CONFIG="$EVE_DIR/conf" OVERWRITE_YES=true ./bootstrap.sh --yes > "$ADAM_RUN_LOG" 2>&1 &
ADAM_PID=$!
popd > /dev/null
log_info "Adam started (PID $ADAM_PID)"

log_info "Waiting for Adam to start..."
until grep -q "Starting adam" "$ADAM_RUN_LOG" 2>/dev/null; do
    sleep 1
done
log_info "Adam is up."

# ── step 7: build EVE version 1 ───────────────────────────────────────────────

log_info "=== Step 7: Build EVE $EVE_VERSION_1 ==="

if $SKIP_BUILD; then
    log_info "Skipping build (--skip-build)"
else
    BUILD_LOG="$WORK_DIR/eve_build.log"
    log_info "Build output → $BUILD_LOG"
    pushd "$EVE_DIR" > /dev/null
    make pkg/pillar live > "$BUILD_LOG" 2>&1
    popd > /dev/null
fi

# ── step 8: boot EVE and wait for onboarding ──────────────────────────────────

log_info "=== Step 8: Boot EVE and wait for onboarding ==="

EVE_RUN_LOG="$WORK_DIR/eve_run.log"
log_info "EVE run log → $EVE_RUN_LOG"
pushd "$EVE_DIR" > /dev/null
make run TPM=Y QEMU_EVE_SERIAL="$EVE_SERIAL" > "$EVE_RUN_LOG" 2>&1 &
QEMU_PID=$!
popd > /dev/null

log_info "QEMU started (PID $QEMU_PID)"

wait_for_ssh
wait_for_onboard

# ── step 9: reboot after onboarding ───────────────────────────────────────────

log_info "=== Step 9: Reboot after onboarding ==="

reboot_and_wait

# ── step 10: capture baseline TPM measurements ────────────────────────────────

log_info "=== Step 10: Capture baseline TPM measurements ==="

log_info "Fetching baseline TPM event log..."
ssh_cmd "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "$BASELINE_EVENTLOG"

log_info "Fetching baseline PCR values..."
ssh_cmd "eve exec vtpm tpm2 pcrread" > "$BASELINE_PCRS"

log_info "Saved: $BASELINE_EVENTLOG"
log_info "Saved: $BASELINE_PCRS"

# ── step 11: write new rootfs to other partition ───────────────────────────────

log_info "=== Step 11: Flash $EVE_VERSION_2 rootfs to other partition ==="

CURPART=$(ssh_cmd "eve exec pillar zboot curpart")
OTHERPART=$([ "$CURPART" = "IMGA" ] && echo "IMGB" || echo "IMGA")
log_info "Current partition: $CURPART  →  target partition: $OTHERPART"

# Find the block device for the other partition by its GPT label.
OTHER_PARTDEV=$(ssh_cmd "lsblk -rno NAME,PARTLABEL | awk -v p='$OTHERPART' '\$2==p {print \"/dev/\" \$1}'")
if [ -z "$OTHER_PARTDEV" ]; then
    log_error "Could not find block device for partition $OTHERPART"
    exit 1
fi
log_info "Other partition device: $OTHER_PARTDEV"

log_info "Uploading rootfs v2 to EVE (this may take a while)..."
scp_to_eve "$ROOTFS_V2" "/persist/rootfs-v2.img"

log_info "Writing rootfs v2 to $OTHER_PARTDEV ..."
ssh_cmd "dd if=/persist/rootfs-v2.img of=$OTHER_PARTDEV bs=4M && sync"

log_info "Setting $OTHERPART state to 'updating'..."
ssh_cmd "eve exec pillar zboot set_partstate $OTHERPART updating"

# ── step 12: reboot into updated partition ────────────────────────────────────

log_info "=== Step 12: Reboot into updated partition ==="

reboot_and_wait

# ── step 13: capture updated TPM measurements ─────────────────────────────────

log_info "=== Step 13: Capture updated TPM measurements ==="

log_info "Fetching updated TPM event log..."
ssh_cmd "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "$UPDATED_EVENTLOG"

log_info "Fetching updated PCR values..."
ssh_cmd "eve exec vtpm tpm2 pcrread" > "$UPDATED_PCRS"

log_info "Saved: $UPDATED_EVENTLOG"
log_info "Saved: $UPDATED_PCRS"

fi # end of steps 1-13 (skipped by --predict)

# ── step 14: predict PCR values ───────────────────────────────────────────────

log_info "=== Step 14: Predict and validate post-update PCR values ==="

# Extract PCR 14 (SHA-256) from the baseline — it must remain unchanged across
# the update just like the firmware PCRs.
BASELINE_PCR14=$(awk '
    /^[[:space:]]*sha256[[:space:]]*:/          { in_sha256=1; next }
    /^[[:space:]]*sha[0-9]/ && !/sha256/        { in_sha256=0 }
    in_sha256 && /^[[:space:]]*14[[:space:]]*:/ { val=$NF; sub(/^0[xX]/, "", val); print tolower(val); exit }
' "$BASELINE_PCRS")
if [ -z "$BASELINE_PCR14" ]; then
    log_error "Could not extract PCR 14 (sha256) from $BASELINE_PCRS"
    exit 1
fi
log_info "Baseline PCR 14 (sha256): $BASELINE_PCR14"

"$EVE_PREDICT" \
    -old     "$BASELINE_EVENTLOG" \
    -new     "$UPDATED_EVENTLOG" \
    -rootfs  "$ROOTFS_V2" \
    -out     "$PREDICTIONS_GOB" \
    -compare "$UPDATED_PCRS" \
    -algo    sha256 \
    "14:$BASELINE_PCR14"

log_info "=== Test complete ==="
