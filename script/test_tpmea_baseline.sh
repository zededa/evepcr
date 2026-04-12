#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# test_tpmea_baseline.sh - end-to-end test for TPM EA policy across EVE OS updates.
#
# Like test_tpmea.sh but uses baseline-only PCR prediction: the policy bundle
# is generated from the v1 event log and the v2 rootfs image alone, without
# capturing a second event log from the running v2 system.
#
# Usage: ./test_tpmea_baseline.sh [--skip-build] [--clean] [--verbose]
#

set -euo pipefail


exec > >(tee "${BASH_SOURCE[0]%.sh}.log") 2>&1

# ── option parsing ─────────────────────────────────────────────────────────────
SKIP_BUILD=false
CLEAN=false
VERBOSE=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --clean)      CLEAN=true ;;
        --verbose)    VERBOSE=true ;;
        *) echo "[ERROR] Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# ── configuration ─────────────────────────────────────────────────────────────
EVE_VERSION_1="16.1.0"
EVE_VERSION_2="16.2.0"
# Full version string as it appears in the TPM event log (grub_cmd setparams / menuentry).
# EVE appends the hypervisor and architecture to the short version: <ver>-<hv>-<arch>.
EVE_VERSION_2_FULL="16.2.0-kvm-amd64"

EVE_SERIAL="shahshah"
SSH_PORT=2222

EVE_REPO_URL="https://github.com/lf-edge/eve.git"
EVE_RELEASES_URL="https://github.com/lf-edge/eve/releases/download"
ROOTFS_ASSET="amd64.kvm.generic.rootfs.img"

# PCR indexes to bind the policy to.
PCR_INDEXES="0 1 2 3 4 6 7 8 9 13 14"

# NV handles used on EVE's TPM.
NV_INDEX="0x1500016"
NV_COUNTER_INDEX="0x1500017"

# Working directory
WORK_DIR="$PWD/out/tpmea-bl"

# ── derived paths ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EVE_DIR="$WORK_DIR/eve"
ROOTFS_DIR="$WORK_DIR/rootfs"
MEASUREMENTS_DIR="$WORK_DIR/measurements"
KEY_DIR="$WORK_DIR/keys"
SWTPM_DIR="$WORK_DIR/swtpm"
SSH_KEY="$WORK_DIR/eve_ssh_key"

ROOTFS_V2="$ROOTFS_DIR/${EVE_VERSION_2}.img"

# Host-side tool binaries (built for the host OS)
EVE_PREDICT="$REPO_ROOT/cmd/predict/predict"
GEN_POLICY="$REPO_ROOT/cmd/gen-policy/gen-policy"
# Static alpine binary uploaded to EVE
VALIDATE_POLICY_BIN="$WORK_DIR/validate-policy"

BASELINE_EVENTLOG="$MEASUREMENTS_DIR/baseline_eventlog"
BASELINE_PCRS="$MEASUREMENTS_DIR/baseline_pcrs.yaml"
UPDATED_EVENTLOG="$MEASUREMENTS_DIR/updated_eventlog"
PREDICTIONS_GOB="$MEASUREMENTS_DIR/predictions.gob"

# JSON files transferred to EVE
POLICY_JSON="$WORK_DIR/policy.json"        # single policy for v1 PCRs
BUNDLE_JSON="$WORK_DIR/bundle.json"        # multi-policy bundle for post-update

POLICY_SIGNING_KEY="$KEY_DIR/policy_signing_key.pem"
POLICY_SIGNING_PUB="$KEY_DIR/policy_signing_key.pub.pem"

SWTPM_SRV_SOCK="$SWTPM_DIR/tpm.srv.sock"
SWTPM_CTRL_SOCK="$SWTPM_DIR/tpm.ctrl.sock"

ADAM_REPO_URL="https://github.com/shjala/adam.git"
ADAM_BRANCH="MinimalistAdam"
ADAM_DIR="$WORK_DIR/adam"
ADAM_BUILD_LOG="$WORK_DIR/adam_build.log"
ADAM_RUN_LOG="$WORK_DIR/adam_run.log"

QEMU_PID=""
ADAM_PID=""
SWTPM_PID=""
EVE_RUN_LOG=""

# ── helpers ───────────────────────────────────────────────────────────────────

log_info()  { echo "[INFO]  $*"; }
log_step()  { echo ""; echo "[INFO]  $*"; }
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
    stop_swtpm
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

# ── swtpm helpers ─────────────────────────────────────────────────────────────

start_swtpm() {
    mkdir -p "$SWTPM_DIR"
    rm -f "$SWTPM_SRV_SOCK" "$SWTPM_CTRL_SOCK"
    swtpm socket --tpm2 \
        --flags startup-clear \
        --server type=unixio,path="$SWTPM_SRV_SOCK" \
        --ctrl   type=unixio,path="$SWTPM_CTRL_SOCK" \
        --tpmstate dir="$SWTPM_DIR" \
        --log file="$SWTPM_DIR/swtpm.log" &
    SWTPM_PID=$!
    local i=0
    while [ ! -S "$SWTPM_SRV_SOCK" ] && [ $i -lt 20 ]; do
        sleep 0.5
        i=$((i + 1))
    done
    [ -S "$SWTPM_SRV_SOCK" ] || { log_error "swtpm did not create socket"; exit 1; }
    log_info "swtpm started (PID $SWTPM_PID)"
}

stop_swtpm() {
    if [ -n "$SWTPM_PID" ] && kill -0 "$SWTPM_PID" 2>/dev/null; then
        log_info "Stopping swtpm (PID $SWTPM_PID)..."
        kill "$SWTPM_PID" || true
        SWTPM_PID=""
    fi
}

# ── PCR helpers ───────────────────────────────────────────────────────────────

# get_pcr_sha256 <yaml-file> <pcr-index>
# Extracts a single SHA-256 PCR value from tpm2 pcrread YAML output.
get_pcr_sha256() {
    local file="$1" idx="$2"
    awk -v idx="$idx" '
        /^[[:space:]]*sha256[[:space:]]*:/          { in_sha256=1; next }
        /^[[:space:]]*sha[0-9]/ && !/sha256/        { in_sha256=0 }
        in_sha256 && /^[[:space:]]*[0-9]/ {
            split($0, a, ":"); key=a[1]+0;
            if (key == idx) {
                val=$NF; sub(/^0[xX]/, "", val); print tolower(val); exit
            }
        }
    ' "$file"
}

# build_pcr_args <yaml-file> <space-separated-indexes>
# Produces "idx:hex idx:hex ..." ready for gen-policy positional args.
build_pcr_args() {
    local pcr_file="$1"
    shift
    local args=""
    for idx in "$@"; do
        val=$(get_pcr_sha256 "$pcr_file" "$idx")
        if [ -z "$val" ]; then
            log_error "PCR $idx not found in $pcr_file"
            exit 1
        fi
        args="$args ${idx}:${val}"
    done
    echo "$args"
}

# pcr_indexes_csv <space-separated-indexes>
# Converts "4 14" -> "4,14" for -pcr-indexes flag.
pcr_indexes_csv() {
    echo "$*" | tr ' ' ','
}


# ── step 1: prerequisites ─────────────────────────────────────────────────────

log_step "=== Step 1: Prerequisites ==="

require_tool curl
require_tool git
require_tool go
require_tool python3
require_tool ssh
require_tool ssh-keygen
require_tool openssl
require_tool swtpm

if $CLEAN && [ -d "$WORK_DIR" ]; then
    log_info "Cleaning working directory $WORK_DIR ..."
    rm -rf "$WORK_DIR"
fi

mkdir -p "$WORK_DIR" "$ROOTFS_DIR" "$MEASUREMENTS_DIR" "$KEY_DIR" "$SWTPM_DIR"

# Build host-side tools.
for tool_name in predict; do
    log_info "Building $tool_name..."
    (cd "$REPO_ROOT/cmd/$tool_name" && go build -o "$tool_name" .)
done

log_info "Building gen-policy (host)..."
(cd "$REPO_ROOT/cmd/gen-policy" && go build -o gen-policy .)

VALIDATE_BUILD_LOG="$WORK_DIR/validate-policy_build.log"
log_info "Building validate-policy (static linux/amd64 for EVE) -> $VALIDATE_BUILD_LOG"
# CGO_ENABLED=0 produces a pure-Go binary with no libc dependency - runs on
# EVE's musl without any dynamic linker. GOOS/GOARCH cross-compiles from host.
(
    cd "$REPO_ROOT/cmd/validate-policy"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$VALIDATE_POLICY_BIN" .
) > "$VALIDATE_BUILD_LOG" 2>&1 || {
    log_error "validate-policy build failed - see $VALIDATE_BUILD_LOG"
    exit 1
}

# ── step 2: fetch EVE source ───────────────────────────────────────────────────

log_step "=== Step 2: Fetch EVE source ==="

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

# ── step 3: download rootfs images ────────────────────────────────────────────

log_step "=== Step 3: Download rootfs images ==="

if [ ! -f "$ROOTFS_V2" ]; then
    url="${EVE_RELEASES_URL}/${EVE_VERSION_2}/${ROOTFS_ASSET}"
    log_info "Downloading rootfs for $EVE_VERSION_2 ..."
    curl -fL --progress-bar -o "$ROOTFS_V2" "$url"
else
    log_info "Rootfs for $EVE_VERSION_2 already present."
fi

# ── step 4: switch EVE repo to version 1 ──────────────────────────────────────

log_step "=== Step 4: Switch EVE to $EVE_VERSION_1 ==="

pushd "$EVE_DIR" > /dev/null
git checkout "$EVE_VERSION_1"
popd > /dev/null

# ── step 5: generate SSH key and install into EVE conf ────────────────────────

log_step "=== Step 5: SSH key setup ==="

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

log_step "=== Step 6: Set up Adam controller ==="

if [ ! -d "$ADAM_DIR/.git" ]; then
    log_info "Cloning Adam repository to $ADAM_DIR ..."
    git clone --quiet "$ADAM_REPO_URL" "$ADAM_DIR"
else
    log_info "Adam repository already cloned."
fi

pushd "$ADAM_DIR" > /dev/null
git checkout "$ADAM_BRANCH"
popd > /dev/null

ADAM_BIN="$ADAM_DIR/bin/adam"
ADAM_CERTS="$ADAM_DIR/run/certs/server-tls.crt"

if [ -f "$ADAM_BIN" ] && [ -f "$ADAM_CERTS" ]; then
    log_info "Adam binary and certs already exist - skipping build"
    log_info "Running bootstrap.sh --run -> $ADAM_RUN_LOG"
    pushd "$ADAM_DIR" > /dev/null
    EVE_CONFIG="$EVE_DIR/conf" EVE_SERIAL="$EVE_SERIAL" ./bootstrap.sh --run > "$ADAM_RUN_LOG" 2>&1 &
    ADAM_PID=$!
    popd > /dev/null
else
    log_info "Building Adam (branch $ADAM_BRANCH) -> $ADAM_BUILD_LOG"
    pushd "$ADAM_DIR" > /dev/null
    make > "$ADAM_BUILD_LOG" 2>&1
    popd > /dev/null
    log_info "Adam built."

    log_info "Running bootstrap.sh --yes -> $ADAM_RUN_LOG"
    pushd "$ADAM_DIR" > /dev/null
    EVE_CONFIG="$EVE_DIR/conf" EVE_SERIAL="$EVE_SERIAL" OVERWRITE_YES=true ./bootstrap.sh --yes > "$ADAM_RUN_LOG" 2>&1 &
    ADAM_PID=$!
    popd > /dev/null
fi
log_info "Adam started (PID $ADAM_PID)"

log_info "Waiting for Adam to start..."
until grep -q "Starting adam" "$ADAM_RUN_LOG" 2>/dev/null; do
    sleep 1
done
log_info "Adam is up."

# ── step 7: build EVE version 1 ───────────────────────────────────────────────

log_step "=== Step 7: Build EVE $EVE_VERSION_1 ==="

EVE_DIST_DIR="$EVE_DIR/dist/amd64/current"
if [ -d "$EVE_DIST_DIR" ] && [ -n "$(ls -A "$EVE_DIST_DIR" 2>/dev/null)" ]; then
    log_info "EVE $EVE_VERSION_1 already built ($EVE_DIST_DIR) - skipping build"
elif $SKIP_BUILD; then
    log_info "Skipping build (--skip-build)"
else
    BUILD_LOG="$WORK_DIR/eve_build.log"
    log_info "Build output -> $BUILD_LOG"
    pushd "$EVE_DIR" > /dev/null
    make pkg/pillar live > "$BUILD_LOG" 2>&1
    popd > /dev/null
fi

# ── step 8: boot EVE and wait for onboarding ──────────────────────────────────

log_step "=== Step 8: Boot EVE and wait for onboarding ==="

EVE_RUN_LOG="$WORK_DIR/eve_run.log"
log_info "EVE run log -> $EVE_RUN_LOG"
pushd "$EVE_DIR" > /dev/null
make run TPM=Y QEMU_EVE_SERIAL="$EVE_SERIAL" > "$EVE_RUN_LOG" 2>&1 &
QEMU_PID=$!
popd > /dev/null
log_info "QEMU started (PID $QEMU_PID)"

wait_for_ssh
wait_for_onboard

# ── step 8a: initialize other partition if empty ──────────────────────────────

log_step "=== Step 8a: Initialize other partition if empty ==="

_CURPART=$(ssh_cmd "eve exec pillar zboot curpart")
_OTHERPART=$([ "$_CURPART" = "IMGA" ] && echo "IMGB" || echo "IMGA")
_CURPART_DEV=$(ssh_cmd "lsblk -rno NAME,PARTLABEL | awk -v p='$_CURPART' '\$2==p {print \"/dev/\" \$1}'")
_OTHER_PARTDEV=$(ssh_cmd "lsblk -rno NAME,PARTLABEL | awk -v p='$_OTHERPART' '\$2==p {print \"/dev/\" \$1}'")
log_info "Current: $_CURPART ($_CURPART_DEV)  other: $_OTHERPART ($_OTHER_PARTDEV)"

if [ -z "$_OTHER_PARTDEV" ]; then
    log_info "$_OTHERPART device not found in GPT - skipping"
else
    # squashfs magic 0x73717368 stored little-endian on disk = bytes 68 73 71 73
    _MAGIC=$(ssh_cmd "dd if=$_OTHER_PARTDEV bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'" 2>/dev/null || echo "")
    if [ "$_MAGIC" = "68737173" ]; then
        log_info "$_OTHERPART already has a valid squashfs image - skipping"
    else
        log_info "$_OTHERPART has no valid squashfs (magic=$_MAGIC) - copying $_CURPART image ..."
        ssh_cmd "dd if=$_CURPART_DEV of=$_OTHER_PARTDEV bs=4M && sync"
        ssh_cmd "eve exec pillar zboot set_partstate $_OTHERPART unused" 2>/dev/null || true
        log_info "$_OTHERPART initialized and set to unused."
    fi
fi
unset _CURPART _OTHERPART _CURPART_DEV _OTHER_PARTDEV _MAGIC

# ── step 9: reboot after onboarding ───────────────────────────────────────────

log_step "=== Step 9: Reboot after onboarding ==="

reboot_and_wait

# ── step 10: capture baseline TPM measurements ────────────────────────────────

log_step "=== Step 10: Capture baseline TPM measurements ==="

log_info "Fetching baseline TPM event log..."
ssh_cmd "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "$BASELINE_EVENTLOG"

log_info "Fetching baseline PCR values..."
ssh_cmd "eve exec vtpm tpm2 pcrread" > "$BASELINE_PCRS"

log_info "Saved: $BASELINE_EVENTLOG"
log_info "Saved: $BASELINE_PCRS"

# ── step 10a: generate signing key ────────────────────────────────────────────

log_step "=== Step 10a: Generate signing key ==="

if [ ! -f "$POLICY_SIGNING_KEY" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$POLICY_SIGNING_KEY" 2>/dev/null
    openssl pkey -in "$POLICY_SIGNING_KEY" -pubout -out "$POLICY_SIGNING_PUB" 2>/dev/null
    log_info "RSA-2048 signing key generated at $POLICY_SIGNING_KEY"
else
    log_info "Signing key already exists."
fi

# ── step 10b: generate initial policy using baseline PCR values ───────────────

log_step "=== Step 10b: Generate initial policy (single) ==="

PCR_ARGS=$(build_pcr_args "$BASELINE_PCRS" $PCR_INDEXES)
log_info "PCR args:"
for _pcr_arg in $PCR_ARGS; do
    printf "             %s\n" "$_pcr_arg"
done
unset _pcr_arg

start_swtpm
SWTPM_PATH="$SWTPM_SRV_SOCK" "$GEN_POLICY" \
    -key           "$POLICY_SIGNING_KEY" \
    -counter-index "$NV_COUNTER_INDEX" \
    -counter-val   2 \
    -out           "$POLICY_JSON" \
    $PCR_ARGS
stop_swtpm

log_info "Policy written to $POLICY_JSON"
log_info "Uploading policy and public key to EVE..."
scp_to_eve "$POLICY_JSON"   "/persist/policy.json"
scp_to_eve "$POLICY_SIGNING_PUB"   "/persist/policy_signing_key.pub.pem"

# ── step 10c: upload validate-policy; seal a secret on EVE ────────────────────

log_step "=== Step 10c: Seal secret on EVE ==="

log_info "Uploading validate-policy binary..."
scp_to_eve "$VALIDATE_POLICY_BIN" "/persist/validate-policy"
ssh_cmd "chmod +x /persist/validate-policy"

# Clear any NV handles left over from a previous run so validate-policy
# always enters the seal path here.
log_info "Clearing stale NV handles (if any)..."
ssh_cmd "eve exec vtpm tpm2 nvundefine -C o $NV_INDEX 2>/dev/null" || true
ssh_cmd "eve exec vtpm tpm2 nvundefine -C o $NV_COUNTER_INDEX 2>/dev/null" || true

log_info "Running validate-policy (seal path)..."
ssh_cmd "/persist/validate-policy \
    -policy        /persist/policy.json \
    -pub           /persist/policy_signing_key.pub.pem \
    -nv-index      $NV_INDEX \
    -counter-index $NV_COUNTER_INDEX \
    $PCR_INDEXES"
log_info "Secret sealed - NV index $NV_INDEX."

# ── step 10d: predict post-update PCR values from baseline ────────────────────

log_step "=== Step 10d: Predict post-update PCR values (baseline-only) ==="

# PCR 14 is set in user-mode and is stable across updates - carry it forward.
BASELINE_PCR14=$(get_pcr_sha256 "$BASELINE_PCRS" 14)
if [ -z "$BASELINE_PCR14" ]; then
    log_error "Could not extract PCR 14 from $BASELINE_PCRS"
    exit 1
fi
log_info "Baseline PCR 14 (sha256): $BASELINE_PCR14"

# No -new flag: uses baseline-only prediction mode.  The v2 rootfs image
# patches PCR 13; PCR 14 is passed as a known override.
PREDICT_VERBOSE_FLAG=""
$VERBOSE && PREDICT_VERBOSE_FLAG="-verbose"
"$EVE_PREDICT" \
    -old     "$BASELINE_EVENTLOG" \
    -rootfs  "$ROOTFS_V2" \
    -version "$EVE_VERSION_2_FULL" \
    -out           "$PREDICTIONS_GOB" \
    -dump-eventlog "$MEASUREMENTS_DIR/predicted_evlog" \
    $PREDICT_VERBOSE_FLAG \
    "14:$BASELINE_PCR14"

log_info "Predictions written to $PREDICTIONS_GOB"

# ── step 10e: generate policy bundle from predictions ─────────────────────────

log_step "=== Step 10e: Generate policy bundle ==="

start_swtpm
SWTPM_PATH="$SWTPM_SRV_SOCK" "$GEN_POLICY" \
    -key           "$POLICY_SIGNING_KEY" \
    -counter-index "$NV_COUNTER_INDEX" \
    -counter-val   3 \
    -predict-gob   "$PREDICTIONS_GOB" \
    -pcr-indexes   "$(pcr_indexes_csv $PCR_INDEXES)" \
    -out           "$BUNDLE_JSON"
stop_swtpm

log_info "Policy bundle written to $BUNDLE_JSON"

# ── step 11: write new rootfs to other partition ───────────────────────────────

log_step "=== Step 11: Flash $EVE_VERSION_2 rootfs to other partition ==="

CURPART=$(ssh_cmd "eve exec pillar zboot curpart")
OTHERPART=$([ "$CURPART" = "IMGA" ] && echo "IMGB" || echo "IMGA")
log_info "Current partition: $CURPART  ->  target partition: $OTHERPART"

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

# ── step 11a: embed bundle in v2 partition (before reboot) ────────────────────

log_step "=== Step 11a: Embed bundle in v2 partition ==="

# The bundle is appended beyond the squashfs measured region so the TPM
# measurement of OTHERPART (v2) is not affected.  The payload format is
# an 8-byte little-endian JSON size followed by the JSON bytes.
BUNDLE_PAYLOAD="$WORK_DIR/bundle_payload"
BUNDLE_SIZE=$(wc -c < "$BUNDLE_JSON" | awk '{print $1}')
python3 -c "import struct,sys; sys.stdout.buffer.write(struct.pack('<Q', $BUNDLE_SIZE))" > "$BUNDLE_PAYLOAD"
cat "$BUNDLE_JSON" >> "$BUNDLE_PAYLOAD"
log_info "Payload: 8-byte header + ${BUNDLE_SIZE} bytes JSON"

scp_to_eve "$BUNDLE_PAYLOAD" "/persist/bundle_payload"
ssh_cmd "
    PARTDEV=\$(lsblk -rno NAME,PARTLABEL | awk -v p='$OTHERPART' '\$2==p {print \"/dev/\"\$1}')
    SQFS_SIZE=\$(dd if=\"\$PARTDEV\" bs=1 skip=40 count=4 2>/dev/null | od -An -tu4 | awk '{print \$1}')
    dd if=/persist/bundle_payload of=\"\$PARTDEV\" bs=1 seek=\"\$SQFS_SIZE\" conv=notrunc 2>/dev/null
    sync
    rm -f /persist/bundle_payload
    echo \"bundle embedded at offset \$SQFS_SIZE on \$PARTDEV\"
"
log_info "Bundle embedded in v2 partition."

# ── step 12: reboot into updated partition ────────────────────────────────────

log_step "=== Step 12: Reboot into updated partition ==="

reboot_and_wait

# ── step 12a: capture updated TPM event log (for debugging) ──────────────────

log_step "=== Step 12a: Capture updated TPM event log ==="

ssh_cmd "cat /sys/kernel/security/tpm0/binary_bios_measurements" > "$UPDATED_EVENTLOG"
log_info "Saved: $UPDATED_EVENTLOG"

# ── step 13: verify old policy is rejected after update ───────────────────────

log_step "=== Step 13: Verify old (v1) policy is rejected ==="

VALIDATE_VERBOSE_FLAG=""
$VERBOSE && VALIDATE_VERBOSE_FLAG="-verbose"
if ssh_cmd "/persist/validate-policy \
    -policy        /persist/policy.json \
    -pub           /persist/policy_signing_key.pub.pem \
    -nv-index      $NV_INDEX \
    -counter-index $NV_COUNTER_INDEX \
    $VALIDATE_VERBOSE_FLAG \
    $PCR_INDEXES" 2>&1; then
    log_error "Old policy unsealed successfully - expected failure after update"
    exit 1
fi
log_info "Old policy correctly rejected by EVE v2 PCRs."

# ── step 14: verify policy bundle can unseal ──────────────────────────────────

log_step "=== Step 14: Verify policy bundle unseals secret ==="

ssh_cmd "/persist/validate-policy \
    -local \
    -pub           /persist/policy_signing_key.pub.pem \
    -nv-index      $NV_INDEX \
    -counter-index $NV_COUNTER_INDEX \
    $VALIDATE_VERBOSE_FLAG \
    $PCR_INDEXES"
log_info "Policy bundle correctly unsealed secret on EVE v2."

log_info "=== Test complete ==="
