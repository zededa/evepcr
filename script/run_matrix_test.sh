#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# run_matrix_test.sh - Run test_tpmea.sh across a matrix of EVE LTS version pairs.
#
# This script:
#   1. Discovers EVE LTS releases with downloadable rootfs images
#   2. Builds a test matrix covering far-apart and close version updates
#   3. Runs test_tpmea.sh --clean for each matrix entry
#   4. Saves per-run logs named with version info
#
# The matrix is cached to a file so subsequent runs can skip discovery.
#
# Usage: ./run_matrix_test.sh [--refresh-matrix] [--dry-run]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SCRIPT="$SCRIPT_DIR/test_tpmea.sh"
MATRIX_FILE="$SCRIPT_DIR/test_matrix.txt"
LOG_DIR="$SCRIPT_DIR/../out/matrix-logs"

EVE_RELEASES_URL="https://github.com/lf-edge/eve/releases/download"
GITHUB_API_URL="https://api.github.com/repos/lf-edge/eve/releases"

# ── option parsing ─────────────────────────────────────────────────────────────

REFRESH_MATRIX=false
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --refresh-matrix) REFRESH_MATRIX=true ;;
        --dry-run)        DRY_RUN=true ;;
        *) echo "[ERROR] Unknown option: $arg" >&2; exit 1 ;;
    esac
done

# ── helpers ────────────────────────────────────────────────────────────────────

log_info()  { echo "[MATRIX]  $*"; }
log_error() { echo "[MATRIX]  ERROR: $*" >&2; }

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required tool '$1' not found."
        exit 1
    fi
}

# Probes GitHub to find which rootfs asset name a version uses.
# Prints the asset filename on success, returns 1 if neither is found.
detect_rootfs_asset() {
    local version="$1"
    local asset code
    for asset in "amd64.kvm.generic.rootfs.img" "amd64.rootfs.img"; do
        code=$(curl -sL -o /dev/null -w '%{http_code}' --head \
               "${EVE_RELEASES_URL}/${version}/${asset}")
        if [ "$code" = "200" ] || [ "$code" = "302" ]; then
            echo "$asset"
            return 0
        fi
    done
    return 1
}

# ── step 1: discover LTS releases with downloadable images ────────────────────

discover_lts_versions() {
    log_info "Querying GitHub for EVE LTS releases..." >&2

    local -a versions=()
    local page=1

    while true; do
        local response
        response=$(curl -sL "${GITHUB_API_URL}?per_page=100&page=${page}")
        local tags
        tags=$(echo "$response" | jq -r '.[].tag_name // empty')
        [ -z "$tags" ] && break

        while IFS= read -r tag; do
            [[ "$tag" != *-lts ]] && continue
            [[ "$tag" == 8.* ]] && continue
            versions+=("$tag")
        done <<< "$tags"

        page=$((page + 1))
        [ "$page" -gt 5 ] && break
    done

    printf '%s\n' "${versions[@]}" | sort -V
}

check_rootfs_available() {
    local version="$1"
    detect_rootfs_asset "$version" > /dev/null
}

# ── step 2: build the test matrix ─────────────────────────────────────────────

# Appends a pair to the matrix array if it is not already present.
add_pair() {
    local -n _matrix=$1
    local pair="$2 $3"
    for existing in "${_matrix[@]+"${_matrix[@]}"}"; do
        [ "$existing" = "$pair" ] && return
    done
    _matrix+=("$pair")
}

build_matrix() {
    local -a versions=("$@")
    local n=${#versions[@]}

    if [ "$n" -lt 2 ]; then
        log_error "Need at least 2 versions to build matrix, found $n"
        exit 1
    fi

    log_info "Building test matrix from $n available versions..." >&2

    local -a matrix=()
    local last_idx=$((n - 1))

    # ── far-apart pairs (span multiple major versions) ─────────────────────
    add_pair matrix "${versions[0]}"            "${versions[$last_idx]}"
    [ "$n" -gt 2 ] && \
    add_pair matrix "${versions[1]}"            "${versions[$last_idx]}"
    [ "$n" -gt 3 ] && \
    add_pair matrix "${versions[0]}"            "${versions[$((last_idx - 1))]}"

    # ── medium-gap pairs (roughly half the range apart) ────────────────────
    local mid=$((n / 2))
    add_pair matrix "${versions[0]}"            "${versions[$mid]}"
    add_pair matrix "${versions[$mid]}"         "${versions[$last_idx]}"

    # quarter-point gaps
    local q1=$((n / 4))
    local q3=$((3 * n / 4))
    [ "$q1" -ne "$mid" ] && \
    add_pair matrix "${versions[$q1]}"          "${versions[$q3]}"

    # ── cross-major-version pairs (adjacent major boundaries) ──────────────
    local prev_major="" prev_ver=""
    for v in "${versions[@]}"; do
        local maj
        maj=$(echo "$v" | cut -d. -f1)
        if [ -n "$prev_major" ] && [ "$maj" != "$prev_major" ]; then
            add_pair matrix "$prev_ver" "$v"
        fi
        prev_major="$maj"
        prev_ver="$v"
    done

    # ── close pairs (consecutive versions) from different parts ────────────
    for i in 0 $q1 $mid $q3; do
        local j=$((i + 1))
        [ "$j" -lt "$n" ] && add_pair matrix "${versions[$i]}" "${versions[$j]}"
    done

    # ── pad to at least 10 if needed ───────────────────────────────────────
    local idx=0
    while [ "${#matrix[@]}" -lt 10 ] && [ "$idx" -lt "$last_idx" ]; do
        add_pair matrix "${versions[$idx]}" "${versions[$((idx + 1))]}"
        idx=$((idx + 1))
    done

    printf '%s\n' "${matrix[@]}"
}

# ── main ──────────────────────────────────────────────────────────────────────

require_tool curl
require_tool jq

if [ ! -f "$TEST_SCRIPT" ]; then
    log_error "test_tpmea.sh not found at $TEST_SCRIPT"
    exit 1
fi

mkdir -p "$LOG_DIR"

# Build or load the matrix.
if [ -f "$MATRIX_FILE" ] && ! $REFRESH_MATRIX; then
    log_info "Using cached matrix: $MATRIX_FILE"
else
    log_info "Discovering available EVE LTS versions..."

    mapfile -t all_lts < <(discover_lts_versions)
    log_info "Found ${#all_lts[@]} LTS releases (excluding 8.x)"

    available=()
    for v in "${all_lts[@]}"; do
        if check_rootfs_available "$v"; then
            available+=("$v")
            log_info "  ✓ $v"
        else
            log_info "  ✗ $v (no rootfs)"
        fi
    done

    log_info "${#available[@]} versions have downloadable rootfs images"

    build_matrix "${available[@]}" > "$MATRIX_FILE"
    log_info "Matrix written to $MATRIX_FILE"
fi

# Display the matrix.
log_info "──────────────────────────────────────"
log_info "Test matrix:"
n=0
while IFS=' ' read -r v1 v2; do
    [ -z "$v1" ] || [ -z "$v2" ] && continue
    n=$((n + 1))
    printf "[MATRIX]  %2d. %s → %s\n" "$n" "$v1" "$v2"
done < "$MATRIX_FILE"
log_info "Total test pairs: $n"
log_info "──────────────────────────────────────"

if $DRY_RUN; then
    log_info "Dry run - not executing tests."
    exit 0
fi

# Run test_tpmea.sh for each matrix entry.
passed=0
failed=0
pair_idx=0

while IFS=' ' read -r v1 v2; do
    [ -z "$v1" ] || [ -z "$v2" ] && continue
    pair_idx=$((pair_idx + 1))

    log_info "════════════════════════════════════════════════════════"
    log_info "[$pair_idx/$n] Running: $v1 → $v2"
    log_info "════════════════════════════════════════════════════════"

    v2_asset=$(detect_rootfs_asset "$v2" || true)
    if [ -z "$v2_asset" ]; then
        log_info "SKIPPED: $v1 → $v2 (no rootfs asset for $v2)"
        continue
    fi
    log_file="$LOG_DIR/test_tpmea_${v1}_to_${v2}.log"

    if EVE_VERSION_1="$v1" \
       EVE_VERSION_2="$v2" \
       ROOTFS_ASSET="$v2_asset" \
       TEST_LOG="$log_file" \
       bash "$TEST_SCRIPT" --clean </dev/null; then
        log_info "PASSED: $v1 → $v2"
        passed=$((passed + 1))
    else
        rc=$?
        log_info "FAILED: $v1 → $v2 (exit $rc)"
        failed=$((failed + 1))
    fi

    log_info "Log saved: $log_file"

done < "$MATRIX_FILE"

# Summary.
log_info "════════════════════════════════════════════════════════"
log_info "Matrix test complete"
log_info "  Passed: $passed"
log_info "  Failed: $failed"
log_info "  Total:  $n"
log_info "  Logs:   $LOG_DIR/"
log_info "════════════════════════════════════════════════════════"

[ "$failed" -eq 0 ]
