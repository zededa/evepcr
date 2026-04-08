#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# build-rootfs-hashes.sh — for every EVE 14.x and 16.x LTS release tag,
# download the rootfs image from GitHub releases, compute the PCR 13 hash
# with eve-rootfs-hash, and write the results to a JSON file.
#
# Output: out/rootfs-hashes.json
#   {
#     "16.0.0-lts": "abcd...",
#     "14.5.2-lts": "ef01...",
#     ...
#   }
#
# Requirements: curl, git, jq, go (to build eve-rootfs-hash)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

EVE_REPO_URL="https://github.com/lf-edge/eve.git"
EVE_RELEASES_URL="https://github.com/lf-edge/eve/releases/download"
ROOTFS_ASSET="amd64.kvm.generic.rootfs.img"

# Versions to include ALL tags for (not just LTS).
ALL_TAG_VERSIONS=("16")

# Versions to include LTS-only tags for.
LTS_ONLY_VERSIONS=("")

OUT_DIR="$REPO_ROOT/out"
OUT_FILE="$OUT_DIR/rootfs-hashes.json"
TOOL="$REPO_ROOT/cmd/eve-rootfs-hash/eve-rootfs-hash"

TEMP_DIR=""

# ── logging ───────────────────────────────────────────────────────────────────

log_info()  { echo "[INFO]  $*" >&2; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        log_info "Removing temp dir $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# ── helpers ───────────────────────────────────────────────────────────────────

require_tool() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required tool not found: $1"
        exit 1
    fi
}

fetch_tags() {
    local clone_dir="$TEMP_DIR/eve_clone"
    log_info "Cloning EVE repository..."
    git clone --quiet --branch master --single-branch --depth 1 "$EVE_REPO_URL" "$clone_dir"

    pushd "$clone_dir" > /dev/null
    log_info "Fetching tags..."
    git fetch --tags --quiet
    local all_tags
    all_tags=$(git tag -l)
    popd > /dev/null

    if [ -z "$all_tags" ]; then
        log_error "No tags found in the repository"
        return 1
    fi

    local collected=""

    for version in "${ALL_TAG_VERSIONS[@]}"; do
        local tags
        tags=$(echo "$all_tags" | grep "^${version}\." || true)
        if [ -n "$tags" ]; then
            log_info "Found $(echo "$tags" | wc -l) tag(s) for ${version}.x (all)"
            collected="$collected"$'\n'"$tags"
        else
            log_warn "No tags found for ${version}.x"
        fi
    done

    for version in "${LTS_ONLY_VERSIONS[@]}"; do
        local tags
        tags=$(echo "$all_tags" | grep "^${version}\." | grep -- "-lts$" || true)
        if [ -n "$tags" ]; then
            log_info "Found $(echo "$tags" | wc -l) LTS tag(s) for ${version}.x"
            collected="$collected"$'\n'"$tags"
        else
            log_warn "No LTS tags found for ${version}.x"
        fi
    done

    if [ -z "$collected" ]; then
        log_error "No tags collected"
        return 1
    fi

    # sort newest-first
    echo "$collected" | grep -v '^$' | sort -V -r
}

process_tag() {
    local tag="$1"
    local url="${EVE_RELEASES_URL}/${tag}/${ROOTFS_ASSET}"
    local img="$TEMP_DIR/${tag}-rootfs.img"

    log_info "  Downloading $ROOTFS_ASSET for $tag ..."
    if ! curl -fsSL -o "$img" "$url" 2>/dev/null; then
        log_warn "  Download failed for $tag (asset may not exist for this release), skipping"
        return 1
    fi

    log_info "  Computing PCR 13 hash..."
    local hash
    if ! hash=$("$TOOL" "$img" 2>/dev/null); then
        log_warn "  eve-rootfs-hash failed for $tag, skipping"
        rm -f "$img"
        return 1
    fi

    rm -f "$img"
    log_info "  $tag -> $hash"
    echo "$hash"
}

# ── main ──────────────────────────────────────────────────────────────────────

require_tool curl
require_tool git
require_tool jq

# Build the hash utility if not already built.
if [ ! -x "$TOOL" ]; then
    log_info "Building eve-rootfs-hash..."
    (cd "$REPO_ROOT/cmd/eve-rootfs-hash" && go build -o eve-rootfs-hash .)
fi

mkdir -p "$OUT_DIR"
TEMP_DIR=$(mktemp -d)

log_info "Fetching EVE tags..."
LTS_TAGS=$(fetch_tags)
if [ -z "$LTS_TAGS" ]; then
    log_error "No tags found, aborting"
    exit 1
fi

TAG_COUNT=$(echo "$LTS_TAGS" | wc -l)
log_info "Processing $TAG_COUNT LTS tag(s)..."

JSON="{}"

while IFS= read -r TAG; do
    [ -z "$TAG" ] && continue
    log_info "=== $TAG ==="

    HASH=$(process_tag "$TAG") || { log_warn "Skipping $TAG"; continue; }
    JSON=$(echo "$JSON" | jq --arg tag "$TAG" --arg hash "$HASH" '. + {($tag): $hash}')
done <<< "$LTS_TAGS"

ENTRY_COUNT=$(echo "$JSON" | jq 'length')
if [ "$ENTRY_COUNT" -eq 0 ]; then
    log_error "No hashes collected, output file not written"
    exit 1
fi

echo "$JSON" | jq '.' > "$OUT_FILE"
log_info "Written $OUT_FILE ($ENTRY_COUNT entries)"
