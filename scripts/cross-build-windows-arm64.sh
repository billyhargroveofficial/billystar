#!/usr/bin/env bash
# Native Windows 11 ARM64 no-TUN client.  The matching server may be Linux,
# but it must be built with the exact same explicit SHADOWPIPE_MAGIC.
set -Eeuo pipefail

cd "$(dirname "$0")/.."

: "${SHADOWPIPE_MAGIC:?set the shared client/server u32, for example 0x50334852}"
export SHADOWPIPE_MAGIC

target="aarch64-pc-windows-gnullvm"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/windows-arm64}"
artifact="${CARGO_TARGET_DIR}/${target}/release/shadowpipe-client.exe"

command -v cargo >/dev/null
command -v zig >/dev/null
command -v file >/dev/null
command -v sha256sum >/dev/null

cargo zigbuild --release --locked \
  -p shadowpipe-client \
  --no-default-features \
  --target "${target}"

file "${artifact}"
printf 'target=%s\n' "${target}"
printf 'shadowpipe_magic=%s\n' "${SHADOWPIPE_MAGIC}"
printf 'sha256=%s\n' "$(sha256sum "${artifact}" | awk '{print $1}')"
printf 'size_bytes=%s\n' "$(wc -c <"${artifact}" | tr -d '[:space:]')"
printf 'artifact=%s\n' "${artifact}"
