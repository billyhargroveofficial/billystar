#!/usr/bin/env bash
# Static musl cross-build for Linux x86_64 (Arch brother, generic servers).
# No tls-chrome/BoringSSL — REALITY / h2 / raw carriers only. Run on Mac only.
set -euo pipefail
cd "$(dirname "$0")/.."

export SHADOWPIPE_MAGIC="${SHADOWPIPE_MAGIC:-0xcafebabe}"
export PATH="/opt/homebrew/opt/musl-cross/bin:${PATH:-}"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-x86_64-linux-musl-gcc}"

FEATURES="${SP_FEATURES:-}"

echo "== musl static build (magic=${SHADOWPIPE_MAGIC}, no tls-chrome) =="
if [ -n "$FEATURES" ]; then
  cargo build --release --locked \
    --target x86_64-unknown-linux-musl \
    -p shadowpipe-client -p shadowpipe-server \
    --no-default-features \
    --features "$FEATURES"
else
  cargo build --release --locked \
    --target x86_64-unknown-linux-musl \
    -p shadowpipe-client -p shadowpipe-server \
    --no-default-features
fi

BIN="target/x86_64-unknown-linux-musl/release"
file "$BIN/shadowpipe-client" "$BIN/shadowpipe-server"
sha256sum "$BIN/shadowpipe-client" "$BIN/shadowpipe-server"
grep BUILD_MAGIC target/x86_64-unknown-linux-musl/release/build/shadowpipe-core-*/out/magic.rs

echo ""
echo "Binaries:"
echo "  $BIN/shadowpipe-client"
echo "  $BIN/shadowpipe-server"
echo ""
echo "Copy to brother (REALITY example):"
echo "  scp $BIN/shadowpipe-client brother:/usr/local/bin/"
echo "  SHADOWPIPE_MAGIC=0xcafebabe ./scripts/cross-build-musl.sh  # rebuild with prod magic"
