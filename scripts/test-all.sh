#!/usr/bin/env bash
# Run unit + integration tests locally.
set -euo pipefail
cd "$(dirname "$0")/.."

export SHADOWPIPE_MAGIC="${SHADOWPIPE_MAGIC:-0xcafebabe}"
echo "== shadowpipe test suite (magic=${SHADOWPIPE_MAGIC}) =="
./scripts/test-cli-flags.sh
./scripts/test-split-rules.sh
cargo test --all --release --features test-util -- --test-threads=1 2>&1
echo ""
echo "== test summary =="
cargo test --all --release -- --list 2>/dev/null | wc -l | xargs echo "registered tests:"
