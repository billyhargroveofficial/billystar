#!/usr/bin/env bash
# Smoke: clap accepts documented kebab-case flags (review H10).
set -euo pipefail
cd "$(dirname "$0")/.."
export SHADOWPIPE_MAGIC="${SHADOWPIPE_MAGIC:-0xcafebabe}"

cargo build --release -p shadowpipe-server -p shadowpipe-client >/dev/null
cargo build --release -p shadowpipe-reality --bin sp-reality-server >/dev/null

BIN="target/release"
for flag in --egress-iface --reality --reality-key --gen-reality-key --reality-short-id --reality-short-id-file --reality-replay-store --cover --advertise --no-cover-profile --print-uri --client-allowlist --development-user-allowlist --allow-insecure-lab-carriers --enroll-client --revoke-client --validate-client-allowlist --forward-idle-timeout-secs; do
  if ! "$BIN/shadowpipe-server" --help 2>&1 | grep -F -e "$flag" >/dev/null; then
    echo "FAIL: shadowpipe-server --help missing $flag" >&2
    exit 1
  fi
done

# A normal daemon invocation must fail before identities, bind or TUN. Linux
# reaches the production carrier gate; non-Linux must stop even earlier at the
# production-server host boundary.
UNGATED_SERVER="$($BIN/shadowpipe-server 2>&1 || true)"
if [[ "$(uname -s)" == Linux ]]; then
  case "$UNGATED_SERVER" in
    *"production daemon requires --reality"*"distinguishable ShadowPipe bootstrap/challenge"*) : ;;
    *) echo "FAIL: ungated server did not fail at the production carrier preflight: $UNGATED_SERVER" >&2; exit 1 ;;
  esac
else
  case "$UNGATED_SERVER" in
    *"production shadowpipe-server is supported only on Linux"*) : ;;
    *) echo "FAIL: non-Linux server did not fail at the host boundary: $UNGATED_SERVER" >&2; exit 1 ;;
  esac
fi

# The escape hatch is deliberately coupled to explicit user-owned no-TUN lab
# mode by clap, so a lone opt-in cannot weaken production startup.
LAB_WITHOUT_DEV="$($BIN/shadowpipe-server --allow-insecure-lab-carriers 2>&1 || true)"
case "$LAB_WITHOUT_DEV" in
  *"--development-user-allowlist"*) : ;;
  *) echo "FAIL: lab carrier gate did not require development allowlist mode: $LAB_WITHOUT_DEV" >&2; exit 1 ;;
esac

if [[ "$(uname -s)" == Linux ]]; then
  DEV_REALITY_WITHOUT_REPLAY="$("$BIN/shadowpipe-server" \
    --reality --development-user-allowlist \
    --reality-short-id 0011223344556677 2>&1 || true)"
  case "$DEV_REALITY_WITHOUT_REPLAY" in
    *"development REALITY requires explicit --reality-replay-store"*) : ;;
    *) echo "FAIL: development REALITY silently accepted process-local replay state: $DEV_REALITY_WITHOUT_REPLAY" >&2; exit 1 ;;
  esac
else
  NON_LINUX_REALITY="$("$BIN/shadowpipe-server" \
    --development-user-allowlist --allow-insecure-lab-carriers \
    --reality --reality-replay-store ./private-replay.bin 2>&1 || true)"
  case "$NON_LINUX_REALITY" in
    *"--allow-insecure-lab-carriers"*"cannot be used with '--reality'"*) : ;;
    *"non-Linux shadowpipe-server lab mode forbids REALITY"*) : ;;
    *) echo "FAIL: non-Linux lab server accepted a REALITY path: $NON_LINUX_REALITY" >&2; exit 1 ;;
  esac
fi

# The standalone REALITY echo binary is an explicitly acknowledged,
# loopback-only protocol diagnostic. It must never become an accidental public
# daemon or accept REALITY's empty/open selector ACL.
REALITY_DEMO="$BIN/sp-reality-server"
DEMO_NO_ACK="$("$REALITY_DEMO" 2>&1 || true)"
case "$DEMO_NO_ACK" in
  *"--insecure-lab-echo"*) : ;;
  *) echo "FAIL: standalone REALITY demo lacks the explicit lab gate: $DEMO_NO_ACK" >&2; exit 1 ;;
esac
DEMO_PUBLIC="$("$REALITY_DEMO" --insecure-lab-echo 0.0.0.0:9 "$(printf '11%.0s' {1..32})" cover.invalid:443 0011223344556677 2>&1 || true)"
case "$DEMO_PUBLIC" in
  *"loopback-only"*) : ;;
  *) echo "FAIL: standalone REALITY demo accepted a non-loopback listener: $DEMO_PUBLIC" >&2; exit 1 ;;
esac
DEMO_EMPTY_ACL="$("$REALITY_DEMO" --insecure-lab-echo 127.0.0.1:9 "$(printf '11%.0s' {1..32})" cover.invalid:443 ./private-replay.bin 2>&1 || true)"
case "$DEMO_EMPTY_ACL" in
  *"1..=16 entries"*) : ;;
  *) echo "FAIL: standalone REALITY demo accepted an empty selector ACL: $DEMO_EMPTY_ACL" >&2; exit 1 ;;
esac
for flag in --auto-route --ipv6-mode --guard-bytes --profile-seed --server-fp --client-credential --development-user-credential --generate-client-credential --write-client-enrollment --reality --reality-pubkey --reality-short-id --uri --uri-file --kill-switch --dns --split --split-rules-dir --split-rules-list --split-direct-rules-list --split-dns --split-dns-upstream --split-dns-direct-upstream --split-dns-guard --split-leak-guard --split-preload-list --restore-lockdown --release-lockdown; do
  if ! "$BIN/shadowpipe-client" --help 2>&1 | grep -F -e "$flag" >/dev/null; then
    echo "FAIL: shadowpipe-client --help missing $flag" >&2
    exit 1
  fi
done
for mode in outer-only tunnel; do
  IPV6_UNAVAILABLE="$("$BIN/shadowpipe-client" --ipv6-mode "$mode" --server-fp malformed 2>&1 || true)"
  case "$IPV6_UNAVAILABLE" in
    *"--ipv6-mode $mode is not implemented"*) : ;;
    *) echo "FAIL: unsupported IPv6 mode did not fail before other preflight: $IPV6_UNAVAILABLE" >&2; exit 1 ;;
  esac
done
# Missing authentication must fail before a socket or privileged TUN open. The
# tunnel invocation intentionally runs without sudo: a TUN error here would mean
# the security preflight happened too late.
MISSING_PIN="$("$BIN/shadowpipe-client" --server 203.0.113.1:9 --tunnel 2>&1 || true)"
case "$MISSING_PIN" in
  *"missing required --server-fp"*) : ;;
  *) echo "FAIL: missing pin did not fail before TUN/network I/O: $MISSING_PIN" >&2; exit 1 ;;
esac

# Every endpoint in a REALITY rotation pool must carry its own ML-KEM pin.
PK="$(printf '11%.0s' {1..32})"
FP="$(printf '22%.0s' {1..32})"
MIXED_POOL="shadowpipe://${PK}@127.0.0.1:443?sni=a.test&sid=0123456789abcdef&fp=${FP},shadowpipe://${PK}@127.0.0.1:444?sni=b.test&sid=fedcba9876543210"
MIXED_RESULT="$("$BIN/shadowpipe-client" --uri "$MIXED_POOL" --tunnel 2>&1 || true)"
case "$MIXED_RESULT" in
  *"requires fp="*) : ;;
  *) echo "FAIL: mixed pinned/unpinned URI pool was accepted: $MIXED_RESULT" >&2; exit 1 ;;
esac

# Private URI-file parsing is a hard preflight: descriptor safety and complete
# URI syntax are checked before credential access or network/host state. These
# checks run in explicit no-TUN user-owned development mode so no root or live
# networking is involved.
URI_TEST_DIR="$(mktemp -d ".shadowpipe-uri-cli.XXXXXX")"
chmod 700 "$URI_TEST_DIR"
trap 'rm -rf -- "$URI_TEST_DIR"' EXIT
VALID_URI="shadowpipe://${PK}@127.0.0.1:9?sni=cover.test&sid=0123456789abcdef&fp=${FP}"
umask 077
printf '%s\n' "$VALID_URI" >"$URI_TEST_DIR/valid.uri"
URI_MISSING_CREDENTIAL="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/valid.uri" \
  --client-credential "$URI_TEST_DIR/missing-credential.json" 2>&1 || true)"
case "$URI_MISSING_CREDENTIAL" in
  *"load explicit development user-owned client credential"*) : ;;
  *) echo "FAIL: valid URI file did not reach credential preflight: $URI_MISSING_CREDENTIAL" >&2; exit 1 ;;
esac

printf '%s\n' 'malformed-without-secret-contents' >"$URI_TEST_DIR/malformed.uri"
URI_MALFORMED="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/malformed.uri" \
  --client-credential "$URI_TEST_DIR/missing-credential.json" 2>&1 || true)"
case "$URI_MALFORMED" in
  *"parse private REALITY URI file"*) : ;;
  *) echo "FAIL: malformed URI file was not rejected before credential state: $URI_MALFORMED" >&2; exit 1 ;;
esac

: >"$URI_TEST_DIR/empty.uri"
URI_EMPTY="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/empty.uri" 2>&1 || true)"
case "$URI_EMPTY" in
  *"is empty"*) : ;;
  *) echo "FAIL: empty URI file was accepted: $URI_EMPTY" >&2; exit 1 ;;
esac

cp "$URI_TEST_DIR/valid.uri" "$URI_TEST_DIR/permissive.uri"
chmod 640 "$URI_TEST_DIR/permissive.uri"
URI_MODE="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/permissive.uri" 2>&1 || true)"
case "$URI_MODE" in
  *"exact mode 0600"*) : ;;
  *) echo "FAIL: permissive URI file was accepted: $URI_MODE" >&2; exit 1 ;;
esac

ln "$URI_TEST_DIR/valid.uri" "$URI_TEST_DIR/hardlink.uri"
URI_HARDLINK="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/valid.uri" 2>&1 || true)"
case "$URI_HARDLINK" in
  *"exactly one hard link"*) : ;;
  *) echo "FAIL: multiply-linked URI file was accepted: $URI_HARDLINK" >&2; exit 1 ;;
esac
rm "$URI_TEST_DIR/hardlink.uri"

ln -s "$URI_TEST_DIR/valid.uri" "$URI_TEST_DIR/symlink.uri"
URI_SYMLINK="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/symlink.uri" 2>&1 || true)"
case "$URI_SYMLINK" in
  *"open private REALITY URI file"*) : ;;
  *) echo "FAIL: symlink URI file was accepted: $URI_SYMLINK" >&2; exit 1 ;;
esac

dd if=/dev/zero of="$URI_TEST_DIR/oversized.uri" bs=65537 count=1 2>/dev/null
chmod 600 "$URI_TEST_DIR/oversized.uri"
URI_OVERSIZED="$("$BIN/shadowpipe-client" \
  --development-user-credential --uri-file "$URI_TEST_DIR/oversized.uri" 2>&1 || true)"
case "$URI_OVERSIZED" in
  *"byte bound"*) : ;;
  *) echo "FAIL: oversized URI file was accepted: $URI_OVERSIZED" >&2; exit 1 ;;
esac

URI_MIXED="$("$BIN/shadowpipe-client" --uri "$VALID_URI" \
  --uri-file "$URI_TEST_DIR/valid.uri" 2>&1 || true)"
case "$URI_MIXED" in
  *"cannot be used with"*) : ;;
  *) echo "FAIL: --uri/--uri-file mixing was accepted: $URI_MIXED" >&2; exit 1 ;;
esac

SHORT_SID="$("$BIN/shadowpipe-client" --development-user-credential \
  --server 127.0.0.1:9 --reality --reality-pubkey "$PK" \
  --reality-short-id 01 --sni cover.test --server-fp "$FP" 2>&1 || true)"
case "$SHORT_SID" in
  *"exactly 16 lowercase hex"*) : ;;
  *) echo "FAIL: short manual REALITY selector escaped early preflight: $SHORT_SID" >&2; exit 1 ;;
esac
# --split and --auto-route are mutually exclusive.
SPLIT_CONFLICT="$("$BIN/shadowpipe-client" --split --auto-route --server x:1 2>&1 || true)"
case "$SPLIT_CONFLICT" in
  *"cannot be used with"*) : ;;
  *) echo "FAIL: client --split should conflict with --auto-route; got: $SPLIT_CONFLICT" >&2; exit 1 ;;
esac
# --reality and --tls are mutually exclusive (clap conflicts_with). Capture the
# output first: under pipefail, clap's non-zero exit would mask a grep match.
CONFLICT="$("$BIN/shadowpipe-client" --reality --tls --server x:1 2>&1 || true)"
case "$CONFLICT" in
  *"cannot be used with"*) : ;;
  *) echo "FAIL: client --reality should conflict with --tls; got: $CONFLICT" >&2; exit 1 ;;
esac
echo "OK: CLI kebab flags present (incl. mandatory-v3 provisioning/reality/lockdown lifecycle)"
