#!/usr/bin/env bash
# Live smoke test for agentmetry-guard, run in CI on every OS.
#
# Starts a plain HTTP server on the machine's non-loopback IPv4, wraps curl
# through `agentmetry-guard wrap`, and asserts the events file records:
#   1. the forwarded GET (outcome success)
#   2. a refused CONNECT to a denylisted host (outcome denied, HTTP 403)
#
# Usage: scripts/smoke.sh [path-to-binary]
set -euo pipefail

BIN="${1:-./target/release/agentmetry-guard}"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

python3 -m http.server 8899 --bind 0.0.0.0 --directory "$WORK" >/dev/null 2>&1 &
SRV=$!
sleep 1

# A non-loopback IPv4 so the request is not caught by NO_PROXY.
case "$(uname -s)" in
  Darwin)
    IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows ipconfig prints usage to stdout on bad args, so parse plain output.
    IP="$(ipconfig | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -vE '^(127\.|169\.254\.|255\.|0\.)' | head -1 || true)"
    ;;
  *)
    IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    ;;
esac
if [ -z "${IP:-}" ]; then
  echo "no non-loopback IPv4 found; cannot test through the proxy" >&2
  exit 2
fi
echo "smoke: target IP $IP"

export AGENTMETRY_DATA_DIR="$WORK"
export AGENTMETRY_CORRELATION_ID="ci-smoke"
export AGENTMETRY_SESSION_ID="ci-smoke"
# No ingest endpoint in this test: events must land in the JSONL file.
unset AGENTMETRY_AUDIT_INGEST_URL AGENTMETRY_API_KEY AGENTMETRY_URL || true

EVENTS="$WORK/guard-events.jsonl"

# 1. Plain HTTP through the proxy.
"$BIN" wrap --events-file "$EVENTS" --deny blocked.invalid -- \
  curl -s -m 10 "http://$IP:8899/" > /dev/null

# 2. Denylisted HTTPS: the proxy must answer 403 and record outcome=denied.
"$BIN" wrap --events-file "$EVENTS" --deny blocked.invalid -- \
  curl -s -m 10 "https://blocked.invalid/" > /dev/null 2>&1 || true

sleep 1

grep -q "\"command\":\"GET $IP/\"" "$EVENTS" || { echo "FAIL: no GET event" >&2; cat "$EVENTS" >&2; exit 1; }
grep -q '"outcome":"success"' "$EVENTS" || { echo "FAIL: GET not marked success" >&2; cat "$EVENTS" >&2; exit 1; }
grep -q '"command":"CONNECT blocked.invalid:443"' "$EVENTS" || { echo "FAIL: no CONNECT event" >&2; cat "$EVENTS" >&2; exit 1; }
grep -q '"outcome":"denied"' "$EVENTS" || { echo "FAIL: CONNECT not marked denied" >&2; cat "$EVENTS" >&2; exit 1; }
grep -q '"correlation_id":"ci-smoke"' "$EVENTS" || { echo "FAIL: correlation missing" >&2; cat "$EVENTS" >&2; exit 1; }

echo "smoke: OK"
cat "$EVENTS"
