#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: test-tun-helper.sh OUTPUT_DIRECTORY}"
MODE="${2:-developer-id}"
FLAGS=(-mmacosx-version-min=13.6)
case "$MODE" in
  developer-id) ;;
  local) FLAGS+=(-DV2RAYN_TUN_LOCAL_TRUST=1) ;;
  *) echo 'Unknown trust mode.' >&2; exit 1 ;;
esac
mkdir -p "$OUTPUT"
xcrun clang "${FLAGS[@]}" -fobjc-arc -fblocks -Wall -Wextra -Werror -Wno-unused-parameter \
  "$ROOT/macos/TunHelper/TunShared.m" "$ROOT/macos/TunHelper/TunLocalTrust.m" "$ROOT/macos/TunHelper/TunConfigPolicy.m" \
  "$ROOT/macos/TunHelper/Tests/PolicyTests.m" -framework Foundation -framework Security \
  -o "$OUTPUT/tun-policy-tests"
"$OUTPUT/tun-policy-tests"
