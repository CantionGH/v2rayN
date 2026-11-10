#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:?Usage: test-tun-helper.sh OUTPUT_DIRECTORY}"
mkdir -p "$OUTPUT"
xcrun clang -mmacosx-version-min=13.6 -fobjc-arc -fblocks -Wall -Wextra -Werror -Wno-unused-parameter \
  "$ROOT/macos/TunHelper/TunShared.m" "$ROOT/macos/TunHelper/TunConfigPolicy.m" \
  "$ROOT/macos/TunHelper/Tests/PolicyTests.m" -framework Foundation -framework Security \
  -o "$OUTPUT/tun-policy-tests"
"$OUTPUT/tun-policy-tests"
