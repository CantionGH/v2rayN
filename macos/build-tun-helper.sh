#!/bin/bash
set -euo pipefail

RID="${1:?Usage: build-tun-helper.sh osx-arm64|osx-x64 OUTPUT}"
OUTPUT="${2:?Missing output directory}"
case "$RID" in
  osx-arm64) ARCH=arm64 ;;
  osx-x64) ARCH=x86_64 ;;
  *) echo "Unsupported runtime: $RID" >&2; exit 1 ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/macos/TunHelper"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
COMMON=(-arch "$ARCH" -mmacosx-version-min=13.6 -fobjc-arc -fblocks -O2 -Wall -Wextra -Werror -Wno-unused-parameter)

xcrun clang "${COMMON[@]}" -dynamiclib -fvisibility=hidden \
  -install_name '@rpath/libV2rayNTun.dylib' \
  "$SOURCE/TunShared.m" "$SOURCE/TunClient.m" \
  -framework Foundation -framework Security -framework ServiceManagement \
  -o "$OUTPUT/libV2rayNTun.dylib"
xcrun clang "${COMMON[@]}" "$SOURCE/TunShared.m" "$SOURCE/TunConfigPolicy.m" "$SOURCE/TunDaemon.m" \
  -framework Foundation -framework Security -framework SystemConfiguration \
  -o "$OUTPUT/v2rayn-tun-helper"
cp "$SOURCE/2dust.v2rayN.TunHelper.plist" "$OUTPUT/"
