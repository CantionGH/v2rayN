#!/bin/bash
set -euo pipefail

RID="${1:?Usage: build-tun-helper.sh osx-arm64|osx-x64 OUTPUT}"
OUTPUT="${2:?Missing output directory}"
MODE="${3:-developer-id}"
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
case "$MODE" in
  developer-id) ;;
  local) COMMON+=(-DV2RAYN_TUN_LOCAL_TRUST=1) ;;
  *) echo "Unknown trust mode: $MODE" >&2; exit 1 ;;
esac

xcrun clang "${COMMON[@]}" -dynamiclib -fvisibility=hidden \
  -install_name '@rpath/libV2rayNTun.dylib' \
  "$SOURCE/TunShared.m" "$SOURCE/TunLocalTrust.m" "$SOURCE/TunClient.m" \
  -framework Foundation -framework Security -framework ServiceManagement \
  -o "$OUTPUT/libV2rayNTun.dylib"
xcrun clang "${COMMON[@]}" "$SOURCE/TunShared.m" "$SOURCE/TunLocalTrust.m" "$SOURCE/TunConfigPolicy.m" "$SOURCE/TunDaemon.m" \
  -framework Foundation -framework Security -framework SystemConfiguration \
  -o "$OUTPUT/v2rayn-tun-helper"
cp "$SOURCE/2dust.v2rayN.TunHelper.plist" "$OUTPUT/"
if [[ "$MODE" == "local" ]]; then
  xcrun clang "${COMMON[@]}" "$SOURCE/TunShared.m" "$SOURCE/TunLocalTrust.m" "$SOURCE/TunTrustTool.m" \
    -framework Foundation -framework Security -o "$OUTPUT/v2rayn-tun-trust"
  cp "$SOURCE/2dust.v2rayN.LocalTunHelper.plist" "$OUTPUT/"
  touch "$OUTPUT/LocalTrustBuild"
fi
