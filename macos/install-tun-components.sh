#!/bin/bash
set -euo pipefail

APP="${1:?Usage: install-tun-components.sh APP NATIVE_OUTPUT}"
NATIVE="${2:?Missing native output directory}"
CONTENTS="$APP/Contents"
mkdir -p "$CONTENTS/Frameworks" "$CONTENTS/Library/LaunchDaemons" \
  "$CONTENTS/Library/LaunchServices" "$CONTENTS/Library/TunCores" "$CONTENTS/Resources/TunAssets"
cp "$NATIVE/libV2rayNTun.dylib" "$CONTENTS/Frameworks/"
cp "$NATIVE/v2rayn-tun-helper" "$CONTENTS/Library/LaunchServices/"
cp "$NATIVE/2dust.v2rayN.TunHelper.plist" "$CONTENTS/Library/LaunchDaemons/"

copy_core() {
  local name="$1"; shift
  local candidate
  for candidate in "$@"; do
    if [[ -f "$CONTENTS/MacOS/bin/$candidate" && ! -L "$CONTENTS/MacOS/bin/$candidate" ]]; then
      cp "$CONTENTS/MacOS/bin/$candidate" "$CONTENTS/Library/TunCores/$name"
      chmod 755 "$CONTENTS/Library/TunCores/$name"
      return
    fi
  done
  echo "Missing bundled TUN core: $name" >&2
  exit 1
}
copy_core sing-box sing_box/sing-box-client sing_box/sing-box
copy_core xray xray/xray
copy_core mihomo mihomo/mihomo mihomo/mihomo-darwin-arm64 mihomo/mihomo-darwin-amd64
for name in geoip.dat geosite.dat; do
  if [[ -f "$CONTENTS/MacOS/bin/$name" && ! -L "$CONTENTS/MacOS/bin/$name" ]]; then
    cp "$CONTENTS/MacOS/bin/$name" "$CONTENTS/Resources/TunAssets/$name"
  fi
done
