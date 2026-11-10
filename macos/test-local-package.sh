#!/bin/bash
set -euo pipefail
# Exercise real macOS signing/pkgbuild before the expensive NativeAOT publish.
# This fixture is not installed or uploaded, and is NOT a usable GUI/TUN build.
WORK="${1:?Usage: test-local-package.sh NEW_FIXTURE_DIRECTORY LOCAL_NATIVE_OUTPUT}"
NATIVE="${2:?Missing local native output directory}"
[[ ! -e "$WORK" && ! -L "$WORK" ]] || { echo 'Fixture directory must be new.' >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$WORK/publish" "$WORK/cores/bin/"{sing_box,xray,mihomo}
printf 'int main(void) { return 0; }\n' > "$WORK/stub.c"
xcrun clang "$WORK/stub.c" -o "$WORK/publish/v2rayN"
touch "$WORK/publish/v2rayN.NativeAOT" "$WORK/publish/v2rayN.icns"
for pair in sing_box/sing-box xray/xray mihomo/mihomo; do
  cp "$WORK/publish/v2rayN" "$WORK/cores/bin/$pair"
done
for data in geoip.dat geosite.dat Country.mmdb geoip.metadb; do
  printf 'fixture resource\n' > "$WORK/cores/bin/$data"
done
bash "$ROOT/macos/assemble-app.sh" "$WORK/publish" "$WORK/cores" "$NATIVE" "$WORK/v2rayN.app" 7.25.6
[[ ! -e "$WORK/v2rayN.app/Contents/MacOS/bin" &&
   ! -e "$WORK/v2rayN.app/Contents/MacOS/v2rayN.NativeAOT" &&
   -f "$WORK/v2rayN.app/Contents/Resources/v2rayN.NativeAOT" ]]
bash "$ROOT/macos/package-local-tun.sh" "$WORK/v2rayN.app" 7.25.6 "$WORK/fixture.pkg"
[[ -s "$WORK/fixture.pkg" && -x "$WORK/v2rayN.app/Contents/MacOS/v2rayN" ]]
echo 'PASS: real nested-code signing, strict verification and PKG construction with fixture resources'
