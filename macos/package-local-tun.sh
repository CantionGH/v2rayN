#!/bin/bash
set -euo pipefail
APP="${1:?Usage: package-local-tun.sh APP VERSION OUTPUT.pkg}"
VERSION="${2:?Missing version}"
OUTPUT="${3:?Missing output pkg}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$(cd "$(dirname "$APP")" && pwd)/$(basename "$APP")"
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]] || { echo 'Expected a numeric bundle version.' >&2; exit 1; }
[[ "$(basename "$APP")" == v2rayN.app && -f "$APP/Contents/Resources/v2rayN.NativeAOT" &&
   -f "$APP/Contents/Resources/TunLocalTrustBuild" && -f "$APP/Contents/Library/LaunchServices/v2rayn-tun-trust" ]] || {
  echo 'Assemble a NativeAOT app with explicitly local-mode native components first.' >&2; exit 1;
}
[[ -z "$(find "$APP" -type l -print -quit)" ]] || { echo 'Symlinks are not supported in a locally trusted bundle.' >&2; exit 1; }
mkdir -p "$APP/Contents/Resources/LocalTun"
cp "$ROOT/macos/local-installer/uninstall.sh" "$APP/Contents/Resources/LocalTun/"
find "$APP" -type d -exec chmod 755 {} +
find "$APP" -type f -exec chmod 644 {} +
chmod -RN "$APP"
while IFS= read -r -d '' binary; do
  # Signing the main executable signs its enclosing bundle. Do that only after
  # every nested executable/library has its final signature.
  [[ "$binary" != "$APP/Contents/MacOS/v2rayN" ]] || continue
  if /usr/bin/file -b "$binary" | grep -q 'Mach-O'; then
    chmod 755 "$binary"
    identifier="2dust.v2rayN.Runtime.$(basename "$binary")"
    case "$binary" in
      */Library/TunCores/*) identifier="2dust.v2rayN.TunCore.$(basename "$binary")" ;;
      */v2rayn-tun-helper) identifier=2dust.v2rayN.TunHelper ;;
      */v2rayn-tun-trust) identifier=2dust.v2rayN.TunTrustTool ;;
      */libV2rayNTun.dylib) identifier=2dust.v2rayN.TunClient ;;
    esac
    codesign --force --sign - --options runtime --timestamp=none --identifier "$identifier" "$binary"
  fi
done < <(find "$APP" -type f -print0)
chmod 755 "$APP/Contents/MacOS/v2rayN"
codesign --force --sign - --options runtime --timestamp=none \
  --entitlements "$ROOT/macos/local-gui.entitlements.plist" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/v2rayn-local-package.XXXXXX")"
# Only this invocation's newly-created temporary staging tree is removed.
trap 'rm -rf -- "${WORK:?}"' EXIT
mkdir "$WORK/scripts"
mkdir "$WORK/payload"
ditto "$APP" "$WORK/payload/v2rayN.app"
cp "$ROOT/macos/local-installer/preinstall" "$ROOT/macos/local-installer/postinstall" "$WORK/scripts/"
chmod 755 "$WORK/scripts/"*
cat > "$WORK/components.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><dict>
<key>RootRelativeBundlePath</key><string>v2rayN.app</string>
<key>BundleIsRelocatable</key><false/>
<key>BundleIsVersionChecked</key><false/>
<key>BundleOverwriteAction</key><string>upgrade</string>
</dict></array></plist>
PLIST
pkgbuild --root "$WORK/payload" --component-plist "$WORK/components.plist" \
  --identifier 2dust.v2rayN.LocalTun --version "$VERSION" \
  --install-location '/Library/Application Support/v2rayN-LocalTun' \
  --ownership recommended --scripts "$WORK/scripts" "$OUTPUT"
echo "Created local-test PKG: $OUTPUT (ad-hoc signed payload, unsigned installer, no Apple notarization)."
