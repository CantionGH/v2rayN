#!/bin/bash
set -euo pipefail
PUBLISHED="${1:?Usage: assemble-app.sh PUBLISHED CORE_BUNDLE NATIVE_OUTPUT APP VERSION}"
CORES="${2:?Missing core bundle directory}"
NATIVE="${3:?Missing native output directory}"
APP="${4:?Missing destination app}"
VERSION="${5:?Missing version}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}$ && ! -e "$APP" && ! -L "$APP" &&
   -f "$PUBLISHED/v2rayN.NativeAOT" && -d "$CORES/bin" ]] || {
  echo 'Expected a new destination, NativeAOT publish marker, numeric version, and extracted core bundle.' >&2; exit 1;
}
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R "$PUBLISHED/." "$APP/Contents/MacOS/"
cp -R "$CORES/bin" "$APP/Contents/MacOS/"
cp "$PUBLISHED/v2rayN.icns" "$APP/Contents/Resources/AppIcon.icns"
echo 'Store GUI data in the ordinary user data directory, never in this bundle.' > "$APP/Contents/MacOS/NotStoreConfigHere.txt"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>2dust.v2rayN</string>
<key>CFBundleName</key><string>v2rayN Local TUN</string>
<key>CFBundleDisplayName</key><string>v2rayN Local TUN (self-test)</string>
<key>CFBundleExecutable</key><string>v2rayN</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSMinimumSystemVersion</key><string>13.6</string>
</dict></plist>
PLIST
bash "$ROOT/macos/install-tun-components.sh" "$APP" "$NATIVE"
# MacOS is a nested-code location: a mixed bin directory there makes codesign
# interpret GeoIP databases as unsigned subcomponents. Keep the ordinary-user
# core seed in Resources; the privileged copies already have fixed role paths.
mv "$APP/Contents/MacOS/bin" "$APP/Contents/Resources/BundledCores"
