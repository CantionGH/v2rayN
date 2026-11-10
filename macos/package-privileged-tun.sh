#!/bin/bash
set -euo pipefail

# Run AFTER assembling the app and BEFORE distributing it. Signing keys stay in
# the caller's Keychain; no identity, password or certificate is stored in Git.
APP="${1:?Usage: package-privileged-tun.sh APP VERSION APPLICATION_IDENTITY INSTALLER_IDENTITY OUTPUT.pkg}"
VERSION="${2:?Missing version}"
APPLICATION_IDENTITY="${3:?Missing Developer ID Application identity}"
INSTALLER_IDENTITY="${4:?Missing Developer ID Installer identity}"
OUTPUT="${5:?Missing output pkg}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$(cd "$(dirname "$APP")" && pwd)/$(basename "$APP")"
if [[ "$(basename "$APP")" != "v2rayN.app" ]]; then
  echo "The installer expects an assembled v2rayN.app bundle." >&2
  exit 1
fi
if [[ -f "$APP/Contents/Resources/TunLocalTrustBuild" ]]; then
  echo 'Local-trust components cannot be packaged as a Developer ID build.' >&2
  exit 1
fi
if [[ "$APPLICATION_IDENTITY" != "Developer ID Application:"* || "$INSTALLER_IDENTITY" != "Developer ID Installer:"* ]]; then
  echo "Real Developer ID Application/Installer identities are required; ad-hoc signing is not supported." >&2
  exit 1
fi
if [[ ! -f "$APP/Contents/MacOS/v2rayN.NativeAOT" ]]; then
  echo "Privileged TUN currently requires a NativeAOT build. Rebuild with -p:IsAot=true." >&2
  exit 1
fi
if [[ ! -x "$APP/Contents/Library/LaunchServices/v2rayn-tun-helper" ]]; then
  echo "Install the native TUN components before signing." >&2
  exit 1
fi
for core in sing-box xray mihomo; do
  if [[ ! -f "$APP/Contents/Library/TunCores/$core" ]]; then
    echo "Missing trusted bundled core: $core" >&2
    exit 1
  fi
done
if [[ -n "$(find "$APP" -type l -print -quit)" ]]; then
  echo "Symlinks are not supported in the privileged application bundle." >&2
  exit 1
fi
find "$APP" -type d -exec chmod 755 {} +
find "$APP" -type f -exec chmod 644 {} +

# Sign inside out, including every native dependency. Do not disable library
# validation to accommodate unsigned runtime libraries. The helper accepts only
# the hardened NativeAOT GUI, not a JIT runtime with injectable startup hooks.
while IFS= read -r -d '' binary; do
  if /usr/bin/file -b "$binary" | grep -q 'Mach-O'; then
    chmod 755 "$binary"
    identifier="2dust.v2rayN.Runtime.$(basename "$binary")"
    case "$binary" in
      */Library/TunCores/*) identifier="2dust.v2rayN.TunCore.$(basename "$binary")" ;;
      */v2rayn-tun-helper) identifier="2dust.v2rayN.TunHelper" ;;
      */libV2rayNTun.dylib) identifier="2dust.v2rayN.TunClient" ;;
      */MacOS/v2rayN) identifier="2dust.v2rayN" ;;
    esac
    codesign --force --options runtime --timestamp --identifier "$identifier" --sign "$APPLICATION_IDENTITY" "$binary"
  fi
done < <(find "$APP" -type f -print0)
codesign --force --options runtime --timestamp --sign "$APPLICATION_IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

# An ordinary drag-and-drop install leaves the bundle user-writable. The signed
# installer gives every payload entry root ownership and secure permissions.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/v2rayn-tun-package.XXXXXX")"
trap 'rm -f "$WORK/component.plist"; rmdir "$WORK"' EXIT
cat > "$WORK/component.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><dict>
<key>RootRelativeBundlePath</key><string>v2rayN.app</string>
<key>BundleIsRelocatable</key><false/>
<key>BundleIsVersionChecked</key><true/>
<key>BundleOverwriteAction</key><string>upgrade</string>
</dict></array></plist>
PLIST
pkgbuild --component "$APP" --component-plist "$WORK/component.plist" \
  --identifier 2dust.v2rayN.PrivilegedTun --version "$VERSION" \
  --install-location "/Library/Application Support/v2rayN" --ownership recommended \
  --sign "$INSTALLER_IDENTITY" "$OUTPUT"
echo "Created $OUTPUT. Notarize and staple it before distribution (see macos/README.md)."
