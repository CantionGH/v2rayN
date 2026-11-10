# macOS privileged TUN service (方案 B)

**无 Developer ID 的自用测试实现见 [LOCAL-TESTING.md](LOCAL-TESTING.md)。**
它必须显式构建为 `local` 模式，使用本机 root 信任清单及独立 launchd 服务，
不会让下面的 Developer ID 路径自动降级。

This branch replaces macOS's in-app sudo password collection with an
`SMAppService` launch daemon and authenticated XPC. Linux and Windows retain their
existing launch paths. **This is a security-sensitive implementation requiring
macOS integration testing and independent review before a production release.**

## Architecture and trust boundary

```text
NativeAOT GUI (ordinary user)
  └─ libV2rayNTun.dylib, loaded from the signed application bundle
       └─ XPC message → launchd → v2rayn-tun-helper (root)
            └─ fixed, signed bundled sing-box / Xray / mihomo
```

- The system handles installer authentication and background-service approval.
  The GUI never receives an administrator password. No password is cached,
  piped into a process, saved in Keychain, or added to sudoers.
- The native library runs **inside the GUI**, not in a separately executable
  root-launching CLI. The helper validates every message with
  `SecCodeCreateWithXPCMessage`, which uses the message's audit token, and checks
  the GUI's exact signing identifier, Apple certificate chain, Team ID, hardened
  runtime and restrictive entitlements. The client authenticates helper replies
  by the same mechanism and checks that the helper runs as root.
- Only the current console user is accepted. Service approval is device-level
  delegation to the signed app; it is **not** fresh administrator authorization
  for each node change. A logged-in user running the trusted app can use TUN.
- The only XPC operations are `start`, `status`, and `stop`. Start accepts an
  allowlisted core name, JSON configuration and bounded data assets. It accepts
  no executable path, arbitrary arguments, environment, shell text, PID, or
  user-supplied filesystem URL. Status and stop apply only to the connection's
  own child. At most two cores run concurrently (main/pre-core).
- The helper launches with `posix_spawn`, a fixed argument list and a clean
  environment. It owns child reaping, so PID reuse cannot redirect a later stop
  to an unrelated process. It tries SIGTERM, then SIGKILL after three seconds.
- Configuration and file assets are read by the **unprivileged GUI** and sent as
  bytes. The daemon validates them independently and snapshots them under a
  root-owned `0700` session directory; files are `0600`. It never follows a GUI
  pathname as root. Absolute/traversing paths, scripts, plugins, external UI
  downloads, and Xray's mutating gRPC API are rejected. Core logs use a bounded
  pipe/XPC buffer rather than root opening a GUI-selected log filename.
- Dynamic mihomo `proxy-providers` are rejected: a downloaded proxy description
  can introduce new filesystem references after the initial validation. Use
  static, expanded proxies in privileged mode until this path is separately
  audited. Downloaded rule sets are data, not general proxy configurations.
- Clash-compatible controllers must use IPv4 loopback and a fresh 256-bit secret
  held in GUI memory. HTTP/WebSocket API clients send the secret; it is not
  written into ordinary GUI configuration. Without this, local processes could
  bypass the XPC boundary through a root core's unauthenticated control API.
- Disconnecting the GUI, including a GUI crash or an ambiguous timed-out start,
  stops that connection's core. Helper shutdown stops all owned cores. Children
  inherit the daemon's process group; `AbandonProcessGroup=false` asks launchd to
  clean up descendants when the job terminates. This crash path **must be tested
  on supported macOS releases**, especially after forced termination.

### Why NativeAOT and a protected installation location?

A signed .NET JIT host can have managed-code injection surfaces such as startup
hooks and diagnostics. An IPC code-signature check alone does not make those
surfaces safe. This first implementation therefore requires a **NativeAOT** GUI
without `allow-jit`, unsigned executable memory, disabled library validation,
DYLD environment overrides, or `get-task-allow`. All native dependencies must be
signed by the same publisher. There is no unsigned/debug bypass.

The signed installer puts the app at:

```text
/Library/Application Support/v2rayN/v2rayN.app
```

Every bundle entry and every ancestor must be root-owned, non-symlink and not
group/other-writable. `/Applications` is intentionally not the trust anchor: it
is commonly writable by the admin group, allowing bundle/ancestor swaps even
when the app's files themselves belong to root. Launch the protected app
directly; it can be kept in the Dock. Ordinary proxy mode remains usable in
unsigned/JIT builds, but privileged TUN fails closed.

## Build and assemble

Requirements: macOS 13.6+, Xcode command-line tools, .NET 10, the appropriate
architecture's trusted core binaries/data, Developer ID Application and Developer
ID Installer certificates. The key material stays in your Keychain; it is not
provided to this repository or embedded in the app.

From the repository root, for Apple Silicon (use `osx-x64` for Intel):

```sh
dotnet publish v2rayN/v2rayN.Desktop/v2rayN.Desktop.csproj \
  -c Release -r osx-arm64 -p:SelfContained=true -p:IsAot=true \
  -o artifacts/macos-publish
bash macos/build-tun-helper.sh osx-arm64 artifacts/macos-native
```

Assemble `v2rayN.app` using the existing macOS packaging layout:

- Published output under `Contents/MacOS`.
- The existing `package-osx.sh` creates the icon, `Info.plist` and
  `NotStoreConfigHere.txt`. Point it at the **NativeAOT** output, not the JIT
  artifact. It also obtains the regular core bundle.
- Merge the correct architecture's core bundle into `Contents/MacOS/bin` and
  mark the reviewed AOT output with `Contents/MacOS/v2rayN.NativeAOT`.
  The existing build workflow writes that marker only for `isAot=true`.
- Install native components before signing:

```sh
bash macos/install-tun-components.sh \
  artifacts/v2rayN.app artifacts/macos-native
```

`install-tun-components.sh` copies fixed cores into `Contents/Library/TunCores`
and fixed geo data into `Contents/Resources/TunAssets`. The helper **does not run
the copies in the user-updatable data directory**. A TUN core upgrade requires a
new reviewed, signed application package; ordinary non-TUN core updates retain
their previous behavior. Local `.srs`/certificate inputs can be snapshotted as
data, but arbitrary custom file layouts are not supported.

Sign inside-out and produce a root-owned installer payload:

```sh
bash macos/package-privileged-tun.sh artifacts/v2rayN.app 7.25.6 \
  'Developer ID Application: YOUR NAME (TEAMID)' \
  'Developer ID Installer: YOUR NAME (TEAMID)' \
  artifacts/v2rayN-privileged-tun.pkg
```

Before distribution, notarize and staple with your own configured Keychain
profile:

```sh
xcrun notarytool submit artifacts/v2rayN-privileged-tun.pkg \
  --keychain-profile YOUR_NOTARY_PROFILE --wait
xcrun stapler staple artifacts/v2rayN-privileged-tun.pkg
```

The existing DMG/ZIP workflows do **not** automatically produce an authenticated
privileged-TUN installer. GPG signing an archive is not Apple code signing.
The new CI workflow compiles native code and tests policy; it does not distribute
unsigned privileged functionality or need signing secrets.

## Use, revoke and uninstall

1. Quit any old copy of v2rayN. Install the signed PKG through the system installer.
2. Launch `/Library/Application Support/v2rayN/v2rayN.app`.
3. Enable TUN. If macOS requires approval, the app opens Login Items settings;
   approve the v2rayN background service and retry. Refusal does not trigger a
   fallback password box or leave a core running.
4. After approval, node switches and normal stops use the existing daemon. There
   is no dependency on a sudo timeout or saved password. Registration persists
   across reboot, but TUN runs only when the GUI owns an active session.

To revoke, disable the background service in System Settings. To unregister,
first quit the GUI, then run as the ordinary user:

```sh
'/Library/Application Support/v2rayN/v2rayN.app/Contents/MacOS/v2rayN' --macos-tun-status
'/Library/Application Support/v2rayN/v2rayN.app/Contents/MacOS/v2rayN' --macos-tun-unregister
```

Use administrator-managed removal of the protected app after unregistering.
No `/etc/sudoers` entries or standalone LaunchDaemon plist are installed outside
the bundle. Ordinary GUI data is not deleted by service unregistering. Session
snapshots are deleted on normal exit; a forced helper crash can leave private
files in `/private/var/run/v2rayn-tun` until cleanup/reboot.

## Tests and required macOS acceptance checks

```sh
dotnet test --project v2rayN/ServiceLib.Tests -c Release -p:PublishAot=false
bash macos/test-tun-helper.sh artifacts/native-tests
```

The managed tests cover fixed core selection, YAML conversion, input snapshots,
controller authentication and configuration limits. Native tests exercise the
independent helper policy, path restrictions, controller restrictions, asset
validation and rejection of XPC messages without an audit token. CI builds both
native architectures with warnings as errors.

Before shipping, perform all of these on a real Mac with a signed package:

- Approval accepted/denied/revoked, standard/admin accounts, fast user switching.
- All three cores, main/pre-core combinations, switching nodes, rapid reloads,
  service restart, reboot, sleep/wake, GUI exit/crash and helper SIGTERM/SIGKILL.
- Check actual utun interfaces, routes/DNS restoration, logs, traffic statistics,
  authenticated controller access and absence of orphan root processes.
- Reject an unsigned/wrong-team/wrong-identifier client, unsigned/replaced core,
  writable/symlink bundle entry and moved/unprotected installation.
- Reject arbitrary PID/argv/environment requests and filesystem traversal.
- Lost start replies must stop their core; repeated start on one connection and
  more than two concurrent core launches must be rejected.
- Verify both Intel and Apple Silicon NativeAOT packages, signing, notarization,
  upgrade, service revocation and unregistering.

## Remaining limitations

The network cores still run as root; this design reduces credential exposure and
constrains the launcher, but is **not a sandbox for vulnerabilities in a core**.
Configuration validation is intentionally conservative, not a complete schema
for every future core release. Incompatible custom configurations fail rather
than silently relaxing the boundary. Persistent core caches currently live only
for a session. Core-version updates need policy review and the tests above.
