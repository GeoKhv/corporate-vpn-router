# macOS DMG · beta.6 installer-fix.1

The corrected asset is `Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64-installer-fix.1.dmg`.
The previous DMG, ZIPs and checksums remain release assets. Do not overwrite them.

Build locally on Apple Silicon with Xcode command line tools and Python 3.9+.
No Actions, sudo, Developer ID or notarization service is used. The metadata
libraries and their licenses are vendored in `scripts/dmg/vendor`.

```sh
bash scripts/package-dmg.sh /path/to/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.zip
python3 -B scripts/test-dmg.py \
  dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64-installer-fix.1.dmg \
  '/path/to/original-beta.6/Corporate VPN Router.app'
```

The builder verifies the published ZIP SHA-256
`83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c`
and original application CDHash `06684ffbb00baba39f611a7d20c9c643791e893d`.
It rebuilds the Swift menu executable with the installation corrections, updates
CFBundleVersion to 8, adds `Resources/INSTALLER_REVISION` (`installer-fix.1`), and
signs the resulting bundle ad hoc. Every original resource, including the VPN
engine, native worker, CPython runtime and licenses, is compared byte-for-byte.
The shell pins the resulting application CDHash and verifies it before copying,
in staging, and after placement. The adjacent `.dmg.sha256` identifies the image.
A fresh `CVR_DIST_DIR` can be used for another build; existing images are refused.

## Installation

The DMG contains one self-contained **Установить Corporate VPN Router.app**.
Double-click it. It installs only to `~/Applications/Corporate VPN Router.app`.
There is no drop target, sibling-app dependency or system Applications shortcut.
App Translocation can relocate the installer without hiding its payload.
The payload is copied as files; the shell never directly executes its nested
Mach-O file or calls the original `--install` across a quarantine boundary.

`Sources/InstallTransaction.swift` is shared by the shell and the app's explicit
`--install`. The transaction validates destination ownership and login arguments,
rejects user symlinks, and holds `menu.lock` until commit or rollback. It never
stops or reloads any production launchd job. A running menu refuses replacement;
the existing VPN session remains live. A second installer is excluded by the
same lock. A system-wide copy is reported instead of overwritten.

The staged app is verified before the old app is moved to a unique rollback
bundle. Failure of placement, final signature verification or creation of a new
menu LaunchAgent restores the previous app. If rollback itself fails, the error
names both recovery locations. Existing login-agent bytes and settings are
preserved, including disabled RunAtLoad and launchctl overrides. A fresh install
creates the user LaunchAgent for `CorporateVPNRouter --login`; the installer
opens the app through NSWorkspace and waits for `isFinishedLaunching`, separately
from installation. A process suspended by Gatekeeper is not a successful launch;
the shell reports installation success with a specific launch error or a 30-second
timeout. No HTTP router plist, Chrome profile, credentials or site list is
rewritten.

The app resolves its own bundle through Foundation instead of trusting argv[0].
When Gatekeeper translocates an installed app, it recognizes the same verified
executable, Info.plist and signed resource manifest at the installed location;
it does not replace that app over itself. Startup still takes the ordinary menu
lock. Each filesystem/command failure includes the operation, path and system
error or captured codesign/ditto output. Launch denial reports that installation
already succeeded and points to the installed location.

## Quarantine and acceptance

Neither the installer nor the builder removes quarantine or changes Gatekeeper.
Both bundles are ad hoc signed, without Developer ID/notarization; the image is
unsigned. First launch may therefore require **Privacy & Security → Open Anyway**
for **Установить Corporate VPN Router**, and a separate approval for
**Corporate VPN Router** if macOS blocks the installed application. Approve only
the named item after verifying the source and SHA-256. An organizational policy
that forbids this approval is not bypassed.

The integration test runs non-root, mounts the image read-only and installs in a
verified disposable Foundation home. It checks fresh installation, actual menu
startup, exclusion while running, a unique temporary Aqua launchd job, foreign
login-agent and damaged-payload refusal, actual write-permission failure after
replacement with restoration of the previous app, update of the published
beta.6, preservation of customized login bytes and synthetic settings, and
restoration/launch of the exact old bundle. It never loads the production labels.

These tests are distinct from Gatekeeper acceptance. `hdiutil attach` alone does
not reproduce a browser-downloaded first launch. A quarantined image must be
opened using DiskImageMounter and observed mounted with `quarantine`; launch
through LaunchServices, keep quarantine, and record the actual approval and
result. An empty disposable home on this Mac is not a second physical Mac or a
fresh OS trust database. See `VALIDATION.md` for observed results and limits.

## Publication

Only publish after acceptance. Upload the new names without `--clobber`:

```sh
gh release upload v0.2.0-beta.6 --repo GeoKhv/corporate-vpn-router \
  dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64-installer-fix.1.dmg \
  dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64-installer-fix.1.dmg.sha256
```

Download the new assets again, compare SHA-256, and compare every previous asset
ID and digest with the pre-publication inventory. The original `SHA256SUMS.txt`
and ZIPs stay intact. File rollback of beta.6 is described in the colleague
instructions; beta.5 Chrome-profile rollback remains the separate app workflow.
