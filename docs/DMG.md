# macOS DMG distribution for the unchanged beta.6

Build locally on an Apple Silicon Mac with Xcode command line tools and Python
3.9+. No Actions, sudo, Finder automation, Developer ID or notarization service
is used. Two hash-pinned, pure-Python metadata wheels are vendored under
`scripts/dmg/vendor` with their licenses; no package installation or network
access is required once the published ZIP has been downloaded. Finder view
metadata is written directly with [ds_store](https://ds-store.readthedocs.io/en/v1.3.1/)
and volume-relative aliases, following [dmgbuild](https://github.com/dmgbuild/dmgbuild/blob/v1.6.5/src/dmgbuild/core.py).

```sh
gh release download v0.2.0-beta.6 --repo GeoKhv/corporate-vpn-router \
  --pattern Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.zip --dir /tmp/cvr-input
bash scripts/package-dmg.sh /tmp/cvr-input/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.zip
python3 scripts/test-dmg.py dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.dmg
```

The builder pins the published ZIP SHA-256 and beta.6 CDHash, verifies its deep
strict signature, and compares every payload file, directory mode and symlink
before/after packaging. It never invokes `build.sh`, signs the VPN payload, or
overwrites the ZIP, existing checksums or an existing DMG. `CVR_DIST_DIR` selects
a fresh output directory. SHA-256 is in the adjacent `.dmg.sha256` file.
This reproduces the packaging procedure and identical VPN payload; DMG bytes
are not deterministic (filesystem UUID/timestamps, Finder metadata and locally
compiled distribution shells can vary with macOS/Xcode).

The visible Corporate VPN Router is a distribution launcher with an icon. Its
`Contents/Resources/Payload/Corporate VPN Router.app` is the exact published app.
The separate “Программы” drop target is an installer application with a folder
and download-arrow icon, explicitly described as such in the image. Both call
the original `--install` and open only `~/Applications/Corporate VPN Router.app`.
There is deliberately no `/Applications` shortcut: beta.6 self-installs to the
user's Applications folder and a conventional system-wide copy would duplicate
it. Double-clicking the launcher is the equivalent accessible installation path.
The installed app retains its original generic icon; its signed resources are
unchanged. The DMG/launcher icons belong to the distribution shells only.

The wrapper checks the live `menu.lock` before writes, refuses an existing
system-wide copy, and relies on beta.6's ownership, signature, backup and login
agent checks. The original installer repeats its lock check. It neither registers
new login jobs nor stops/reloads either existing job. Existing HTTP proxy jobs,
settings, Chrome enrollment and the SSL tunnel are not changed by packaging.
An existing app must be quit by its user before updating. A manually started
older/system-wide copy or manual Finder replacement is outside this installer.

The integration test mounts read-only, checks image integrity, signatures and
payload inventory, installs to a disposable home with `CFFIXED_USER_HOME`, runs
the actual published app there, checks refusal while its lock is held, tests a
same-version update/backup and restores that backup. No real home, launchd job,
network profile, credentials or live VPN is mutated. The environment override is
checked against Foundation before installation; failure stops the test. Tests
must run without sudo. This is an isolated installation/launch test on the real
Mac, not a second physical user login or a fresh-machine Gatekeeper test.

Both shells and the payload are ad hoc signed; the DMG is unsigned. `spctl`
rejection is expected without Developer ID/notarization. A browser-downloaded,
quarantined first launch may require per-app approval in macOS Settings, subject
to organizational policy. Never disable Gatekeeper or remove quarantine. A full
quarantined first-install approval on a second clean Mac remains a separate check.

Upload only after local acceptance, without replacing any beta.6 asset:

```sh
gh release upload v0.2.0-beta.6 --repo GeoKhv/corporate-vpn-router \
  dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.dmg \
  dist/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64.dmg.sha256
```

Keep the existing `SHA256SUMS.txt` and ZIPs intact. Verify the new download and
compare the old release asset IDs/digests after publication. Installation-file
rollback is documented in the DMG; beta.5's Chrome migration rollback still
uses the existing app menu and its separately confirmed profile.
