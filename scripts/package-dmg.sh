#!/bin/bash
# Installer fix.1: rebuild only the menu executable; preserve published VPN resources.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
VERSION=0.2.0-beta.6
ZIP_SHA=83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c
CDHASH=06684ffbb00baba39f611a7d20c9c643791e893d
BASE="Corporate-VPN-Router-$VERSION-macOS-arm64"
NAME="$BASE-installer-fix.1"
ZIP="${1:?Usage: scripts/package-dmg.sh /path/to/published-beta.6-macOS-arm64.zip}"
ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
DEST="${CVR_DIST_DIR:-$PWD/dist}"
mkdir -p "$DEST" .build/module-cache
DEST="$(cd "$DEST" && pwd)"
test "$(shasum -a 256 "$ZIP" | awk '{print $1}')" = "$ZIP_SHA" || { echo 'Published ZIP SHA-256 mismatch' >&2; exit 1; }
test ! -e "$DEST/$NAME.dmg" && test ! -e "$DEST/$NAME.dmg.sha256" || { echo 'Refusing to overwrite an existing DMG; use a fresh CVR_DIST_DIR.' >&2; exit 1; }
WORK=$(mktemp -d /private/tmp/cvr-dmg.XXXXXX)
MOUNT="$WORK/Corporate VPN Router beta.6"
MOUNTED=0
cleanup() {
    if [[ "$MOUNTED" = 1 ]]; then hdiutil detach "$MOUNT" >/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
ditto -x -k "$ZIP" "$WORK/unzip"
ORIGINAL="$WORK/unzip/$BASE/Corporate VPN Router.app"
codesign --verify --deep --strict "-R=cdhash H\"$CDHASH\"" "$ORIGINAL"
test "$(cat "$ORIGINAL/Contents/Resources/VERSION")" = "$VERSION"
STAGE="$WORK/stage"
SOURCE="$STAGE/Установить Corporate VPN Router.app"
mkdir -p "$SOURCE/Contents/Resources/Payload" "$SOURCE/Contents/MacOS" "$STAGE/.background"
ditto --rsrc --extattr --qtn --acl "$ORIGINAL" "$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app"
PAYLOAD="$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app"
# Installation and launch code changes only; Backend, Runtime and native worker stay identical.
swiftc -D CVR_MENU_BETA -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" \
  -framework AppKit Sources/{Core,MacOS,Lifecycle,InstallTransaction,BetaInstall,MenuComponents,OfficialGUI,MenuBeta,BrowserRouter,WorkSites,main}.swift -o "$PAYLOAD/Contents/MacOS/CorporateVPNRouter"
/usr/libexec/PlistBuddy -c 'Set :CFBundleVersion 8' "$PAYLOAD/Contents/Info.plist"
printf 'installer-fix.1\n' > "$PAYLOAD/Contents/Resources/INSTALLER_REVISION"
codesign --force --sign - --timestamp=none "$PAYLOAD"
codesign --verify --deep --strict "$PAYLOAD"
NEW_CDHASH=$(codesign -dvvv "$PAYLOAD" 2>&1 | sed -n 's/^CDHash=//p')
python3 - "$NEW_CDHASH" "$WORK/PayloadRequirement.swift" <<'PYREQ'
import json, re, sys
assert re.fullmatch('[0-9a-f]{40}', sys.argv[1]), 'Missing payload CDHash'
with open(sys.argv[2], 'w') as out:
    out.write('let payloadRequirement = ' + json.dumps('cdhash H"' + sys.argv[1] + '"') + '\n')
PYREQ
cp scripts/dmg/Installer.swift "$WORK/main.swift"
swiftc -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" -framework AppKit Sources/InstallTransaction.swift "$WORK/PayloadRequirement.swift" "$WORK/main.swift" -o "$WORK/DistributionInstaller"
python3 scripts/dmg/bundle-manifest.py "$PAYLOAD" > "$SOURCE/Contents/Resources/Payload.manifest.json"
swiftc -swift-version 5 -O -module-cache-path "$PWD/.build/module-cache" -framework AppKit scripts/dmg/Artwork.swift -o "$WORK/Artwork"
"$WORK/Artwork" "$WORK/art"
iconutil -c icns "$WORK/art/Router.iconset" -o "$WORK/Router.icns"
iconutil -c icns "$WORK/art/Programs.iconset" -o "$WORK/Programs.icns"
cp "$WORK/art/background.png" "$STAGE/.background/"
BUNDLE="$SOURCE"
cp "$WORK/DistributionInstaller" "$BUNDLE/Contents/MacOS/DistributionInstaller"
cp "$WORK/Router.icns" "$BUNDLE/Contents/Resources/Distribution.icns"
python3 - "$BUNDLE/Contents/Info.plist" <<'PYINFO'
import plistlib, sys
info = dict(CFBundleIdentifier='com.geokhv.corporate-vpn-router.distribution.install-fix-1',
            CFBundleName='Установить Corporate VPN Router', CFBundleDisplayName='Установить Corporate VPN Router',
            CFBundleExecutable='DistributionInstaller', CFBundlePackageType='APPL', CFBundleIconFile='Distribution',
            CFBundleShortVersionString='0.2.0', CFBundleVersion='2', LSMinimumSystemVersion='13.0',
            LSUIElement=True, NSHighResolutionCapable=True)
with open(sys.argv[1], 'wb') as stream: plistlib.dump(info, stream)
PYINFO
codesign --force --sign - --timestamp=none "$BUNDLE"
codesign --verify --deep --strict "$BUNDLE"
# Verify all published VPN engine/runtime resources stayed byte-identical.
python3 - "$ORIGINAL/Contents/Resources" "$PAYLOAD/Contents/Resources" <<'PYRES'
import hashlib, sys
from pathlib import Path
old, new = map(Path, sys.argv[1:])
for source in old.rglob('*'):
    if source.is_file():
        target = new/source.relative_to(old)
        assert source.read_bytes() == target.read_bytes(), str(target)
PYRES
cp scripts/dmg/INSTALL.ru.txt "$STAGE/Установка и откат.txt"
cp LICENSE "$STAGE/.background/"
ditto "$WORK/unzip/$BASE/Licenses" "$STAGE/.background/Licenses"
cp "$WORK/Router.icns" "$STAGE/.VolumeIcon.icns"
hdiutil create -quiet -srcfolder "$STAGE" -volname 'Corporate VPN Router beta.6' -fs HFS+ -format UDRW "$WORK/layout.dmg"
mkdir -p "$MOUNT"
hdiutil attach -quiet -nobrowse -noautoopen -readwrite -mountpoint "$MOUNT" "$WORK/layout.dmg"
MOUNTED=1
SetFile -a C "$MOUNT"
python3 -B scripts/dmg/layout.py "$MOUNT"
test -s "$MOUNT/.DS_Store"
sync
hdiutil detach -quiet "$MOUNT"
MOUNTED=0
hdiutil convert -quiet "$WORK/layout.dmg" -format UDZO -imagekey zlib-level=9 -o "$WORK/$NAME.dmg"
hdiutil verify "$WORK/$NAME.dmg"
mv "$WORK/$NAME.dmg" "$DEST/$NAME.dmg"
(cd "$DEST" && shasum -a 256 "$NAME.dmg" > "$NAME.dmg.sha256")
echo "Built: $DEST/$NAME.dmg"
