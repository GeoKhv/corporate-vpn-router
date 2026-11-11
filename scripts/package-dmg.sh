#!/bin/bash
# Build a DMG around the published beta.6 ZIP. Never rebuild the VPN application.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
VERSION=0.2.0-beta.6
ZIP_SHA=83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c
CDHASH=06684ffbb00baba39f611a7d20c9c643791e893d
NAME="Corporate-VPN-Router-$VERSION-macOS-arm64"
ZIP="${1:?Usage: scripts/package-dmg.sh /path/to/published-beta.6-macOS-arm64.zip}"
ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
DEST="${CVR_DIST_DIR:-$PWD/dist}"
mkdir -p "$DEST" .build/module-cache
DEST="$(cd "$DEST" && pwd)"
test "$(shasum -a 256 "$ZIP" | awk '{print $1}')" = "$ZIP_SHA" || { echo 'Published ZIP SHA-256 mismatch' >&2; exit 1; }
test ! -e "$DEST/$NAME.dmg" || { echo 'Refusing to overwrite an existing DMG; use a fresh CVR_DIST_DIR.' >&2; exit 1; }
WORK=$(mktemp -d /private/tmp/cvr-dmg.XXXXXX)
MOUNT="$WORK/Corporate VPN Router beta.6"
MOUNTED=0
cleanup() {
    if [[ "$MOUNTED" = 1 ]]; then hdiutil detach "$MOUNT" >/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
ditto -x -k "$ZIP" "$WORK/unzip"
ORIGINAL="$WORK/unzip/$NAME/Corporate VPN Router.app"
codesign --verify --deep --strict "-R=cdhash H\"$CDHASH\"" "$ORIGINAL"
test "$("$ORIGINAL/Contents/MacOS/CorporateVPNRouter" --version)" = "$VERSION"
STAGE="$WORK/stage"
SOURCE="$STAGE/Corporate VPN Router.app"
TARGET="$STAGE/Программы.app"
mkdir -p "$SOURCE/Contents/Resources/Payload" "$SOURCE/Contents/MacOS" "$TARGET/Contents/Resources" "$TARGET/Contents/MacOS" "$STAGE/.background"
ditto --norsrc "$ORIGINAL" "$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app"
python3 scripts/dmg/bundle-manifest.py "$ORIGINAL" > "$WORK/original.json"
python3 scripts/dmg/bundle-manifest.py "$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app" > "$WORK/copied.json"
cmp "$WORK/original.json" "$WORK/copied.json"
cp "$WORK/original.json" "$SOURCE/Contents/Resources/Payload.manifest.json"
swiftc -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" -framework AppKit scripts/dmg/Installer.swift -o "$WORK/DistributionInstaller"
swiftc -swift-version 5 -O -module-cache-path "$PWD/.build/module-cache" -framework AppKit scripts/dmg/Artwork.swift -o "$WORK/Artwork"
"$WORK/Artwork" "$WORK/art"
iconutil -c icns "$WORK/art/Router.iconset" -o "$WORK/Router.icns"
iconutil -c icns "$WORK/art/Programs.iconset" -o "$WORK/Programs.icns"
cp "$WORK/art/background.png" "$STAGE/.background/"
for ROLE in launcher programs; do
    if [[ "$ROLE" = launcher ]]; then BUNDLE="$SOURCE"; TITLE='Corporate VPN Router'; ICON=Router; else BUNDLE="$TARGET"; TITLE='Программы'; ICON=Programs; fi
    cp "$WORK/DistributionInstaller" "$BUNDLE/Contents/MacOS/DistributionInstaller"
    cp "$WORK/$ICON.icns" "$BUNDLE/Contents/Resources/Distribution.icns"
    python3 - "$BUNDLE/Contents/Info.plist" "$ROLE" "$TITLE" <<'PY'
import plistlib, sys
info = dict(CFBundleIdentifier='com.geokhv.corporate-vpn-router.distribution.' + sys.argv[2],
            CFBundleName=sys.argv[3], CFBundleDisplayName=sys.argv[3], CFBundleExecutable='DistributionInstaller',
            CFBundlePackageType='APPL', CFBundleIconFile='Distribution', CFBundleShortVersionString='0.2.0',
            CFBundleVersion='1', LSMinimumSystemVersion='13.0', LSUIElement=True, NSHighResolutionCapable=True,
            CFBundleDocumentTypes=[dict(CFBundleTypeName='Application', CFBundleTypeRole='Viewer',
                                       LSHandlerRank='None', LSItemContentTypes=['com.apple.application-bundle'])])
with open(sys.argv[1], 'wb') as stream: plistlib.dump(info, stream)
PY
    # Sign only the new distribution shell, WITHOUT --deep or touching the VPN payload.
    codesign --force --sign - --timestamp=none "$BUNDLE"
    codesign --verify --deep --strict "$BUNDLE"
done
codesign --verify --deep --strict "-R=cdhash H\"$CDHASH\"" "$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app"
python3 scripts/dmg/bundle-manifest.py "$SOURCE/Contents/Resources/Payload/Corporate VPN Router.app" > "$WORK/final.json"
cmp "$WORK/original.json" "$WORK/final.json"
cp scripts/dmg/INSTALL.ru.txt "$STAGE/Установка и откат.txt"
cp LICENSE "$STAGE/.background/"
ditto "$WORK/unzip/$NAME/Licenses" "$STAGE/.background/Licenses"
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
