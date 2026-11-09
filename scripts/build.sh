#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD_DIR="$PWD/.build"
APP="$(mktemp -d /private/tmp/cvr-app.XXXXXX)/Corporate VPN Router.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$BUILD_DIR/module-cache"
export CLANG_MODULE_CACHE_PATH="$BUILD_DIR/module-cache"
export SWIFT_MODULECACHE_PATH="$BUILD_DIR/module-cache"
swiftc -D CVR_MENU_BETA -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$BUILD_DIR/module-cache" \
  -framework AppKit Sources/{Core,MacOS,Lifecycle,BetaInstall,MenuBeta,main}.swift -o "$APP/Contents/MacOS/CorporateVPNRouter"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.geokhv.corporate-vpn-router</string>
<key>CFBundleName</key><string>Corporate VPN Router</string>
<key>CFBundleExecutable</key><string>CorporateVPNRouter</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.0</string>
<key>CFBundleVersion</key><string>2</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/python3 -B scripts/bundle.py "$APP/Contents/Resources"
cp VERSION "$APP/Contents/Resources/"
xattr -cr "$APP"
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"
"$APP/Contents/MacOS/CorporateVPNRouter" --version
printf '%s\n' "$APP" > "$BUILD_DIR/app-path.txt"
