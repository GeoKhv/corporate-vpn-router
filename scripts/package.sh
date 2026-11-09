#!/bin/bash
# Package the exact signed bundle that has passed local acceptance.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(cat VERSION)
NAME="Corporate-VPN-Router-${VERSION}-macOS-arm64"
APP=$(cat .build/app-path.txt)
test "$("$APP/Contents/MacOS/CorporateVPNRouter" --version)" = "$VERSION"
codesign --verify --deep --strict "$APP"
WORK=$(mktemp -d /private/tmp/cvr-package.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/$NAME"
mkdir -p "$STAGE" dist
ditto --norsrc "$APP" "$STAGE/Corporate VPN Router.app"
codesign --verify --deep --strict "$STAGE/Corporate VPN Router.app"
cp README.md LICENSE "packaging/Restore beta.2.command" "$STAGE/"
ditto docs "$STAGE/docs"
ditto ThirdParty/licenses "$STAGE/Licenses"
cp ThirdParty/README.md "$STAGE/Licenses/COMPONENTS.md"
ditto -c -k --norsrc --keepParent "$STAGE" "$WORK/$NAME.zip"
mv -f "$WORK/$NAME.zip" "dist/$NAME.zip"
(cd dist && shasum -a 256 "$NAME.zip" > SHA256SUMS.txt)
