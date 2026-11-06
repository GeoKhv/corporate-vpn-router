#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build.sh
VERSION=$(cat VERSION)
NAME="Corporate-VPN-Router-${VERSION}-macOS-arm64"
PACKAGE_DIR="$(mktemp -d /private/tmp/cvr-package.XXXXXX)"
trap 'rm -rf "$PACKAGE_DIR"' EXIT
STAGE="$PACKAGE_DIR/$NAME"
mkdir -p "$STAGE" dist
rm -rf "$STAGE/Corporate VPN Router.app"
APP=$(cat .build/app-path.txt)
ditto "$APP" "$STAGE/Corporate VPN Router.app"
xattr -cr "$STAGE/Corporate VPN Router.app"
codesign --verify --deep --strict "$STAGE/Corporate VPN Router.app"
cp packaging/Install.command packaging/Uninstall.command "$STAGE/"
cp README.md LICENSE "$STAGE/"
ditto docs "$STAGE/docs"
chmod +x "$STAGE/Install.command" "$STAGE/Uninstall.command"
ditto -c -k --norsrc --keepParent "$STAGE" "dist/$NAME.zip"
cd dist
shasum -a 256 "$NAME.zip" > SHA256SUMS.txt
printf '%s\n' "$NAME.zip"
