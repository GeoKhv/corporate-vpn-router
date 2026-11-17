#!/bin/bash
# Private colleague ZIP. No uploads, installer shell, downloads or paid services.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
ZIP="${1:?Usage: scripts/package-demo.sh published-beta6.zip private.cvrprofile}"
PROFILE="${2:?Pass a private, schema-only work-sites profile}"
DEST="$PWD/.private/demo-20261112"
mkdir -p "$DEST" .build/module-cache
test "$(shasum -a 256 "$ZIP" | awk '{print $1}')" = 83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c
OUT="$DEST/Corporate-VPN-Router-0.2.0-beta.6-demo.2-private-arm64.zip"
test ! -e "$OUT" || { echo 'Existing ZIP preserved; move it aside explicitly before rebuilding.' >&2; exit 1; }
WORK=$(mktemp -d /private/tmp/cvr-demo.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
ditto -x -k "$ZIP" "$WORK/base"
ORIGINAL="$WORK/base/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64/Corporate VPN Router.app"
codesign --verify --deep --strict '-R=cdhash H"06684ffbb00baba39f611a7d20c9c643791e893d"' "$ORIGINAL"
APP="$WORK/Corporate VPN Router.app"
ditto "$ORIGINAL" "$APP"
swiftc -D CVR_MENU_BETA -D CVR_DEMO_SINGLE -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" -framework AppKit Sources/{Core,MacOS,Lifecycle,InstallTransaction,BetaInstall,MenuComponents,OfficialGUI,MenuBeta,BrowserRouter,WorkSites,main}.swift -o "$APP/Contents/MacOS/CorporateVPNRouter"
python3 - "$PROFILE" "$APP/Contents/Resources/DefaultWorkSites.json" <<'PY'
import json,sys
sys.path.insert(0,'Backend')
from sites import validate
# Strict allowlist rejects credentials, gateway receipts, pins, cookies and tokens.
cfg=validate(json.load(open(sys.argv[1])))
with open(sys.argv[2],'w') as out: json.dump(cfg,out,ensure_ascii=False,indent=2)
print('Bundled profile:',len(cfg['sites']),'sites;',len(cfg['beforeLogin']),'exceptions; no extra fields')
PY
/usr/libexec/PlistBuddy -c 'Set :CFBundleVersion 10' "$APP/Contents/Info.plist"
printf 'demo.2-private\n' > "$APP/Contents/Resources/INSTALLER_REVISION"
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"
python3 - "$ORIGINAL/Contents/Resources" "$APP/Contents/Resources" <<'PY'
from pathlib import Path
import sys
old,new=map(Path,sys.argv[1:])
for p in old.rglob('*'):
 if p.is_file(): assert p.read_bytes()==(new/p.relative_to(old)).read_bytes(),p.name
assert {str(p.relative_to(new)) for p in new.rglob('*') if p.is_file()}-{str(p.relative_to(old)) for p in old.rglob('*') if p.is_file()}=={'DefaultWorkSites.json','INSTALLER_REVISION'}
print('All original VPN engine, native worker, TLS/MFA/DNS code and runtime bytes preserved')
PY
ditto -c -k --sequesterRsrc --keepParent "$APP" "$OUT"
(cd "$DEST" && shasum -a 256 "$(basename "$OUT")" > "$(basename "$OUT").sha256")
printf '%s\n' "$APP" > "$DEST/build-source-path.txt"
echo "Built private ZIP: $OUT"
