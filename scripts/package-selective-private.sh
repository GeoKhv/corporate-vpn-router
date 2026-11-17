#!/bin/bash
# One Finder-visible .app only; no wrapper folder, readme or installer shell.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
APP="${1:?Pass the verified private TUN Trial app}"
VERSION=$([ -x "$APP/Contents/MacOS/CorporateVPNRouter" ] && "$APP/Contents/MacOS/CorporateVPNRouter" --version)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+$ ]]
DEST="$PWD/.private/selective-tun-build"
OUT="$DEST/Corporate-VPN-Router-$VERSION-private-arm64.zip"
mkdir -p "$DEST"
test ! -e "$OUT" || { echo 'Existing archive preserved.' >&2; exit 1; }
codesign --verify --deep --strict "$APP"
python3 scripts/normalize-code-modes.py --check "$APP"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$OUT"
python3 -B - "$OUT" <<'PY'
import hashlib,sys,zipfile
from pathlib import Path
path=Path(sys.argv[1])
with zipfile.ZipFile(path) as archive:
    roots={n.split('/')[0] for n in archive.namelist() if not n.startswith('__MACOSX/')}
assert roots=={'Corporate VPN Router TUN Trial.app'},roots
path.with_suffix('.zip.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
print(path)
print('PASS exactly one application at archive root')
PY
