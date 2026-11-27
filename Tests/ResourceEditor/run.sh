#!/bin/bash
set -euo pipefail
if [[ $# != 1 ]]; then
  echo "Usage: bash Tests/ResourceEditor/run.sh /path/to/Corporate\ VPN\ Router.app" >&2
  exit 2
fi
app=$(cd "$1" && pwd)
cd "$(dirname "$0")/../.."
mkdir -p .build/module-cache
scratch=$(mktemp -d /private/tmp/cvr-resource-editor.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
fixture="$scratch/ResourceEditor.app/Contents"
mkdir -p "$fixture/MacOS"
python3 - "$app/Contents" "$fixture" <<'PY'
import plistlib
import sys
from pathlib import Path

payload, fixture = map(Path, sys.argv[1:])
info = plistlib.loads((payload / 'Info.plist').read_bytes())
info.update(CFBundleExecutable='ResourceEditor', CFBundleIdentifier='local.router.tests.resource-editor')
(fixture / 'Info.plist').write_bytes(plistlib.dumps(info))
PY
sources=()
for file in Sources/*.swift; do
  case "$file" in Sources/main.swift|Sources/UI.swift) continue ;; esac
  sources+=("$file")
done
swiftc -D CVR_MENU_BETA -D CVR_DEMO_SINGLE -D CVR_SELECTIVE_TUN -D CVR_UPDATES \
  -swift-version 5 -Onone -target arm64-apple-macos13.0 -module-cache-path .build/module-cache \
  -F "$app/Contents/Frameworks" -framework Sparkle -framework AppKit -framework Network -framework Security \
  -Xlinker -rpath -Xlinker "$app/Contents/Frameworks" "${sources[@]}" Tests/ResourceEditor/main.swift \
  -o "$fixture/MacOS/ResourceEditor"
"$fixture/MacOS/ResourceEditor" "$app/Contents/Resources"
"$fixture/MacOS/ResourceEditor" "$app/Contents/Resources" --first-profile
