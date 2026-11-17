#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?helper output directory}"
PROFILE="${2:?approved private policy}"
mkdir -p "$OUT" .build/module-cache
swiftc -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" Sources/RouteHelper/{Protocol,Client}.swift -o "$OUT/RouteClient"
codesign --force --sign - --options runtime --timestamp=none "$OUT/RouteClient"
python3 - "$PROFILE" "$OUT" <<'PY'
import json,pathlib,re,subprocess,sys
sys.path.insert(0,'Backend/Selective')
from policy import validate_selective
cfg=validate_selective(json.loads(pathlib.Path(sys.argv[1]).read_text()))
out=pathlib.Path(sys.argv[2]);info=subprocess.run(['codesign','-dvvv',str(out/'RouteClient')],capture_output=True,text=True,check=True)
cdhash=re.search(r'^CDHash=([0-9a-f]{40})$',info.stderr,re.M)[1]
constants='import Foundation\n'
for key,value in dict(helperBuild='0.3.0-alpha.3',clientCDHash=cdhash,adapterSHA256='6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2',approvedRDPHost='',approvedDomains=[r['domain'] for r in cfg['sites']],approvedPorts=cfg['ports']).items():
 constants+='let '+key+' = '+json.dumps(value)+'\n'
(out/'BuildPolicy.swift').write_text(constants)
PY
swiftc -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" Sources/RouteHelper/{Protocol,Daemon}.swift "$OUT/BuildPolicy.swift" -o "$OUT/RouteHelper"
codesign --force --sign - --options runtime --timestamp=none "$OUT/RouteHelper"
codesign --verify --strict "$OUT/RouteClient"
codesign --verify --strict "$OUT/RouteHelper"
