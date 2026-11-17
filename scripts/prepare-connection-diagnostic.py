#!/usr/bin/env python3
"""Reproduce a private diagnostic app from the exact alpha.5 ZIP; no install."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

os.umask(0o077)
bundle = Path(__file__).resolve().parent
archive, target = map(lambda v: Path(v).resolve(), sys.argv[1:])
if hashlib.sha256(archive.read_bytes()).hexdigest() != '2c158353e7f440c968e401f9582844f34d36aa10bf63c9620d4ce8cb93e0659d':
    raise SystemExit('BASE_ALPHA5_HASH_MISMATCH')
if target.exists():
    raise SystemExit('TARGET_EXISTS_PRESERVE_IT')
manifest = json.loads((bundle/'payload-sha256.json').read_text())
for name, digest in manifest.items():
    if Path(name).name != name or hashlib.sha256((bundle/name).read_bytes()).hexdigest() != digest:
        raise SystemExit('PAYLOAD_HASH_MISMATCH')
target.mkdir(parents=True, mode=0o700)
subprocess.run(['/usr/bin/ditto','-x','-k',str(archive),str(target)], check=True)
app = target/'Corporate VPN Router TUN Trial.app'
# The historical ZIP contains Finder metadata. Strip only those two metadata
# attributes from this disposable extracted copy, never quarantine or trust.
for attr in ('com.apple.FinderInfo','com.apple.ResourceFork'):
    subprocess.run(['/usr/bin/xattr','-r','-d',attr,str(app)],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)], check=True)
res = app/'Contents/Resources'
for name in ('session.py','connection_trace.py'):
    shutil.copyfile(bundle/name, res/'Engine'/name)
(res/'ConnectionDiagnostic.json').write_text(json.dumps({'schema':1,'base':'alpha.5','diagnostic':'connection-metadata.1'}))
(res/'INSTALLER_REVISION').write_text('0.3.0-alpha.5-private-connection-diagnostic.1\n')
subprocess.run(['/usr/bin/codesign','--force','--sign','-','--timestamp=none',str(app)], check=True)
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)], check=True)
print(app)
