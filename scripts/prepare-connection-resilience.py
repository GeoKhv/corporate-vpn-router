#!/usr/bin/env python3
"""Build a private resilience candidate from the exact alpha.5 ZIP. No install."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

os.umask(0o077)
bundle=Path(__file__).resolve().parent
archive,target=map(lambda v:Path(v).resolve(),sys.argv[1:])
if hashlib.sha256(archive.read_bytes()).hexdigest()!='2c158353e7f440c968e401f9582844f34d36aa10bf63c9620d4ce8cb93e0659d':
    raise SystemExit('BASE_ALPHA5_HASH_MISMATCH')
if target.exists():raise SystemExit('TARGET_EXISTS_PRESERVE_IT')
manifest=json.loads((bundle/'payload-sha256.json').read_text())
for name,digest in manifest.items():
    if Path(name).name!=name or hashlib.sha256((bundle/name).read_bytes()).hexdigest()!=digest:
        raise SystemExit('PAYLOAD_HASH_MISMATCH')
target.mkdir(parents=True,mode=0o700)
subprocess.run(['/usr/bin/ditto','-x','-k',str(archive),str(target)],check=True)
app=target/'Corporate VPN Router TUN Trial.app'
for attr in ('com.apple.FinderInfo','com.apple.ResourceFork'):
    subprocess.run(['/usr/bin/xattr','-r','-d',attr,str(app)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
res=app/'Contents/Resources'
retained=['RouteHelper/RouteHelper','RouteHelper/RouteClient','RouteHelper/sing-box','Runtime/bin/python3.13']
before={n:hashlib.sha256((res/n).read_bytes()).hexdigest() for n in retained}
for name in ('session.py','trust.py','tls_policy.py','connection_trace.py','connection_resilience.py'):
    shutil.copyfile(bundle/name,res/'Engine'/name)
(res/'ConnectionDiagnostic.json').write_text(json.dumps({'schema':1,'base':'alpha.5','diagnostic':'connection-metadata.1'}))
(res/'ConnectionResilience.json').write_text(json.dumps({'schema':1,'variant':'resilience.1','maxTcpDials':2,'tcpBudgetSeconds':10,'discoveryBudgetSeconds':12,'requestReplay':False}))
(res/'INSTALLER_REVISION').write_text('0.3.0-alpha.5-private-resilience.1\n')
subprocess.run(['/usr/bin/codesign','--force','--sign','-','--timestamp=none',str(app)],check=True)
subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True)
assert before=={n:hashlib.sha256((res/n).read_bytes()).hexdigest() for n in retained}
print(app)
