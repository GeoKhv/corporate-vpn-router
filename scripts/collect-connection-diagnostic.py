#!/usr/bin/env python3
"""Collect only schema-filtered connection/UI metadata; never raw app logs."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import zipfile

os.umask(0o077)
app, destination = map(Path, sys.argv[1:])
destination.mkdir(mode=0o700, parents=True, exist_ok=False)
data = Path.home()/'Library/Application Support/Corporate VPN Router'
res = app/'Contents/Resources'
allowed = {'time','monotonic_ns','pid','ppid','phase','event','role','executable','python','executable_sha256',
           'connection','target','family','timeout','route','error_class','errno','local','peer','duration_ms',
           'child_pid','rc','version','code','failed_phase','attempt','budget_ms','allowance_ms','http_status','reusable'}
for path in (data/'Selective/ConnectionDiagnostics').glob('connections-*.jsonl'):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > 8*1024*1024:
        continue
    rows = []
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
            rows.append({k:v for k,v in row.items() if k in allowed})
        except ValueError:
            pass
    (destination/path.name).write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
for name in ('connection-events.jsonl','connection-events.previous.jsonl'):
    path = data/'Selective'/name
    if path.exists() and not path.is_symlink() and path.stat().st_size < 1024*1024:
        rows=[]
        for line in path.read_text().splitlines():
            try: row=json.loads(line)
            except ValueError: continue
            rows.append({k:v for k,v in row.items() if k in ('time','attempt','phase','component','event','code','errno')})
        (destination/name).write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
hashes={}
for name in ('Engine/session.py','Engine/trust.py','Engine/tls_policy.py','Engine/connection_trace.py',
             'RouteHelper/RouteClient','RouteHelper/RouteHelper','RouteHelper/sing-box'):
    hashes[name]=hashlib.sha256((res/name).read_bytes()).hexdigest()
p=subprocess.run([str(res/'RouteHelper/RouteClient')],input='{"op":"status"}\n',text=True,capture_output=True,timeout=8)
helper=json.loads(p.stdout)
report={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'hashes':hashes,
        'helper':{k:helper.get(k) for k in ('ok','version','active','cleanupPending')},
        'limitations':['OS route is not proof of VPN egress','No packet payload or authorization material collected']}
failure=helper.get('lastAdapterFailure')
if isinstance(failure,dict):
    fields={'schema','time','stage','elapsedMilliseconds','identityMilliseconds','interfaceIndex',
            'childPID','childRunning','waitStatus','waitErrno','processState','processInfoErrno','logSHA256'}
    report['helper']['lastAdapterFailure']={k:v for k,v in failure.items()
        if k in fields and (v is None or isinstance(v,(str,int,float,bool)))}
(destination/'summary.json').write_text(json.dumps(report,indent=2))
with zipfile.ZipFile(destination.with_suffix('.zip'),'x',zipfile.ZIP_DEFLATED) as archive:
    for path in destination.iterdir():
        archive.write(path,path.name)
print(destination.with_suffix('.zip'))
