#!/usr/bin/env python3
"""Fail closed before publishing a generic update, including embedded binaries/archives."""
import argparse,hashlib,io,json,re,zipfile,plistlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('app',type=Path);p.add_argument('--private-reference',type=Path,required=True);a=p.parse_args()
res=a.private_reference/'Contents/Resources'; forbidden=[]
for name in ['DefaultWorkSites.json','ApprovedGateway.json','DefaultDomainMap.json','CertificateEndpoints.json','ApprovedCertificates/manifest.json']:
 v=json.loads((res/name).read_text())
 def visit(x):
  if isinstance(x,dict):
   for k,y in x.items():
    if k in ('site','ip','cn','domain','subject'):forbidden.append(str(y).encode())
    visit(y)
  elif isinstance(x,list):
   for y in x:visit(y)
 visit(v)
# Include names allocated in the durable map, including hosts absent from root rules.
for name in json.loads((res/'DefaultDomainMap.json').read_text())['names']:forbidden.append(name.encode())
forbidden += [b'alfabank.ru',b'alfa-bank',b'/Users/alfa/',b'/Users/geo/',b'BEGIN PRIVATE KEY',b'BEGIN OPENSSH PRIVATE KEY',b'ghp_',b'github_pat_']
forbidden=list(set(s.lower() for s in forbidden if len(s)>4))
bad=[];count=0
def scan(name,data):
 global count
 count+=1;lower=data.lower()
 if any(s in lower for s in forbidden):bad.append(name)
 if zipfile.is_zipfile(io.BytesIO(data)):
  with zipfile.ZipFile(io.BytesIO(data)) as z:
   for n in z.namelist():
    if not n.endswith('/'):scan(name+'!'+n,z.read(n))
for path in a.app.rglob('*'):
 if path.is_file() and not path.is_symlink():scan(str(path.relative_to(a.app)),path.read_bytes())
for name in ['ApprovedGateway.json','ApprovedCertificates','DefaultWorkSites.json','DefaultDomainMap.json','WorkSiteAdditions.json','CertificateEndpoints.json','RouteHelper/RouteHelper']:
 if (a.app/'Contents/Resources'/name).exists():bad.append('forbidden resource: '+name)
d=plistlib.loads((a.app/'Contents/Info.plist').read_bytes())
assert d['SURequireSignedFeed'] and d['SUVerifyUpdateBeforeExtraction'] and not d['SUAllowsAutomaticUpdates']
assert d['SUFeedURL'].startswith('https://github.com/GeoKhv/corporate-vpn-router/')
print(json.dumps({'filesScannedIncludingNestedZip':count,'forbiddenMatches':sorted(set(bad)),'passed':not bad},indent=2))
raise SystemExit(bool(bad))
