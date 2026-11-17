#!/usr/bin/env python3
"""Fail closed before publishing a generic update, including embedded binaries/archives."""
import argparse,hashlib,io,json,re,zipfile,plistlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('app',type=Path);p.add_argument('--private-reference',type=Path,required=True);p.add_argument('--rdp-host')
p.add_argument('--public-desktop',help='Exact DNS name explicitly approved for DefaultDesktop.json in this release only')
p.add_argument('--public-site-pin',type=Path,help='Exact reviewed site pin approved for publication in this release')
a=p.parse_args()
pin_resource='Contents/Resources/ApprovedSitePin.json'
pin_bytes=a.public_site_pin.read_bytes() if a.public_site_pin else None
desktop_resource='Contents/Resources/DefaultDesktop.json'
approved_bytes=None
if a.public_desktop:
 labels=a.public_desktop.split('.')
 if len(labels)<2 or len(a.public_desktop)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels) or not any(c.isalpha() for c in labels[-1]):
  p.error('Expected a canonical DNS name for --public-desktop')
 approved_bytes=(json.dumps({'desktop':a.public_desktop},sort_keys=True)+'\n').encode('ascii')
res=a.private_reference/'Contents/Resources'; forbidden=[]
refs=['DefaultWorkSites.json','ApprovedGateway.json','DefaultDomainMap.json','CertificateEndpoints.json','ApprovedCertificates/manifest.json']
if (res/'ApprovedSitePin.json').exists():refs.append('ApprovedSitePin.json')
for name in refs:
 v=json.loads((res/name).read_text())
 def visit(x):
  if isinstance(x,dict):
   for k,y in x.items():
    if k in ('site','ip','cn','domain','subject','leaf_sha256') or (name=='ApprovedSitePin.json' and k=='ca_sha256'):forbidden.append(str(y).encode())
    visit(y)
  elif isinstance(x,list):
   for y in x:visit(y)
 visit(v)
# Include names allocated in the durable map, including hosts absent from root rules.
for name in json.loads((res/'DefaultDomainMap.json').read_text())['names']:forbidden.append(name.encode())
if a.rdp_host:forbidden.append(a.rdp_host.encode('ascii'))
if a.public_desktop:forbidden.append(a.public_desktop.encode('ascii'))
forbidden += [b'BEGIN PRIVATE KEY',b'BEGIN OPENSSH PRIVATE KEY',b'ghp_',b'github_pat_']
# Known private names must not leave the machine as reversible dictionary fingerprints either.
for value in forbidden.copy():
 digest=hashlib.sha256(value.lower()).digest()
 forbidden.extend([digest,digest.hex().encode()])
forbidden=list(set(s.lower() for s in forbidden if len(s)>4))
bad=[];count=0
def scan(name,data):
 global count
 count+=1;lower=data.lower()
 if name==pin_resource and pin_bytes is not None:
  if data!=pin_bytes:bad.append(name)
  return
 if name==desktop_resource and approved_bytes is not None:
  if data!=approved_bytes:bad.append(name)
  return
 if any(s in lower for s in forbidden) or re.search(rb'/Users/[A-Za-z0-9_.-]+/',data):bad.append(name)
 if zipfile.is_zipfile(io.BytesIO(data)):
  with zipfile.ZipFile(io.BytesIO(data)) as z:
   for n in z.namelist():
    if not n.endswith('/'):scan(name+'!'+n,z.read(n))
for path in a.app.rglob('*'):
 if path.is_file() and not path.is_symlink():scan(str(path.relative_to(a.app)),path.read_bytes())
desktop=a.app/desktop_resource
if approved_bytes is None:
 if desktop.exists() or desktop.is_symlink():bad.append('forbidden resource: DefaultDesktop.json')
elif not desktop.is_file() or desktop.is_symlink():
 bad.append('missing or linked DefaultDesktop.json')
for name in ['ApprovedGateway.json','ApprovedSitePin.json','ApprovedCertificates','DefaultWorkSites.json','DefaultDomainMap.json','WorkSiteAdditions.json','CertificateEndpoints.json','RouteHelper/RouteGrants.json','RouteHelper/LocalPolicy.json']:
 if name=='ApprovedSitePin.json' and pin_bytes is not None:
  path=a.app/pin_resource
  if not path.is_file() or path.is_symlink():bad.append('missing or linked site pin')
  continue
 if (a.app/'Contents/Resources'/name).exists():bad.append('forbidden resource: '+name)
d=plistlib.loads((a.app/'Contents/Info.plist').read_bytes())
helper=a.app/'Contents/Resources/RouteHelper/RouteHelper'
if helper.exists():
 assert hashlib.sha256(helper.read_bytes()).hexdigest()==d['CVRRouteHelperSHA256']
 assert b'LOCAL_POLICY_MISSING' in helper.read_bytes()
 assert hashlib.sha256(helper.with_name('sing-box').read_bytes()).hexdigest()=='6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2'
assert d['SURequireSignedFeed'] and d['SUVerifyUpdateBeforeExtraction'] and not d['SUAllowsAutomaticUpdates']
assert d['SUFeedURL'].startswith('https://github.com/GeoKhv/corporate-vpn-router/')
print(json.dumps({'filesScannedIncludingNestedZip':count,'forbiddenMatches':sorted(set(bad)),'passed':not bad},indent=2))
raise SystemExit(bool(bad))
