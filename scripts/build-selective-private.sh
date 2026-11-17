#!/bin/bash
# One local private application candidate. No download, upload or release.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
BASE="${1:?published beta.6 ZIP}"
PROFILE="${2:?private sites JSON}"
MAP="${3:?preserved durable map JSON}"
ADDITIONS="${4:-}"
DEST="$PWD/.private/selective-tun-build"
APP="/private/tmp/cvr-selective-candidate-0.3.0-alpha.5/Corporate VPN Router TUN Trial.app"
test "$(shasum -a 256 "$BASE" | awk '{print $1}')" = 83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c
mkdir -p "$DEST" .build/module-cache
WORK=$(mktemp -d /private/tmp/cvr-tun-build.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
ditto -x -k "$BASE" "$WORK/base"
ORIGINAL="$WORK/base/Corporate-VPN-Router-0.2.0-beta.6-macOS-arm64/Corporate VPN Router.app"
codesign --verify --deep --strict '-R=cdhash H"06684ffbb00baba39f611a7d20c9c643791e893d"' "$ORIGINAL"
test ! -e "$APP" || { echo 'Candidate already exists; preserve its evidence before rebuilding.' >&2; exit 1; }
ditto "$ORIGINAL" "$APP"
swiftc -D CVR_MENU_BETA -D CVR_DEMO_SINGLE -D CVR_SELECTIVE_TUN -swift-version 5 -O -target arm64-apple-macos13.0 -module-cache-path "$PWD/.build/module-cache" -framework AppKit -framework Network -framework Security Sources/{Core,MacOS,DNS,Lifecycle,InstallTransaction,FirstLaunch,BetaInstall,MenuComponents,OfficialGUI,MenuBeta,BrowserRouter,WorkSites,SelectiveRouter,ConnectionFlow,Certificates,CertificatePlan,CertificateWizard,TLSProbe,Diagnostics,main}.swift -o "$APP/Contents/MacOS/CorporateVPNRouter"
mkdir -p "$APP/Contents/Resources/Engine/Selective" "$APP/Contents/Resources/SelectiveAdapter"
cp Backend/Selective/*.py "$APP/Contents/Resources/Engine/Selective/"
rm "$APP/Contents/Resources/Engine/Selective/network.py"
mkdir -p "$APP/Contents/Resources/RouteHelper"
# Keep the network broker boundary unchanged; retain the exact enrolled client signature and broker.
# Recompiling the client changes its cdhash and would force an admin reinstall.
python3 - "$DEST/Corporate-VPN-Router-0.3.0-alpha.3-private-arm64.zip" "$PROFILE" "$APP/Contents/Resources/RouteHelper" <<'PY'
import hashlib,json,os,sys,zipfile
from pathlib import Path
archive,profile,out=map(Path,sys.argv[1:])
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='9ee19ef8ca3203d80222b5c91d185e9b8c7cea392d4c196a6f76ad71db1403df'
base='Corporate VPN Router TUN Trial.app/Contents/Resources/'
with zipfile.ZipFile(archive) as z:
 assert json.loads(z.read(base+'DefaultWorkSites.json'))==json.loads(profile.read_text()),'Helper policy changed: rebuild and version the broker explicitly'
 for name in ['RouteClient','RouteHelper']:
  target=out/name;target.write_bytes(z.read(base+'RouteHelper/'+name));target.chmod(0o755)
print('Exact alpha.3 helper/client retained; existing enrollment remains valid')
PY
cp Backend/checkpoint_diagnostic.py "$APP/Contents/Resources/Engine/"
cp Backend/support_report.py "$APP/Contents/Resources/Engine/"
python3 scripts/report_terms.py "$APP/Contents/Resources/ReportTerms.json"
cp "scripts/Check Check Point.command" "$APP/Contents/Resources/"
cp Backend/trust.py "$APP/Contents/Resources/Engine/trust.py"
cp Backend/session.py "$APP/Contents/Resources/Engine/session.py"
cp Backend/{tls_policy,connection_resilience,connection_trace}.py "$APP/Contents/Resources/Engine/"
cp "$PWD/.private/alpha5-evidence/ApprovedGateway.json" "$APP/Contents/Resources/ApprovedGateway.json"
python3 - "$PWD/.private/alpha5-evidence/certificates" "$APP/Contents/Resources" <<'PYCA'
import hashlib,json,shutil,sys
from pathlib import Path
src,res=map(Path,sys.argv[1:]);manifest=json.loads((src/'manifest.json').read_text())
assert manifest['schema']==1 and manifest['provenance']=='OWNER_APPROVED_EXISTING_KEYCHAIN_AND_VERIFIED_CHAIN'
out=res/'ApprovedCertificates';out.mkdir()
for row in manifest['certificates']:
 sha=row['sha256'].replace(':','').upper();assert row['file']==sha+'.cer'
 cert=src/row['file'];assert hashlib.sha256(cert.read_bytes()).hexdigest().upper()==sha
 shutil.copy2(cert,out/row['file'])
shutil.copy2(src/'manifest.json',out/'manifest.json')
hosts=sorted({h for r in manifest['certificates'] for h in r['hosts']})
(res/'CertificateEndpoints.json').write_text(json.dumps({'hosts':hosts}))
gateway=json.loads((res/'ApprovedGateway.json').read_text());assert gateway['schema']==1 and len(gateway['receipt']['ca_sha256'])==64
print('Private approved gateway and public CA fingerprints verified; no identities or private keys bundled')
PYCA
# Reuse the existing Router artwork, now inside the app itself (not just DMG).
cp Resources/Router.icns "$APP/Contents/Resources/Router.icns"
UPSTREAM="$PWD/.private/selective-tun-20261111/upstream/sing-box-1.14.4-darwin-arm64"
test "$(shasum -a 256 "$UPSTREAM/sing-box" | awk '{print $1}')" = 6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2
cp "$UPSTREAM/sing-box" "$UPSTREAM/LICENSE" "$APP/Contents/Resources/SelectiveAdapter/"
cp "$UPSTREAM/sing-box" "$APP/Contents/Resources/RouteHelper/"
printf '%s\n' 6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2 > "$APP/Contents/Resources/SelectiveAdapter/SHA256"
printf '%s\n' 'sing-box v1.14.4, unmodified official darwin-arm64 binary.' 'https://github.com/SagerNet/sing-box/tree/v1.14.4' 'https://github.com/SagerNet/sing-box/archive/refs/tags/v1.14.4.tar.gz' > "$APP/Contents/Resources/SelectiveAdapter/SOURCE.txt"
python3 - "$PROFILE" "$MAP" "$APP/Contents/Resources" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'Backend/Selective')
from policy import validate_selective
from domain_map import DomainMap
cfg=validate_selective(json.loads(Path(sys.argv[1]).read_text()))
registry=DomainMap(sys.argv[2]); target=Path(sys.argv[3])
assert all(any(n==r['domain'] or n.endswith('.'+r['domain']) for r in cfg['sites']) for n in registry.names)
(target/'DefaultWorkSites.json').write_text(json.dumps(cfg,ensure_ascii=False,indent=2))
(target/'DefaultDomainMap.json').write_bytes(Path(sys.argv[2]).read_bytes())
print('Private defaults validated; credentials and session state excluded')
PY
if [[ -n "$ADDITIONS" ]]; then
python3 -B - "$ADDITIONS" "$PROFILE" "$APP/Contents/Resources/WorkSiteAdditions.json" <<'PY'
import json,re,sys
from pathlib import Path
sys.path.insert(0,'Backend/Selective')
from policy import validate_selective
v=json.loads(Path(sys.argv[1]).read_text());cfg=validate_selective(json.loads(Path(sys.argv[2]).read_text()))
assert set(v)=={'version','id','sites'} and v['version']==1 and re.fullmatch('[a-z0-9-]{1,64}',v['id'])
validate_selective(dict(version=1,sites=v['sites'],beforeLogin=[],ports=[443]))
assert all(rule in cfg['sites'] for rule in v['sites'])
Path(sys.argv[3]).write_text(json.dumps(v,ensure_ascii=False,indent=2))
print('Explicit private work-site addition validated')
PY
fi
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier com.geokhv.corporate-vpn-router.tun-trial' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleDisplayName string Corporate VPN Router TUN Trial' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleName Corporate VPN Router TUN Trial' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleShortVersionString 0.3.0' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleVersion 16' "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIconFile string Router.icns' "$APP/Contents/Info.plist"
printf '0.3.0-alpha.5-private\n' > "$APP/Contents/Resources/INSTALLER_REVISION"
python3 scripts/normalize-code-modes.py "$APP"
codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"
python3 - "$ORIGINAL/Contents/Resources" "$APP/Contents/Resources" <<'PY'
from pathlib import Path
import sys
old,new=map(Path,sys.argv[1:])
for p in old.rglob('*'):
 if p.is_file() and p.relative_to(old).as_posix() not in {'Engine/trust.py','Engine/session.py','Engine/tls_policy.py'}:
  assert p.read_bytes()==(new/p.relative_to(old)).read_bytes(),p.name
# TLS/pin and authentication remain strict; only fixed first-use approval and status milestones change.
import ast
def funcs(path):
 tree=ast.parse(path.read_text())
 return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,ast.FunctionDef)}
before,after=funcs(old/'Engine/trust.py'),funcs(new/'Engine/trust.py')
assert {k:v for k,v in before.items() if k not in {'official_info','anchor','preapproved'}}=={k:v for k,v in after.items() if k not in {'official_info','anchor','preapproved'}}
if 'preapproved' in before:assert before['preapproved']==after['preapproved']
before,after=funcs(old/'Engine/session.py'),funcs(new/'Engine/session.py')
assert {k:v for k,v in before.items() if k not in {'main','dataplane','request'}}=={k:v for k,v in after.items() if k not in {'main','dataplane','request'}}
old_tls,new_tls=funcs(old/'Engine/tls_policy.py'),funcs(new/'Engine/tls_policy.py')
for name in ('pinned_context','require_strict'):assert old_tls[name]==new_tls[name]
# Exact prompt addition: release the optional control connection before input.
prompt=next(n for n in ast.parse((new/'Engine/session.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='request')
assert ast.dump(prompt.body.pop(0),include_attributes=False)==ast.dump(ast.parse('close_control()').body[0],include_attributes=False)
assert ast.dump(prompt,include_attributes=False)==before['request']
# Dataplane edits may add milestones and retain the pre-cleanup failure stage;
# strip only that exact telemetry, then require identical transport behavior.
class StripTelemetry(ast.NodeTransformer):
 def visit_Expr(self,node):
  if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='status':return None
  return self.generic_visit(node)
 def visit_ExceptHandler(self,node):
  if (isinstance(node.type,ast.Name) and node.type.id=='BaseException' and node.name is None
      and len(node.body)==2 and isinstance(node.body[1],ast.Raise)
      and ast.dump(node.body[0],include_attributes=False)==ast.dump(ast.parse("STATE.setdefault('failure_stage', STATE.get('stage'))").body[0],include_attributes=False)):
   return None
  return self.generic_visit(node)
def dataplane_behavior(path):
 node=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='dataplane')
 # Normalize only the explicit opt-in transport wrapper to its legacy branch.
 wrappers=[n for n in ast.walk(node) if isinstance(n,ast.AsyncFunctionDef) and n.name=='open_transport']
 if wrappers:
  assert len(wrappers)==1
  wrapper=wrappers[0];branch=wrapper.body[0]
  assert ast.dump(branch.test)==ast.dump(ast.parse('not RESILIENT',mode='eval').body)
  assert len(branch.body)==1 and isinstance(branch.body[0],ast.Return) and isinstance(branch.body[0].value,ast.Await)
  legacy=branch.body[0].value.value
  class LegacyBranch(ast.NodeTransformer):
   def visit_AsyncFunctionDef(self,n):
    return None if n.name=='open_transport' else self.generic_visit(n)
   def visit_Call(self,n):
    if isinstance(n.func,ast.Name) and n.func.id=='open_transport':
     assert not n.args and not n.keywords
     return legacy
    return self.generic_visit(n)
  node=LegacyBranch().visit(node)
 return ast.dump(StripTelemetry().visit(node),include_attributes=False)
assert dataplane_behavior(old/'Engine/session.py')==dataplane_behavior(new/'Engine/session.py')
assert not (new/'ConnectionResilience.json').exists(),'Use the separate private resilience preparer to enable the candidate'
print('Strict TLS/pin functions, legacy dataplane, auth helpers, native SOCKS and runtime audited; resilience remains opt-in')
PY
printf '%s\n' "$APP" > "$DEST/candidate-path.txt"
echo "Candidate: $APP"
