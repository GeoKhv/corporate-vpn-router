#!/usr/bin/env python3
"""Build a private bootstrap or a corporate-data-free Sparkle update locally."""
import argparse, hashlib, json, os, plistlib, re, shutil, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--base-app',type=Path,required=True);p.add_argument('--sparkle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--version',required=True);p.add_argument('--build',type=int,required=True);p.add_argument('--private',action='store_true');a=p.parse_args()
assert re.fullmatch(r'\d+\.\d+\.\d+',a.version)
assert not a.output.exists(),'Never overwrite an existing release'
os.umask(0o077)
app=a.output/'Corporate VPN Router TUN Trial.app';res=app/'Contents/Resources'
def run(*args):subprocess.run([str(x) for x in args],check=True)
run('codesign','--verify','--deep','--strict',a.base_app)
run('ditto',a.base_app,app)
framework=app/'Contents/Frameworks/Sparkle.framework';framework.parent.mkdir(exist_ok=True)
run('ditto',a.sparkle/'Sparkle.framework',framework)
sources='Core MacOS DNS Lifecycle InstallTransaction BetaInstall MenuComponents OfficialGUI MenuBeta BrowserRouter WorkSites SelectiveRouter ConnectionFlow Certificates CertificatePlan CertificateWizard TLSProbe Diagnostics Provisioning Updates main'.split()
run('swiftc','-D','CVR_MENU_BETA','-D','CVR_DEMO_SINGLE','-D','CVR_SELECTIVE_TUN','-D','CVR_UPDATES','-swift-version','5','-O','-target','arm64-apple-macos13.0','-module-cache-path',ROOT/'.build/module-cache','-F',a.sparkle,'-framework','Sparkle','-Xlinker','-rpath','-Xlinker','@executable_path/../Frameworks','-framework','AppKit','-framework','Network','-framework','Security',*[ROOT/'Sources'/(s+'.swift') for s in sources],'-o',app/'Contents/MacOS/CorporateVPNRouter')
# The proven resilience implementation is retained; no authentication replay.
for name in ['session.py','tls_policy.py','connection_resilience.py','connection_trace.py']:
 assert (ROOT/'Backend'/name).read_bytes()==(res/'Engine'/name).read_bytes(),name
shutil.copy2(ROOT/'Backend/trust.py',res/'Engine/trust.py')
shutil.copy2(ROOT/'Backend/Selective/controller.py',res/'Engine/Selective/controller.py')
assert (res/'ConnectionResilience.json').is_file()
helper=res/'RouteHelper/RouteHelper'
helper_sha=hashlib.sha256(helper.read_bytes()).hexdigest() if helper.exists() else plistlib.loads((a.base_app/'Contents/Info.plist').read_bytes())['CVRRouteHelperSHA256']
if not a.private:
 for name in ['ApprovedGateway.json','ApprovedCertificates','CertificateEndpoints.json','DefaultWorkSites.json','DefaultDomainMap.json','WorkSiteAdditions.json','RouteHelper/RouteHelper','RouteHelper/sing-box','SelectiveAdapter/sing-box']:
  path=res/name
  if path.is_dir():shutil.rmtree(path)
  elif path.exists():path.unlink()
# No compile paths or signing private keys are included.
info=app/'Contents/Info.plist';d=plistlib.loads(info.read_bytes())
d.update(CFBundleShortVersionString=a.version,CFBundleVersion=str(a.build),LSMinimumSystemVersion='13.0',
 SUFeedURL='https://github.com/GeoKhv/corporate-vpn-router/releases/download/update-channel/appcast.xml',
 SUPublicEDKey=(ROOT/'packaging/updates/public-key.txt').read_text().strip(),
 SUEnableAutomaticChecks=True,SUAutomaticallyUpdate=False,SUAllowsAutomaticUpdates=False,
 SUScheduledCheckInterval=86400,SUEnableSystemProfiling=False,SUShowReleaseNotes=False,
 SUVerifyUpdateBeforeExtraction=True,SURequireSignedFeed=True,SUSignedFeedFailureExpirationInterval=0,
 CVRRouteHelperSHA256=helper_sha,CVRRouteHelperProtocol='0.3.0-alpha.3')
info.write_bytes(plistlib.dumps(d,sort_keys=True))
(res/'VERSION').write_text(a.version+'\n');(res/'INSTALLER_REVISION').write_text(a.version+'\n')
# Remove only Finder metadata from build copies; never quarantine or security policy.
subprocess.run(['xattr','-dr','com.apple.FinderInfo',str(app)],check=False)
run('codesign','--force','--sign','-','--timestamp=none',app)
run('codesign','--verify','--deep','--strict',app)
run(app/'Contents/MacOS/CorporateVPNRouter','--version')
print(app)
