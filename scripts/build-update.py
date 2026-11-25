#!/usr/bin/env python3
"""Build a private bootstrap or a corporate-data-free Sparkle update locally."""
import argparse, hashlib, json, os, plistlib, re, shutil, subprocess, tempfile
import bundle
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--base-app',type=Path,required=True);p.add_argument('--sparkle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--version',required=True);p.add_argument('--build',type=int,required=True);p.add_argument('--private',action='store_true')
p.add_argument('--site-pin',type=Path,help='Previously verified alternate site and leaf/CA SHA-256 for a private starter')
p.add_argument('--rdp-host', help='Exact RDP destination to authorize when building from an enrolled starter')
p.add_argument('--deployment-desktop', help='Package a fixed DNS name for distribution to this deployment')
p.add_argument('--ipsec-bridge', type=Path, help='Explicitly opt this candidate into the reviewed unprivileged IPsec bridge')
p.add_argument('--bundled-rules', action='store_true', help='Include the reviewed deployment-specific rule migration')
p.add_argument('--starter-https-aliases', type=Path, help='Reviewed HTTPS aliases for an enrolled starter')
p.add_argument('--retire-starter-tree', help='Remove one unchanged legacy tree rule from the RED starter and migrate enrolled profiles')
p.add_argument('--credit', help='GitHub authors as shown in the version label, separated by comma and space')
a=p.parse_args()
edition = 'RED' if a.private else 'WHITE'
channel = 'update-channel' if a.private else 'update-channel-white'
# Preserve a starter's deployment manifest and its receipt identities on RED updates.
base_resources=a.base_app/'Contents/Resources'
if a.private and (base_resources/'StarterHTTPSAliases.json').is_file():
 a.starter_https_aliases=a.starter_https_aliases or base_resources/'StarterHTTPSAliases.json'
 a.bundled_rules=True
# Carry the enrolled RED desktop through subsequent builds from that signed edition.
previous_desktop=a.base_app/'Contents/Resources/DefaultDesktop.json'
if a.private and previous_desktop.is_file() and not (a.deployment_desktop or a.rdp_host):
 a.deployment_desktop=json.loads(previous_desktop.read_bytes())['desktop']
 a.rdp_host=a.deployment_desktop
if a.rdp_host and not a.private:p.error('--rdp-host requires --private')
if not a.private and (a.bundled_rules or a.site_pin or a.deployment_desktop):
 p.error('Bundled work rules, site pins and deployment desktops are RED-only (--private)')
if a.starter_https_aliases and not (a.private and a.bundled_rules):p.error('--starter-https-aliases requires --private and --bundled-rules')
if a.retire_starter_tree and not a.starter_https_aliases:p.error('--retire-starter-tree requires a starter alias manifest')
if a.credit and not re.fullmatch(r'[A-Za-z0-9-]{1,39}(, [A-Za-z0-9-]{1,39})*',a.credit):p.error('Expected GitHub logins separated by comma and space')
assert re.fullmatch(r'\d+\.\d+\.\d+',a.version)
assert not a.output.exists(),'Never overwrite an existing release'
os.umask(0o077)
app=a.output/'Corporate VPN Router TUN Trial.app';res=app/'Contents/Resources'
def run(*args):subprocess.run([str(x) for x in args],check=True)
run('codesign','--verify','--deep','--strict',a.base_app)
run('ditto',a.base_app,app)
if a.bundled_rules:
 shutil.copyfile(ROOT/'packaging/updates/BundledTCPRule.json',res/'BundledTCPRule.json')
else:
 (res/'BundledTCPRule.json').unlink(missing_ok=True)
(res/'StarterHTTPSAliases.json').unlink(missing_ok=True)
if a.starter_https_aliases:
 aliases=json.loads(a.starter_https_aliases.read_bytes())
 # Keep the original Superset migration identity for previously enrolled installations.
 retired=aliases.get('retiredTreeHost')
 if retired and a.retire_starter_tree and retired!=a.retire_starter_tree:p.error('Retirement identity changed')
 retired=retired or a.retire_starter_tree
 aliases={'hosts':aliases['hosts']}
 if retired:
  import sys
  sys.path.insert(0,str(ROOT/'Backend'))
  from sites import hostname
  if not hostname(retired) or retired in aliases['hosts']:p.error('Invalid retired starter host')
  default=res/'DefaultWorkSites.json'
  profile=json.loads(default.read_bytes())
  legacy={'domain':retired,'scope':'tree'}
  if legacy in profile['sites']:
   profile['sites'].remove(legacy)
   default.write_text(json.dumps(profile,ensure_ascii=False,indent=2)+'\n')
  elif a.retire_starter_tree and not json.loads(a.starter_https_aliases.read_bytes()).get('retiredTreeHost'):
   p.error('Legacy rule missing in base starter')
  aliases['retiredTreeHost']=retired
 for alias, field in [('superset','httpEntryHost'), ('ametrica','additionalHTTPEntryHost')]:
  matches=[host for host in aliases['hosts'] if host.split('.')[0]==alias]
  if len(matches)>1:p.error(f'Ambiguous {alias} alias in starter manifest')
  if matches:aliases[field]=matches[0]
 (res/'StarterHTTPSAliases.json').write_text(json.dumps(aliases,indent=2)+'\n')
framework=app/'Contents/Frameworks/Sparkle.framework';framework.parent.mkdir(exist_ok=True)
if (a.sparkle/'Sparkle.framework').resolve() != (a.base_app/'Contents/Frameworks/Sparkle.framework').resolve():
 run('ditto',a.sparkle/'Sparkle.framework',framework)
sources='Core MacOS DNS Lifecycle InstallTransaction FirstLaunch BetaInstall MenuComponents OfficialGUI MenuBeta BrowserRouter WorkSites SelectiveRouter ConnectionFlow Certificates CertificatePlan CertificateWizard TLSProbe Diagnostics Provisioning Updates main'.split()
run('swiftc','-D','CVR_MENU_BETA','-D','CVR_DEMO_SINGLE','-D','CVR_SELECTIVE_TUN','-D','CVR_UPDATES','-swift-version','5','-O','-target','arm64-apple-macos13.0','-module-cache-path',ROOT/'.build/module-cache','-F',a.sparkle,'-framework','Sparkle','-Xlinker','-rpath','-Xlinker','@executable_path/../Frameworks','-framework','AppKit','-framework','Network','-framework','Security',*[ROOT/'Sources'/(s+'.swift') for s in sources],'-o',app/'Contents/MacOS/CorporateVPNRouter')
assert (ROOT/'Backend/connection_trace.py').read_bytes()==(res/'Engine/connection_trace.py').read_bytes()
from report_terms import write_terms
write_terms(ROOT,res/'ReportTerms.json')
for name in ['trust.py','session.py','official_handoff.py','tls_policy.py','connection_resilience.py','browser_auth.py','sites.py','proxy_supervisor.py','support_report.py','checkpoint_diagnostic.py','http_router.py','gateway_disconnect.py','ipsec_session.py']:
 shutil.copy2(ROOT/'Backend'/name,res/'Engine'/name)
# Never silently inherit a test transport in a later normal build.
(res/'Engine/cvr-ipsec').unlink(missing_ok=True)
if a.ipsec_bridge:
 shutil.copy2(a.ipsec_bridge,res/'Engine/cvr-ipsec')
 (res/'Engine/cvr-ipsec').chmod(0o755)
 run('codesign','--force','--sign','-','--options','runtime','--timestamp=none',res/'Engine/cvr-ipsec')
 (res/'Licenses').mkdir(exist_ok=True)
 shutil.copy2(ROOT/'ThirdParty/ipsec-bridge/COPYING',res/'Licenses/IPsec-AGPL-3.txt')
 shutil.copy2(ROOT/'ThirdParty/ipsec-bridge/NOTICE.txt',res/'Licenses/IPsec-NOTICE.txt')
 # License documents need their contents, not source-folder extended attributes.
 # macOS may deny copying synced-folder metadata into the staged app.
 license_source = ROOT/'ThirdParty/ipsec-bridge/dependency-licenses'
 license_target = res/'Licenses/IPsec-dependencies'
 for source in sorted(license_source.rglob('*')):
  if source.is_symlink():raise ValueError('Linked dependency license is not allowed')
  destination=license_target/source.relative_to(license_source)
  if source.is_dir():
   destination.mkdir(parents=True,exist_ok=True);destination.chmod(0o755)
  elif source.is_file():
   destination.parent.mkdir(parents=True,exist_ok=True)
   destination.write_bytes(source.read_bytes());destination.chmod(0o644)
 license_target.chmod(0o755)
for name in ['controller.py','helper_client.py','services.py','policy.py','sparse_dns.py','analyze.py','system_dns_check.py']:
 shutil.copy2(ROOT/'Backend/Selective'/name,res/'Engine/Selective'/name)
# Do not inherit a host-only proxy from an older bootstrap.
bundle.CACHE.mkdir(parents=True,exist_ok=True)
bundle.native(res/'Engine/ocproxy')
run('codesign','--force','--sign','-','--timestamp=none',res/'Engine/ocproxy')
assert (res/'ConnectionResilience.json').is_file()
helper=res/'RouteHelper/RouteHelper'
portable_helper = not a.private or a.starter_https_aliases is not None
# Keep the enrolled RouteClient byte-for-byte. Its cdhash is the XPC peer identity.
if a.private:
 from sys import path as module_path
 module_path.insert(0,str(ROOT/'Backend'))
 if a.site_pin:
  from trust import read_site_pin
  pin=read_site_pin(a.site_pin)
  seed=json.loads((res/'ApprovedGateway.json').read_text())['receipt']
  if pin['site']==seed['site']:raise ValueError('Additional site must differ from the primary site')
  (res/'ApprovedSitePin.json').write_text(json.dumps(pin,sort_keys=True)+'\n')
 module_path.insert(0,str(ROOT/'Backend/Selective'))
 from policy import validate_selective
 policy=validate_selective(json.loads((res/'DefaultWorkSites.json').read_bytes()))
 from sites import rdp_host_for_profile
 if a.rdp_host and (3389 in policy['ports'] or not rdp_host_for_profile(policy,a.rdp_host)):
  p.error('The RDP host must be in the work profile, outside login exclusions, without a global 3389 rule')
client=helper.with_name('RouteClient')
run('codesign','--verify','--strict',client)
signature=subprocess.run(['codesign','-dvvv',client],capture_output=True,text=True,check=True).stderr
cdhash=re.search(r'^CDHash=([a-f0-9]{40})$',signature,re.M)[1]
adapter_hash=hashlib.sha256(helper.with_name('sing-box').read_bytes()).hexdigest()
assert adapter_hash=='6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2'
with tempfile.TemporaryDirectory() as scratch:
 constants=Path(scratch)/'BuildPolicy.swift'
 values=dict(helperBuild='0.3.0-alpha.3',clientCDHash=cdhash,adapterSHA256=adapter_hash,approvedPorts=[443])
 if not portable_helper:
  values.update(approvedDomains=[r['domain'] for r in policy['sites']],approvedPorts=policy['ports'],approvedRDPHost=a.rdp_host or '')
 constants.write_text('import Foundation\n'+''.join('let '+k+' = '+json.dumps(v)+'\n' for k,v in values.items()))
 flags=['-D','CVR_PORTABLE_HELPER'] if portable_helper else []
 run('swiftc',*flags,'-swift-version','5','-O','-target','arm64-apple-macos13.0','-module-cache-path',ROOT/'.build/module-cache',
     ROOT/'Sources/RouteHelper/Protocol.swift',ROOT/'Sources/RouteHelper/Daemon.swift',constants,'-o',helper)
run('codesign','--force','--sign','-','--options','runtime','--timestamp=none',helper)
run('codesign','--verify','--strict',helper)

helper_sha=hashlib.sha256(helper.read_bytes()).hexdigest() if helper.exists() else plistlib.loads((a.base_app/'Contents/Info.plist').read_bytes())['CVRRouteHelperSHA256']
if not a.private:
 for name in ['ApprovedGateway.json','ApprovedSitePin.json','ApprovedCertificates','CertificateEndpoints.json','DefaultWorkSites.json','DefaultDomainMap.json','WorkSiteAdditions.json','RouteHelper/RouteGrants.json','RouteHelper/LocalPolicy.json','SelectiveAdapter/sing-box']:
  path=res/name
  if path.is_dir():shutil.rmtree(path)
  elif path.exists():path.unlink()
# Never inherit a deployment-specific desktop from a base bundle implicitly.
desktop_file = res/'DefaultDesktop.json'
desktop_file.unlink(missing_ok=True)
desktop = a.deployment_desktop or (a.rdp_host if a.private else None)
if desktop:
 labels = desktop.split('.')
 if len(desktop)>253 or len(labels)<2 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels) or not any(c.isalpha() for c in labels[-1]):
  p.error('Expected a canonical DNS name for the deployment desktop')
 if a.private and desktop != a.rdp_host:p.error('The private helper and deployment must authorize the same desktop')
 desktop_file.write_text(json.dumps({'desktop':desktop},sort_keys=True)+'\n')
# No compile paths or signing private keys are included.
info=app/'Contents/Info.plist';d=plistlib.loads(info.read_bytes())
d.pop('CVRVersionCredit',None)
if a.credit:d['CVRVersionCredit']=a.credit
d.update(CFBundleShortVersionString=a.version,CFBundleVersion=str(a.build),LSMinimumSystemVersion='26.0',
 CVRDeploymentEdition=edition,
 SUFeedURL=f'https://github.com/GeoKhv/corporate-vpn-router/releases/download/{channel}/appcast.xml',
 SUPublicEDKey=(ROOT/'packaging/updates/public-key.txt').read_text().strip(),
 SUEnableAutomaticChecks=True,SUAutomaticallyUpdate=False,SUAllowsAutomaticUpdates=False,
 SUScheduledCheckInterval=86400,SUEnableSystemProfiling=False,SUShowReleaseNotes=False,
 SUVerifyUpdateBeforeExtraction=True,SURequireSignedFeed=True,SUSignedFeedFailureExpirationInterval=0,
 CVRRouteHelperSHA256=helper_sha,CVRRouteHelperBuild='0.3.20' if portable_helper else '0.3.10',CVRRouteHelperProtocol='0.3.0-alpha.3')
info.write_bytes(plistlib.dumps(d,sort_keys=True))
bundle.runtime_landmark(res/'Runtime')
(res/'VERSION').write_text(a.version+'\n');(res/'INSTALLER_REVISION').write_text(a.version+'\n')
# Remove only Finder metadata from build copies; never quarantine or security policy.
subprocess.run(['xattr','-dr','com.apple.FinderInfo',str(app)],check=False)
run('python3',ROOT/'scripts/normalize-code-modes.py',app)
run('codesign','--force','--sign','-','--timestamp=none',app)
run('codesign','--verify','--deep','--strict',app)
# Version is sealed metadata; invoking a quarantined release here can block on
# Gatekeeper and is not a distribution test. Launch checks are explicit steps.
assert plistlib.loads(info.read_bytes())['CFBundleShortVersionString']==a.version
# Catch missing sibling imports with the same isolated interpreter as the GUI.
# Import only: do not collect device logs or start a connection during a build.
run(res/'Runtime/bin/python3.13','-I','-B','-c',
    'import runpy,sys; runpy.run_path(sys.argv[1], run_name="report_import_check")',
    res/'Engine/support_report.py')
print(app)
