"""Private ZIP integration in a disposable Foundation home; no production launchd jobs."""
import hashlib,json,os,plistlib,subprocess,sys,tempfile,time
from pathlib import Path
assert os.getuid()!=0
image=Path(sys.argv[1]).resolve(); base=Path(sys.argv[2]).resolve()
def run(*args,env=None,ok=True):
 r=subprocess.run(list(map(str,args)),env=env,capture_output=True,text=True,timeout=45)
 if ok and r.returncode: raise RuntimeError(r.stderr)
 return r
def inventory(p):return {str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob('*') if f.is_file()}
report={}
with tempfile.TemporaryDirectory(prefix='cvr-demo-check-',dir='/private/tmp') as tmp:
 t=Path(tmp); run('ditto','-x','-k',image,t/'new');run('ditto','-x','-k',base,t/'old')
 source=t/'new/Corporate VPN Router.app';old=next((t/'old').glob('*/Corporate VPN Router.app'))
 run('codesign','--verify','--deep','--strict',source);run('codesign','--verify','--deep','--strict',old)
 home=t/'home';home.mkdir();env={**os.environ,'HOME':str(home),'CFFIXED_USER_HOME':str(home)}
 exe=source/'Contents/MacOS/CorporateVPNRouter'
 assert Path(run(exe,'--installation-home',env=env).stdout.strip()).resolve()==home.resolve()
 installed=home/'Applications/Corporate VPN Router.app';data=home/'Library/Application Support/Corporate VPN Router'
 run(exe,'--install',env=env);assert inventory(installed)==inventory(source)
 agent=home/'Library/LaunchAgents/com.geokhv.corporate-vpn-router.menu.plist'
 # Start disconnected using the actual menu; no proxy job or profile installation.
 p=subprocess.Popen([str(installed/'Contents/MacOS/CorporateVPNRouter'),'--login'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try:
  for _ in range(80):
   if (data/'ssl-status.json').exists():break
   assert p.poll() is None;time.sleep(.1)
  assert json.loads((data/'ssl-status.json').read_text())['connected'] is False
  assert (data/'work-sites.json').read_bytes()==(source/'Contents/Resources/DefaultWorkSites.json').read_bytes()
  busy=run(exe,'--install',env=env,ok=False);assert busy.returncode!=0 and 'VPN-сеанс сохранён' in busy.stderr
  report['fresh_seed_login_busy']='PASS'
 finally:p.terminate();p.wait(timeout=8)
 # Simulate an existing release, preserve customized site/login/agent bytes.
 import shutil
 shutil.rmtree(installed);run('ditto',old,installed)
 saved=inventory(installed)
 cfg=json.loads((data/'work-sites.json').read_text());cfg['sites'].append({'domain':'edited.example.com','scope':'exact'})
 (data/'work-sites.json').write_text(json.dumps(cfg));(data/'ssl-logins.json').write_text('{"synthetic":"keep"}')
 job=plistlib.loads(agent.read_bytes());job['RunAtLoad']=False;agent.write_bytes(plistlib.dumps(job))
 keep={str(f):f.read_bytes() for f in [data/'work-sites.json',data/'ssl-logins.json',agent]}
 run(exe,'--install',env=env)
 backups=list(data.glob('rollback-*.app'));assert len(backups)==1 and inventory(backups[0])==saved
 assert all(Path(f).read_bytes()==v for f,v in keep.items())
 report['safe_update_exact_backup_settings']='PASS'
 # Relaunch must leave all edited settings intact.
 p=subprocess.Popen([str(installed/'Contents/MacOS/CorporateVPNRouter'),'--login'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 try:
  time.sleep(1);assert p.poll() is None
  assert all(Path(f).read_bytes()==v for f,v in keep.items())
 finally:p.terminate();p.wait(timeout=8)
 shutil.rmtree(installed);run('ditto',backups[0],installed)
 assert inventory(installed)==saved and all(Path(f).read_bytes()==v for f,v in keep.items())
 report['rollback_exact_original']='PASS'
print(json.dumps(report,indent=2))
