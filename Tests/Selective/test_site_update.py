"""Private addition: preserve edits, apply once, block during active routing."""
import json,os,subprocess,sys,tempfile,time
from pathlib import Path

app=Path(sys.argv[1]).resolve();resources=app/'Contents/Resources'
update=json.loads((resources/'WorkSiteAdditions.json').read_text())
added={r['domain'] for r in update['sites']}
cfg=json.loads((resources/'DefaultWorkSites.json').read_text())
cfg['sites']=[r for r in cfg['sites'] if r['domain'] not in added]
cfg['sites'].append({'domain':'custom.example.invalid','scope':'tree'})
cfg['ports']=[443,8443];cfg['beforeLogin'].append('login.example.invalid')
original=json.dumps(cfg,indent=2).encode()
with tempfile.TemporaryDirectory(prefix='cvr-site-update-',dir='/private/tmp') as tmp:
    home=Path(tmp);env={**os.environ,'HOME':tmp,'CFFIXED_USER_HOME':tmp}
    data=home/'Library/Application Support/Corporate VPN Router';data.mkdir(parents=True)
    target=data/'work-sites.json';target.write_bytes(original)
    subprocess.run([str(app/'Contents/MacOS/CorporateVPNRouter'),'--install'],env=env,check=True,capture_output=True)
    executable=home/'Applications/Corporate VPN Router TUN Trial.app/Contents/MacOS/CorporateVPNRouter'
    status=data/'ssl-status.json'
    def launch():
        status.unlink(missing_ok=True)
        p=subprocess.Popen([str(executable),'--login'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                assert p.poll() is None,p.stderr.read().decode()
                if status.exists():break
                time.sleep(.1)
            else:raise AssertionError('menu did not start')
            assert json.loads(status.read_text())['connected'] is False
        finally:
            if p.poll() is None:p.terminate()
            p.wait(timeout=10)
    launch()
    expected={**cfg,'sites':cfg['sites']+update['sites']}
    assert json.loads(target.read_text())==expected
    backup=data/('work-sites-before-'+update['id']+'.json')
    assert backup.read_bytes()==original and backup.stat().st_mode&0o777==0o600
    assert not (data/'Selective').exists()
    target.write_bytes(original)  # user's subsequent removal must be respected
    launch();assert target.read_bytes()==original
    (data/'work-site-updates.json').unlink()
    state=data/'Selective';state.mkdir();session=home/'session';session.mkdir()
    (session/'ready.json').write_text('{}');(state/'last-session.txt').write_text(str(session))
    p=subprocess.run([str(executable),'--login'],env=env,capture_output=True,text=True,timeout=15)
    assert p.returncode!=0 and 'Дождитесь остановки' in p.stderr and target.read_bytes()==original
    (session/'cleanup.json').write_text('{}')
    launch();assert json.loads(target.read_text())==expected and backup.read_bytes()==original
print('PASS one-time domain addition; custom sites/ports/exceptions and exact backup preserved; later removal respected; active routes block edits; cleanup permits migration')
