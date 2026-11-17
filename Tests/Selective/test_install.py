"""Disposable Foundation home: sibling beta.6, edits, locking and private rollback."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,time
from pathlib import Path
def run(*args,env=None,ok=True):
    p=subprocess.run(list(map(str,args)),env=env,capture_output=True,text=True,timeout=45)
    if ok and p.returncode:raise RuntimeError(p.stderr)
    return p
def inventory(path):return {str(p.relative_to(path)):hashlib.sha256(p.read_bytes()).hexdigest() for p in path.rglob('*') if p.is_file()}
source=Path(sys.argv[1]).resolve();original=Path(sys.argv[2]).resolve()
with tempfile.TemporaryDirectory(prefix='cvr-selective-install-',dir='/private/tmp') as tmp:
    home=Path(tmp);env={**os.environ,'HOME':str(home),'CFFIXED_USER_HOME':str(home)}
    data=home/'Library/Application Support/Corporate VPN Router';data.mkdir(parents=True)
    old=home/'Applications/Corporate VPN Router.app';old.parent.mkdir();shutil.copytree(original,old)
    saved=inventory(old)
    (data/'ssl-logins.json').write_text('{"fixture":"preserved"}')
    (data/'work-sites.json').write_bytes((source/'Contents/Resources/DefaultWorkSites.json').read_bytes())
    kept={str(p):p.read_bytes() for p in (data/'ssl-logins.json',data/'work-sites.json')}
    executable=source/'Contents/MacOS/CorporateVPNRouter'
    assert Path(run(executable,'--installation-home',env=env).stdout.strip()).resolve()==home
    run(executable,'--install',env=env)
    target=home/'Applications/Corporate VPN Router TUN Trial.app'
    assert inventory(target)==inventory(source) and inventory(old)==saved
    assert not (home/'Library/LaunchAgents').exists()
    p=subprocess.Popen([str(target/'Contents/MacOS/CorporateVPNRouter'),'--login'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if (data/'ssl-status.json').exists():break
            assert p.poll() is None;time.sleep(.1)
        for _ in range(100):
            status=json.loads((data/'ssl-status.json').read_text())
            if status['message']!='Проверка помощника маршрутов…':break
            assert p.poll() is None;time.sleep(.1)
        else:raise AssertionError('helper startup probe did not finish')
        assert status['connected'] is False
        if os.environ.get('CVR_EXPECT_EXISTING_HELPER')=='1':
            assert status['message']=='Всё готово. Выберите способ входа и нажмите «Подключить».',status['message']
            print('PASS actual installed alpha.3 helper recognized without elevation or route setup')
        assert not (data/'Selective/domain-map.json').exists(), 'routes must require user action; diagnostic journal is allowed'
        result=run(executable,'--install',env=env,ok=False)
        assert result.returncode!=0 and 'VPN-сеанс сохранён' in result.stderr
    finally:p.terminate();p.wait(timeout=10)
    run(executable,'--install',env=env)
    backups=list(data.glob('rollback-*.app'));assert len(backups)==1
    assert inventory(backups[0])==inventory(source)
    assert inventory(old)==saved and all(Path(p).read_bytes()==b for p,b in kept.items())
    shutil.rmtree(target);shutil.copytree(backups[0],target)
    assert inventory(target)==inventory(source)
print('PASS separate installation, unchanged beta.6/config, busy lock, no autostart/network/editor, exact private rollback')
