"""Model macOS-owned state independently from Router's draft, receipt and disk files."""
import copy,json,plistlib,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Backend'))
import routing as r
work=dict(version=1,sites=[dict(domain='office.example',scope='tree')],beforeLogin=['id.example'],ports=[443])
records=[]
def fake(*args,**kwargs):
    if args[0][0]=='/usr/bin/profiles':
        assert args[0][1]=='remove' and args[0][-2]==records[0]['ProfileIdentifier'];records.clear()
        return
    raise AssertionError(args)
def install(path):
    d=plistlib.loads(Path(path).read_bytes());records[:]=[dict(ProfileIdentifier=d['PayloadIdentifier'],ProfileUUID=d['PayloadUUID'],ProfileItems=d['PayloadContent'])]
with tempfile.TemporaryDirectory() as tmp,patch.object(r,'DATA',Path(tmp)),patch.object(r,'preference_dirs',return_value=[]),patch.object(r,'profiles',side_effect=lambda:copy.deepcopy(records)),patch.object(r.subprocess,'check_output',return_value='<dictionary> {}'),patch.object(r.subprocess,'run',side_effect=fake):
    r.put('ssl-site.json',{'site':'gw.example'})
    f=r.prepare(work);assert 'Ожидается' in r.confirm() and not r.read(r.WORK)
    install(f);assert r.confirm().startswith('Приложение') and r.read(r.WORK)==work
    changed=copy.deepcopy(work);changed['sites'][0]['scope']='exact'
    f=r.prepare(changed);assert 'прежний список' in r.confirm() and r.read(r.WORK)==work
    install(f);assert r.confirm().startswith('Приложение') and r.read(r.WORK)==changed
    records[0]['ProfileUUID']='FOREIGN'
    try:r.release()
    except r.Conflict:pass
    else:raise AssertionError('foreign removal')
    install(f);r.release();assert not records and not r.read(r.R) and r.confirm()=='Расширение'
    records[:]=[{'ProfileIdentifier':'other','ProfileItems':[{'PayloadType':'com.google.Chrome','PayloadContent':{'ProxyMode':'fixed_servers'}}]}]
    try:r.prepare(work)
    except r.Conflict:pass
    else:raise AssertionError('foreign policy overwritten')
print('PASS pending vs installed, replacement, drift, ownership, release and foreign managed proxy.')
