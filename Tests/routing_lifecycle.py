"""Verify migrations cannot remove foreign/modified policies or silently enable an extension."""
import copy, plistlib, json, os, sys, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Backend'))
import routing as r

with tempfile.TemporaryDirectory() as tmp, patch.object(r,'DATA',Path(tmp)),patch.object(r,'preference_dirs',return_value=[]):
    old=os.getcwd()
    receipt={'id':'our-id','uuid':'UUID','payload':'PAYLOAD','issued':[{'ProxyMode':'pac_script','ProxyPacUrl':'example'}]}
    record={'ProfileIdentifier':'our-id','ProfileUUID':'UUID','ProfileItems':[{
        'PayloadType':'com.apple.ManagedClient.preferences','PayloadIdentifier':'our-id.settings','PayloadUUID':'PAYLOAD',
        'PayloadContent':{'com.google.Chrome':{'Forced':[{'mcx_preference_settings':{'ProxySettings':receipt['issued'][0]}}]}}}]}
    listed=[copy.deepcopy(record),{'ProfileIdentifier':'foreign-safe'}]
    cfg=dict(version=1,sites=[{'domain':'work.example','scope':'tree'}],beforeLogin=['login.work.example'],ports=[443])
    def remove(args,**kw):
        assert args[-2]=='our-id'
        listed.pop(0)
    def denied(call):
        try:call()
        except r.Conflict:return
        raise AssertionError('operation should have stopped')
    with patch.object(r,'profiles',side_effect=lambda:copy.deepcopy(listed)),patch.object(r.subprocess,'run',side_effect=remove):
        r.put(r.R,receipt);r.put('ssl-site.json',{'site':'login.work.example'});r.put(r.WORK,cfg)
        assert r.migration_check()[1]==record
        listed[0]['ProfileUUID']='foreign'
        denied(r.retire_profile)
        listed[0]=copy.deepcopy(record)
        listed[0]['ProfileItems'][0]['PayloadContent']['extra']={}
        denied(r.retire_profile)
        listed[0]=copy.deepcopy(record)
        old_proxy=receipt['issued'][0]
        r.put('active-proxy.json',old_proxy)
        raw=plistlib.dumps(r.payload(receipt,old_proxy));r.put(r.FILE,raw)
        generated=Path(r.prepare())
        fixed=plistlib.loads(generated.read_bytes())
        assert fixed['PayloadUUID']==receipt['uuid'] and b'work.example' not in generated.read_bytes()
        assert fixed['PayloadContent'][0]['PayloadContent'][r.CHROME]['Forced'][0]['mcx_preference_settings']=={'ProxySettings':r.FIXED}
        changed=copy.deepcopy(cfg);changed['sites'].append({'domain':'new.example','scope':'exact'})
        denied(lambda:r.save(changed))
        listed[0]['ProfileItems']=fixed['PayloadContent']
        assert r.prepare()=='active' and r.rollback()=='confirm'
        with patch.object(r,'synchronize') as sync:
            r.save(changed)
            assert sync.call_args_list[-1].args==(r.HTTP_CONTROL,) and sync.call_args_list[-1].kwargs=={'required':True}
        assert generated.read_bytes()==plistlib.dumps(fixed) and r.read(r.WORK)==changed
        r.put(r.FILE,raw+b' ');denied(r.rollback)
        r.put(r.FILE,raw);listed[0]=copy.deepcopy(record)
        assert r.rollback()=='ready' and r.read(r.WORK)==cfg and r.read(r.R)==receipt
        listed[0]['ProfileRemovalDisallowed']=True;denied(r.prepare)
        listed[0]=copy.deepcopy(record)
        r.retire_profile()
        assert listed==[{'ProfileIdentifier':'foreign-safe'}] and r.read(r.R)==receipt
        assert r.save(cfg) and r.read(r.WORK)==cfg
        cfg['beforeLogin']=[]
        denied(lambda:r.save(cfg))
        listed.append({'ProfileIdentifier':'IT','ProfileItems':[{'PayloadType':'com.google.Chrome','ProxyMode':'fixed_servers'}]})
        denied(r.migration_check)
    os.chdir(old)
print('PASS fixed profile replacement, immediate edits, verified rollback, exact beta.5 retirement, preserve rollback and foreign profile, reject changed policy and missing gateway exception.')
