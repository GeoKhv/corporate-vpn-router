"""Verify migrations cannot remove foreign/modified policies or silently enable an extension."""
import copy, json, os, sys, tempfile
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
        r.retire_profile()
        assert listed==[{'ProfileIdentifier':'foreign-safe'}] and r.read(r.R)==receipt
        assert r.save(cfg) and r.read(r.WORK)==cfg
        cfg['beforeLogin']=[]
        denied(lambda:r.save(cfg))
        listed.append({'ProfileIdentifier':'IT','ProfileItems':[{'PayloadType':'com.google.Chrome','ProxyMode':'fixed_servers'}]})
        denied(r.migration_check)
    os.chdir(old)
print('PASS exact beta.5 retirement, preserve rollback and foreign profile, reject changed policy and missing gateway exception.')
