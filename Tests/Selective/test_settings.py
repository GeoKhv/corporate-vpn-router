"""Real CLI saves: supported edits, no widening, active-session barrier."""
import json,os,subprocess,sys,tempfile
from pathlib import Path
app=Path(sys.argv[1]).resolve();runtime=app/'Contents/Resources/Runtime/bin/python3.13'
entry=app/'Contents/Resources/Engine/Selective/controller.py'
with tempfile.TemporaryDirectory(prefix='cvr-selective-settings-',dir='/private/tmp') as tmp:
    home=Path(tmp);data=home/'Library/Application Support/Corporate VPN Router';data.mkdir(parents=True)
    (data/'ssl-site.json').write_text('{"site":"gateway.example.invalid"}')
    cfg={'version':1,'sites':[{'domain':'work.example.invalid','scope':'tree'}],'beforeLogin':['gateway.example.invalid'],'ports':[443]}
    draft=home/'draft.json';draft.write_text(json.dumps(cfg))
    def save():return subprocess.run([str(runtime),'-I','-B',str(entry),'save',str(draft)],env={**os.environ,'HOME':str(home)},capture_output=True,text=True,timeout=10)
    assert save().returncode==0
    original=(data/'work-sites.json').read_bytes()
    cfg['sites'][0]['scope']='exact';draft.write_text(json.dumps(cfg))
    assert save().returncode!=0 and (data/'work-sites.json').read_bytes()==original
    cfg['sites'][0]['scope']='tree';cfg['sites'].append({'domain':'second.example.invalid','scope':'tree'});draft.write_text(json.dumps(cfg))
    assert save().returncode==0 and json.loads((data/'work-sites.json').read_text())==cfg
    state=data/'Selective';state.mkdir();session=home/'session';session.mkdir();(session/'ready.json').write_text('{}');(state/'last-session.txt').write_text(str(session))
    assert save().returncode!=0
    (session/'cleanup.json').write_text('{}');assert save().returncode==0
print('PASS editable work list; exact scope rejected without overwrite; active routing blocks edits; cleanup releases barrier')
