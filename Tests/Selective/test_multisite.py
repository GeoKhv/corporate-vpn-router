"""Selection uses one complete signed-client record, independent of display order."""
import json, os, sys, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
import trust, official_handoff

def block(h,i,s):
    return f'Conn {h}:\r\n  gw: {i}\r\n  status: {s}\r\n'
work=('new.example.invalid','192.0.2.2')
old=('old.example.invalid','192.0.2.1')
a=block(*old,'Idle'); b=block(*work,'Idle'); c=block(*work,'Connected')
def select(s): return trust.choose_site(trust.parse_sites(s))
def refuses(code, fn):
    try:fn()
    except trust.Refused as e:assert str(e)==code,(code,str(e))
    else:raise AssertionError('expected '+code)

with tempfile.TemporaryDirectory() as d, patch.object(trust,'DATA',Path(d)),patch.object(trust,'APPROVED_GATEWAY',Path(d)/'seed.json'):
    for text in (a+c,c+a):
        assert select(text)==(*work,'Connected')
    refuses('OFFICIAL_SITE_AMBIGUOUS',lambda:select(b+a))
    refuses('OFFICIAL_STATE_UNKNOWN',lambda:select(c+a.replace('Idle','Connected')))
    refuses('OFFICIAL_STATE_UNKNOWN',lambda:select(c+b.replace(work[0],'third.invalid').replace('Idle','?')))
    refuses('OFFICIAL_SITE_FORMAT_UNSUPPORTED',lambda:select(c+b))
    refuses('OFFICIAL_STATE_UNKNOWN',lambda:select(a.replace('status: Idle','xxx')+c))
    refuses('OFFICIAL_SITE_FORMAT_UNSUPPORTED',lambda:select(a.replace(old[1],'999.1.1.1')+c))
    with patch.dict(os.environ,CVR_ATTEMPT_GATEWAY=old[0]+'@'+old[1]):
        refuses('OFFICIAL_SELECTION_CHANGED',lambda:select(c+a))
    (Path(d)/'ssl-site.json').write_text(json.dumps(dict(site=work[0],ip=work[1])))
    assert select(b+a)==(*work,'Idle')
    refuses('OFFICIAL_OTHER_SITE_ACTIVE',lambda:select(b+a.replace('Idle','Connected')))
    refuses('SAVED_SITE_OR_PIN_CHANGED',lambda:select(a))
    moved=b.replace(work[1],'192.0.2.20')+a
    assert select(moved)==(work[0],'192.0.2.20','Idle')  # candidate only; anchor must prove the DNS name
    with patch.dict(os.environ,CVR_ATTEMPT_GATEWAY=work[0]+'@'+work[1]):
        refuses('OFFICIAL_SELECTION_CHANGED',lambda:select(moved))
with patch.object(official_handoff,'official_info',side_effect=[(*work,'Connected'),(*old,'Connected')]),patch.object(official_handoff.subprocess,'run') as cmd:
    refuses('OFFICIAL_SELECTION_CHANGED',lambda:official_handoff.prepare(lambda kind,*a,**kw: 'available' if kind=='check_official_gui' else 'accept'))
    cmd.assert_not_called()
print('PASS active/saved site independent of order; malformed/ambiguous/changed/foreign sessions preserved before disconnect')
