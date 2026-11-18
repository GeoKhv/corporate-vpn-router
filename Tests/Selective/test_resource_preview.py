"""Single-input parsing and bounded corporate DNS discovery."""
import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'Backend/Selective'))
from analyze import parse, preview
from http_router import CorporateDNSFailure
for text,name,port,scheme in [
    ('server: https://node.example:6443/key?q=secret','node.example',6443,'https'),
    ('server: https://node.example/path','node.example',443,'https'),
    ('jdbc:postgresql://db.example:15432/private','db.example',15432,'postgresql'),
    ('redis://cache','cache',6379,'redis'),('someone@node','node',22,'ssh'),
    ('http://node/secret#private','node',80,'http'),('node:8080','node',8080,'tcp')]:
    row=parse(text)
    assert (row['host'],row['port'],row['scheme'])==(name,port,scheme)
    assert all(s not in json.dumps(row) for s in ('secret','private','someone'))
assert parse('*.lab.example')['tree']
for invalid in ['192.0.2.1','foo.*.invalid','server: node','kubectl get pods','*.a.*.test']:
    try: parse(invalid)
    except ValueError: pass
    else: raise AssertionError(invalid)
async def check():
    suffixes=['one.example','two.example']
    profile=dict(sites=[dict(domain=s,scope='tree') for s in suffixes],beforeLogin=[])
    request=dict(text='test:22',suffixes=suffixes)
    class Writer:
        def close(self): pass
    async def found(name,port,*,resolve_only):
        assert name in ['test.'+s for s in suffixes] and port==0 and resolve_only
        return None,Writer()
    for failure,message in [(CorporateDNSFailure(3),'не нашёл'),(TimeoutError(),'недоступен')]:
        with patch('analyze.via_socks',side_effect=failure):
            assert message in (await preview(request,profile))['rows'][0]['error']
    with patch('analyze.via_socks',side_effect=found):
        assert (await preview(request,profile))['rows'][0]['choices']==['test.'+s for s in suffixes]
asyncio.run(check())
print('PASS parse, privacy, DNS absent, unavailable and ambiguous')
