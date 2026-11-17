"""Rollback must preserve concurrent unrelated browser edits and refuse conflicts."""
import json,tempfile
from pathlib import Path
from user_proxy import create_profile,apply,restore,PROXY
with tempfile.TemporaryDirectory(dir='/private/tmp') as d:
 p=Path(d)/'Chrome';create_profile(p);f=p/'Default/Preferences'
 original=b'{\n  "keep": [1, 2], "proxy": {"mode":"direct"}\n}\n';f.write_bytes(original)
 r=apply(p,PROXY);assert restore(p,r)=='exact bytes' and f.read_bytes()==original
 r=apply(p,PROXY);j=json.loads(f.read_text());j['new-browser-value']=123;f.write_text(json.dumps(j))
 assert restore(p,r).startswith('proxy key only');j=json.loads(f.read_text());assert j['proxy']=={'mode':'direct'} and j['new-browser-value']==123
 r=apply(p,PROXY);j=json.loads(f.read_text());j['proxy']={'mode':'system'};f.write_text(json.dumps(j));before=f.read_bytes()
 try:restore(p,r)
 except ValueError:pass
 else:raise AssertionError('foreign proxy overwritten')
 assert f.read_bytes()==before
 (p/'SingletonLock').symlink_to('fake-test-pid')
 try:apply(p,PROXY)
 except ValueError:pass
 else:raise AssertionError('running profile accepted')
 print('PASS exact byte rollback, key-only rollback, proxy conflict refusal, browser lock refusal.')
