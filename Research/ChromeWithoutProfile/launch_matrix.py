"""Run only on a policy-free test browser, with fresh disposable profiles."""
import argparse,http.server,json,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from browser import Browser
from user_proxy import create_profile,apply,restore
p=argparse.ArgumentParser();p.add_argument('--chrome',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();args.chrome=args.chrome.resolve()
hits=[]
class Origin(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  hits.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'CVR-ORIGIN')
class Proxy(Origin):
 def do_GET(self):
  hits.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'CVR-PROXY')
o=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin);proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
for s in (o,proxy):threading.Thread(target=s.serve_forever,daemon=True).start()
rows={};mapping='--host-resolver-rules=MAP *.router.test 127.0.0.1';endpoint='http://127.0.0.1:'+str(proxy.server_port)
url='http://fresh.router.test:'+str(o.server_port)+'/'+uuid.uuid4().hex
try:
 with tempfile.TemporaryDirectory(prefix='cvr-launch-',dir='/private/tmp') as d:
  root=Path(d);profile=root/'Profile';create_profile(profile)
  def check(label,flags,expected):
   b=Browser(args.chrome,profile,[mapping,*flags])
   try:
    err,body=b.page(url+'?'+label);assert not err and expected in body,(label,err,body[:100])
   finally:b.close()
   rows[label]=expected
  check('cold-with-switch',['--proxy-server='+endpoint],'CVR-PROXY')
  check('ordinary-restart-without-switch',[],'CVR-ORIGIN')
  b=Browser(args.chrome,profile,[mapping])
  try:
   assert 'CVR-ORIGIN' in b.page(url+'?before')[1]
   second=subprocess.run([str(args.chrome),'--headless','--user-data-dir='+str(profile),'--proxy-server='+endpoint,url+'?second'],capture_output=True,timeout=15)
   rows['second-process-exit']=second.returncode;rows['second-process-message']=second.stderr.decode(errors='replace')[-1200:]
   assert second.returncode==21,second.stderr.decode(errors='replace')
   assert 'CVR-ORIGIN' in b.page(url+'?after')[1]
  finally:b.close()
  rows['switch-on-already-running']='second process refused with profile-in-use; original direct context retained'
  pref=profile/'Default/Preferences';receipt=apply(profile,dict(mode='fixed_servers',server=endpoint,bypass_list=''))
  check('seeded-user-pref-ordinary-launch',[],'CVR-PROXY')
  check('seeded-user-pref-second-restart',[],'CVR-PROXY')
  j=json.loads(pref.read_text());rows['proxy-pref-persisted']=j.get('proxy')==dict(mode='fixed_servers',server=endpoint,bypass_list='')
  rows['rollback']=restore(profile,receipt);check('restored-pref-ordinary-launch',[],'CVR-ORIGIN')
 print(json.dumps(rows,indent=2));args.output.write_text(json.dumps(rows,indent=2))
finally:
 for s in (o,proxy):s.shutdown();s.server_close()
