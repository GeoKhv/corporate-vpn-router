"""Test explicit fixed-proxy Chrome NetworkContext in an isolated data dir; no default-profile overrides."""
import os,subprocess,threading,time,json,socket,select,tempfile,http.server,uuid,signal
from pathlib import Path
app=Path(Path('.build/app-path.txt').read_text().strip())
engine=app/'Contents/Resources/Engine'
py=app/'Contents/Resources/Runtime/bin/python3.13'
chrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
hits=[]
stream_open=threading.Event()
stream_closed=threading.Event()
class Origin(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path=='/stream':
   self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(64*1024*1024));self.end_headers()
   try:
    for _ in range(16384):
     self.wfile.write(b'x'*4096);self.wfile.flush();stream_open.set();time.sleep(.03)
   except OSError:stream_closed.set()
   return
  hits.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'origin-witness')
origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
threading.Thread(target=origin.serve_forever,daemon=True).start()
class Browser:
 def __init__(self,dir):
  rr,ww=os.pipe();r,w=os.pipe()
  self.pid=os.posix_spawn(chrome,[chrome,'--headless','--remote-debugging-pipe','--disable-extensions','--user-data-dir='+str(dir),'--no-first-run','--disable-background-networking','--host-resolver-rules=MAP *.router.test 127.0.0.1','about:blank'],os.environ,
     file_actions=[(os.POSIX_SPAWN_DUP2,rr,3),(os.POSIX_SPAWN_DUP2,w,4),(os.POSIX_SPAWN_OPEN,2,os.devnull,os.O_WRONLY,0)])
  os.close(rr);os.close(w);self.r=r;self.w=ww;self.buf=b'';self.i=0;self.events=[]
 def msg(self):
  while b'\0' not in self.buf:
   if not select.select([self.r],[],[],18)[0]:raise RuntimeError('CDP timeout')
   data=os.read(self.r,65536)
   if not data:raise RuntimeError('Chrome exited')
   self.buf+=data
  msg,self.buf=self.buf.split(b'\0',1);return json.loads(msg)
 def call(self,method,params={},session=None):
  self.i+=1;d=dict(id=self.i,method=method,params=params)
  if session:d['sessionId']=session
  os.write(self.w,json.dumps(d).encode()+b'\0')
  while True:
   m=self.msg()
   if m.get('id')==self.i:
    if 'error' in m:raise RuntimeError(m['error'])
    return m['result']
   self.events.append(m)
 def page(self,ctx,url):
  t=self.call('Target.createTarget',{'url':'about:blank','browserContextId':ctx})['targetId']
  try:
   s=self.call('Target.attachToTarget',{'targetId':t,'flatten':True})['sessionId']
   nav=self.call('Page.navigate',{'url':url},s)
   if nav.get('errorText'):return nav['errorText'],''
   for _ in range(100):
    v=self.call('Runtime.evaluate',{'expression':'document.readyState+"|"+(document.body?.innerText||"")','returnByValue':True},s)['result'].get('value','')
    if 'complete|' in v and v.split('|',1)[-1]:return '',v
    time.sleep(.075)
   return '',v
  finally:self.call('Target.closeTarget',{'targetId':t})
 def close(self):
  os.kill(self.pid,signal.SIGTERM);os.waitpid(self.pid,0);os.close(self.r);os.close(self.w)
with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
 base=Path(tmp);d=base/'rules';d.mkdir()
 policy=dict(version=1,sites=[dict(domain='router.test',scope='tree')],beforeLogin=[],ports=[443,origin.server_port])
 def save():
  p=d/'new';p.write_text(json.dumps(policy));p.replace(d/'work-sites.json')
 save()
 with socket.socket() as pick:pick.bind(('127.0.0.1',0));port=pick.getsockname()[1]
 def start():
  runner=base/'run.py'
  runner.write_text('import asyncio,sys\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(engine))+')\nimport http_router as h\nh.DATA=Path('+repr(str(d))+')\nh.PORT='+str(port)+'\noriginal=h.Router.direct\nasync def fixture(self,host,port):\n if host=="stream.fixture.test":return await asyncio.open_connection("127.0.0.1",'+str(origin.server_port)+')\n return await original(self,host,port)\nh.Router.direct=fixture\nasyncio.run(h.main())')
  proc=subprocess.Popen([py,'-I','-B',runner])
  for _ in range(80):
   try:
    with socket.create_connection(('127.0.0.1',port),.2):return proc
   except OSError:time.sleep(.05)
  raise RuntimeError('relay did not bind')
 relay=start();b=Browser(base/'Chrome')
 try:
  ctx=b.call('Target.createBrowserContext',{'proxyServer':'http://127.0.0.1:'+str(port)})['browserContextId']
  def ctl(op):
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
    old=os.getcwd()
    try:
     os.chdir(d);client.connect('http-router.sock')
    finally:os.chdir(old)
    client.sendall(op)
    return client.makefile('rb').read()
  token=ctl(b'N').decode()
  assert len(token)==40 and ctl(b'V')==b'0'
  err,doc=b.page(ctx,'http://router-check.invalid/'+token)
  assert not err and 'Corporate VPN Router:' in doc and ctl(b'V')==b'1'
  print('One-time browser enrollment witness received and rendered.',flush=True)
  mark=uuid.uuid4().hex
  target=f'http://a.router.test:{origin.server_port}/{mark}'
  direct=b.call('Target.createBrowserContext',{'proxyServer':'direct://'})['browserContextId']
  err,body=b.page(direct,target+'-control')
  assert not err and 'origin-witness' in body and '/'+mark+'-control' in hits
  b.call('Target.disposeBrowserContext',{'browserContextId':direct})
  hits.clear()
  err,body=b.page(ctx,target)
  assert not hits and (err=='net::ERR_HTTP_RESPONSE_CODE_FAILURE' or '502' in body),(err,body[:100],hits)
  print('work: no direct origin hits. Response',err or body[:80],flush=True)
  life='https://example.com/?probe='+mark
  err,body=b.page(ctx,life);assert not err and ('Example Domain' in body or 'домен предназначен' in body or 'documentation examples' in body),(err,body[:90])
  policy['sites'].append(dict(domain='example.com',scope='exact'));save()
  time.sleep(.25)
  err,body=b.page(ctx,life+'1');assert err and 'TUNNEL' in err,(err,body[:80])
  policy['sites'].pop();save();time.sleep(.25)
  err,body=b.page(ctx,life+'2');assert not err and ('Example Domain' in body or 'домен предназначен' in body or 'documentation examples' in body)
  print('Life rendered; new Work rule blocked HTTPS; deletion restored Life in the same Chrome process.',flush=True)
  # Start a real browser transfer against a deterministic fixture. Keep it open
  # until a successful save converts this once-personal host to Work.
  tab=b.call('Target.createTarget',{'url':'about:blank','browserContextId':ctx})['targetId']
  sess=b.call('Target.attachToTarget',{'targetId':tab,'flatten':True})['sessionId']
  url='http://stream.fixture.test/stream'
  b.call('Network.enable',{},sess)
  assert not b.call('Page.navigate',{'url':url},sess).get('errorText')
  assert stream_open.wait(2)
  time.sleep(2)
  assert not stream_closed.is_set()
  policy['sites'].append(dict(domain='stream.fixture.test',scope='exact'));save()
  assert ctl(b'S')==b'1' and stream_closed.wait(4)
  for _ in range(30):
   b.call('Runtime.evaluate',{'expression':'document.readyState'},sess)
   if any(e.get('method')=='Network.loadingFailed' and e.get('sessionId')==sess for e in b.events):break
   time.sleep(.1)
  else:raise AssertionError('Chrome did not observe interrupted transfer')
  err,body=b.page(ctx,url+'?retry')
  assert err=='net::ERR_HTTP_RESPONSE_CODE_FAILURE' or '502' in body
  print('Existing Chrome transfer interrupted on save; restricted retry blocked.',flush=True)
  b.call('Target.closeTarget',{'targetId':tab})
  relay.kill();relay.wait()
  err,body=b.page(ctx,target+'-crash');assert 'PROXY_CONNECTION_FAILED' in err and not hits,(err,hits)
  relay=start()
  err,body=b.page(ctx,life+'3');assert not err and ('Example Domain' in body or 'домен предназначен' in body or 'documentation examples' in body)
  print('Proxy death: browser error, zero direct hits. Restart: Life rendered.',flush=True)
 finally:
  b.close();relay.terminate();relay.wait();origin.shutdown();origin.server_close()
