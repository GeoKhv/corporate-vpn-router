from pathlib import Path
import os,sys,json,tempfile,subprocess,time,signal,plistlib,socket,uuid
# Use only a uniquely named disposable GUI-domain job and alternate ephemeral port.
app=Path('.build/app-path.txt').read_text().strip()
runtime=Path(app)/'Contents/Resources/Runtime/bin/python3.13'
engine=Path(app)/'Contents/Resources/Engine'
label='com.geokhv.cvr-beta6-test.'+uuid.uuid4().hex
domain='gui/'+str(os.getuid());target=domain+'/'+label
def cmd(*args):
 return subprocess.run(args,capture_output=True,text=True)
with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
 d=Path(tmp); (d/'work-sites.json').write_text(json.dumps(dict(version=1,sites=[dict(domain='work.example',scope='tree')],beforeLogin=[],ports=[443])))
 with socket.socket() as s:
  s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 script=d/'test.py'
 script.write_text('import asyncio, sys\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(engine))+')\nimport http_router as h\nh.DATA=Path('+repr(tmp)+')\nh.PORT='+str(port)+'\nasyncio.run(h.main(launchd=True))\n')
 spec=d/'job.plist'
 spec.write_bytes(plistlib.dumps(dict(Label=label,ProgramArguments=[str(runtime),'-I','-B',str(script)],Sockets=dict(Listener=dict(SockNodeName="127.0.0.1",SockServiceName=str(port),SockType="stream",SockFamily="IPv4")),RunAtLoad=True,KeepAlive=True,ThrottleInterval=2)))
 def verify(host,code):
  with socket.create_connection(('127.0.0.1',port),1) as s:
   s.settimeout(5)
   s.sendall(f'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n'.encode())
   assert f' {code} '.encode() in s.recv(1024)
 def pid():
  out=cmd('/bin/launchctl','print',target).stdout
  rows=[l for l in out.splitlines() if l.strip().startswith('pid = ')]
  return int(rows[0].split('=')[1]) if rows else 0
 def ready(old):
  for _ in range(100):
   p=pid()
   if p and p!=old:
    try:verify('new.work.example',502)
    except OSError:pass
    else:return p
   time.sleep(.05)
  raise RuntimeError('launchd did not restart')
 try:
  p=cmd('/bin/launchctl','bootstrap',domain,str(spec));assert p.returncode==0,p.stderr
  before=ready(0);verify('example.com',200)
  os.kill(before,signal.SIGKILL)
  with socket.socket() as competing:
   try: competing.bind(('127.0.0.1',port))
   except OSError as error:
    import errno
    assert error.errno==errno.EADDRINUSE
   else:raise AssertionError('port could be taken during restart')
  after=ready(before);verify('example.com',200)
  assert after!=before
  print('PASS actual per-user launchd restart after SIGKILL. Life CONNECT 200, Work 502 before and after; disposable job and port.')
 finally:
  cmd('/bin/launchctl','bootout',target)
