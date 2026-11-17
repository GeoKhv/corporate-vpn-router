#!/usr/bin/env python3
"""Actual Sparkle network/signature/cancellation tests in disposable apps."""
import http.server,json,os,plistlib,shutil,socket,subprocess,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
base=Path(tempfile.mkdtemp(prefix='cvr-sparkle-negative-',dir='/private/tmp'))
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  name=self.path.split('/')[-1]
  if name.endswith('.xml'):
   data=(base/name).read_bytes();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
  data=(base/'payload').read_bytes();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
  try:
   if name=='interrupted.zip':
    self.wfile.write(data[:65536]);self.wfile.flush();self.close_connection=True;self.connection.shutdown(socket.SHUT_RDWR);return
   for pos in range(0,len(data),16384):
    self.wfile.write(data[pos:pos+16384]);self.wfile.flush()
    if name=='cancel.zip':time.sleep(.03)
  except (BrokenPipeError,ConnectionResetError):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
port=server.server_port
shutil.copy2(ROOT/'.private/updates/releases/Corporate-VPN-Router-0.3.1-arm64.zip',base/'source-archive.zip')
subprocess.run([str(ROOT/'.build/sparkle-negative'),'--fixtures',str(base),str(port)],check=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
for scenario in ['wrong-signature','interrupted','cancel']:
 app=base/(scenario+'.app');(app/'Contents/MacOS').mkdir(parents=True)
 shutil.copy2(ROOT/'.build/sparkle-negative',app/'Contents/MacOS/Test')
 info=dict(CFBundleIdentifier='com.geokhv.cvr-update-tests.'+scenario,CFBundleExecutable='Test',CFBundleName='CVR Update Test',CFBundlePackageType='APPL',CFBundleVersion='3000',CFBundleShortVersionString='0.3.0',LSMinimumSystemVersion='13.0',SUEnableAutomaticChecks=False,SUAutomaticallyUpdate=False,SUAllowsAutomaticUpdates=False,SUVerifyUpdateBeforeExtraction=True,SURequireSignedFeed=True,SUSignedFeedFailureExpirationInterval=0,SUPublicEDKey=(base/'public-key.txt').read_text(),SUFeedURL=f'http://127.0.0.1:{port}/{scenario}.xml')
 # Test server is loopback only. These settings never enter a shipped bundle.
 (app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
 subprocess.run(['codesign','--force','--sign','-',str(app)],check=True,capture_output=True)
 before=(app/'Contents/MacOS/Test').read_bytes()
 r=subprocess.run([str(app/'Contents/MacOS/Test'),scenario],capture_output=True,text=True,timeout=45)
 print(r.stdout.strip());print(r.stderr[-2000:] if r.returncode else '',end='')
 assert r.returncode==0,scenario
 assert (app/'Contents/MacOS/Test').read_bytes()==before
server.shutdown()
print('PASS all original bundles preserved, no installer invoked')
