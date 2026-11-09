"""Real installed Chrome network stack, disposable profile, synthetic DNS and HTTP origin.
Never alters a user's Chrome preferences. Run before installing any Chrome proxy policy.
The policy precedence/installation in the ordinary profile is a separate acceptance check.
"""
import base64, http.server, json, os, subprocess, sys, tempfile, threading, uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Backend'))
from sites import validate

def pac(cfg):
    validate(cfg)
    # No DNS calls, HTTP service, lifetime dependency on the menu, or DIRECT alternative on a Work match.
    return ('function FindProxyForURL(url,host){var h=host.toLowerCase().replace(/\\.+$/,"");'
        +'var b='+json.dumps(cfg['beforeLogin'],separators=(',',':'))+';if(b.indexOf(h)>=0)return "DIRECT";'
        +'var r='+json.dumps([[s['domain'],s['scope']=='tree'] for s in cfg['sites']],separators=(',',':'))+';'
        +'for(var i=0;i<r.length;i++){var d=r[i][0];if(h===d||(r[i][1]&&h.slice(-d.length-1)==="."+d))return "SOCKS5 127.0.0.1:1090";}return "DIRECT";}')

def proxy(cfg):
    return {'ProxyMode':'pac_script','ProxyPacMandatory':True,'ProxyPacUrl':'data:application/x-ns-proxy-autoconfig;base64,'+base64.b64encode(pac(cfg).encode()).decode()}

chrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
seen=[]
class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        seen.append(self.path)
        self.send_response(200);self.end_headers();self.wfile.write(b'CVR-DIRECT-WITNESS')
srv=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
threading.Thread(target=srv.serve_forever,daemon=True).start()
cfg=proxy(dict(version=1,sites=[dict(domain='work.test',scope='tree')],beforeLogin=['login.work.test'],ports=[443]))
def run(host,pac,mandatory,direct):
    path='/'+uuid.uuid4().hex
    target='http://'+host+':'+str(srv.server_port)+path
    with tempfile.TemporaryDirectory() as tmp:
        dest=Path(tmp)/'Default';dest.mkdir()
        (dest/'Preferences').write_text(json.dumps({'proxy':{'mode':'pac_script','pac_url':pac,'pac_mandatory':mandatory}}))
        p=subprocess.run([chrome,'--headless','--user-data-dir='+tmp,'--log-net-log='+tmp+'/netlog.json','--no-first-run','--disable-background-networking',
            '--host-resolver-rules=MAP *.test 127.0.0.1','--dump-dom',target],capture_output=True,timeout=35)
        hit=path in seen
        assert hit==direct and (b'CVR-DIRECT-WITNESS' in p.stdout)==direct,(host,hit,direct)
        if not direct:
            net=json.loads((Path(tmp)/'netlog.json').read_text())
            ids={e['source']['id'] for e in net['events'] if e.get('params',{}).get('url')==target}
            errors={e.get('params',{}).get('net_error') for e in net['events'] if e['source']['id'] in ids}
            assert errors & {-130,-131,-120},(host,errors,p.returncode)
        print(host,'origin reached' if hit else 'blocked at browser',flush=True)
try:
    run('login.work.test',cfg['ProxyPacUrl'],True,True)
    run('fresh.work.test',cfg['ProxyPacUrl'],True,False)
    # HTTP origin is reachable on this identical host without mandatory PAC.
    bad='data:application/x-ns-proxy-autoconfig;base64,'+base64.b64encode(b'! invalid {{{').decode()
    run('broken.test',bad,False,True)
    run('broken.test',bad,True,False)
finally:srv.shutdown()
