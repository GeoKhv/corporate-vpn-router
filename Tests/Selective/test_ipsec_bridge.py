"""Real subprocess/pipe relay; synthetic credentials and packets only, no VPN."""
import ipaddress,json,os,signal,socket,struct,sys,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'Backend'))
import ipsec_session as ip
import session
from trust import Refused

BRIDGE=r'''#!PYTHON
import json,os,socket,sys,time
config=json.loads(sys.stdin.readline())
assert config['address']=='192.0.2.1'
def emit(x):print(json.dumps(x),flush=True)
def rpc(op,fields):emit(dict(rpc=op,fields=fields));return json.loads(sys.stdin.readline())['value']
emit(dict(stage='ipsec_negotiating'))
emit(dict(stage='ipsec_gateway_verified'))
assert rpc('challenge',dict(prompt='OTP'))=='fixture-otp'
assert rpc('challenge',dict(prompt='Password'))=='fixture-password'
emit(dict(stage='authenticated'))
emit(dict(stage='ipsec_connected',address='192.0.2.8',dns=['192.0.2.53']))
s=socket.socket(fileno=int(os.environ['CVR_PACKET_FD']));s.settimeout(5)
p=s.recv(2048);assert len(p)==28 and p[9]==17
s.send(p[:12]+p[16:20]+p[12:16]+p[20:22][::-1]+p[22:])
time.sleep(.3)
assert rpc('signout',dict(session_id='fixture-session')) is None
emit(dict(stage='failed',detail='gateway unavailable fixture-password secret@example.invalid'))
'''
class BridgeTests(unittest.TestCase):
 def test_real_child_relay_and_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   binary=Path(d)/'fake-bridge';binary.write_text(BRIDGE.replace('PYTHON',sys.executable));binary.chmod(0o700)
   adapter=session.PacketVNA();stages=[];state={};received=[];workers=[]
   def status(stage,**fields):state.update(stage=stage,**fields);stages.append((stage,fields))
   def up():
    adapter.is_up=True
    def traffic():
     p=bytearray(28);p[0]=0x45;p[9]=17;p[12:16]=socket.inet_aton('192.0.2.8');p[16:20]=socket.inet_aton('192.0.2.53');p[22:24]=struct.pack('!H',53)
     adapter.dev.peer.settimeout(4);adapter.dev.peer.send(p);received.append(adapter.dev.peer.recv(2048))
    t=threading.Thread(target=traffic);t.start();workers.append(t)
   replies=iter(['fixture-otp','fixture-password'])
   utils=SimpleNamespace(do_ccc_request=lambda *a,**k:SimpleNamespace(serialize=lambda:'settings-response'))
   snapshot=SimpleNamespace(serialize=lambda:'gateway-snapshot')
   with patch.object(ip,'BINARY',binary),patch.object(adapter,'up',up),patch.object(ip,'socks_ready',return_value=True):
    with self.assertRaisesRegex(Refused,'IPSEC_FAILED'):
     ip.run_ipsec('192.0.2.1',snapshot,'fixture-user','fixture-realm',utils,None,adapter,lambda *a:next(replies),status,state)
   for t in workers:t.join(5)
   self.assertEqual(len(received),1);self.assertEqual(len(received[0]),28)
   self.assertEqual(adapter.dev.counts['out_packets'],1);self.assertEqual(adapter.dev.counts['in_packets'],1)
   self.assertIn('connected',[s for s,_ in stages]);self.assertEqual(stages[-1][0],'dataplane_closed')
   self.assertNotIn('fixture-password',json.dumps(stages));self.assertNotIn('secret@',json.dumps(stages))
   self.assertEqual(state['failure_stage'],'ipsec_error');self.assertEqual(adapter.dev.sock.fileno(),-1)
 def test_cancel_at_mfa_reaps_child(self):
  with tempfile.TemporaryDirectory() as d:
   binary=Path(d)/'bridge';binary.write_text(BRIDGE.replace('PYTHON',sys.executable));binary.chmod(0o700)
   adapter=session.PacketVNA();state={};children=[];real=ip.subprocess.Popen
   def track(*a,**k):p=real(*a,**k);children.append(p);return p
   def cancel(*a):raise Refused('INPUT_CANCELLED')
   with patch.object(ip,'BINARY',binary),patch.object(ip.subprocess,'Popen',side_effect=track):
    with self.assertRaisesRegex(Refused,'INPUT_CANCELLED'):
     ip.run_ipsec('192.0.2.1',SimpleNamespace(serialize=lambda:'snapshot'),'fixture','realm',None,None,adapter,cancel,lambda *a,**k:None,state)
   self.assertEqual(len(children),1);self.assertIsNotNone(children[0].poll());self.assertEqual(adapter.dev.sock.fileno(),-1)
 def test_rpc_cannot_inject_request_or_change_destination(self):
  for sid in ('x) :bad (x','x\ny','',None):
   with self.assertRaisesRegex(Refused,'IPSEC_CONTROL_INVALID'):ip.control_rpc('settings',{'session_id':sid},None,None,'192.0.2.1')
  for op in ('settings','fetch'):
   with self.assertRaises(Refused):ip.control_rpc(op,{'session_id':'fixture'},None,None,'192.0.2.1')
 def test_missing_bridge_preserves_ssl(self):
  with patch.object(ip,'BINARY',Path('/does-not-exist/cvr-ipsec')):
   self.assertEqual(ip.select_transport(None,None,None,None),'ssl')
 def test_tls_failure_does_not_fallback(self):
  import ssl
  cfg=SimpleNamespace(CPRR=lambda _:SimpleNamespace(serialize=lambda:'hello'))
  utils=SimpleNamespace(as_bytes=lambda _:b'hello')
  raw=unittest.mock.MagicMock()
  with patch.object(ip.BINARY.__class__,'is_file',return_value=True),patch.object(ip.socket,'create_connection',return_value=raw),patch.object(ip,'require_strict',side_effect=ssl.SSLCertVerificationError('bad cert')):
   with self.assertRaises(ssl.SSLCertVerificationError):ip.select_transport('192.0.2.1',None,cfg,utils)
if __name__=='__main__':unittest.main()
