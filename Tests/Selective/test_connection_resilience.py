"""Bounded serial dialing, strict TLS, persistent CCC and zero request replay."""
import asyncio
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

engine=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(engine));sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import connection_resilience as resilience
import tls_policy
import beta_tls
import session


def bounded_tests():
    now=[0.0];calls=[];raw=SimpleNamespace(settimeout=lambda value:calls.append(('restore',value)))
    def transient(address,timeout):
        calls.append(('dial',timeout))
        if len(calls)==1:
            now[0]+=timeout;raise TimeoutError('first dial')
        return raw
    with patch.object(resilience.time,'monotonic',lambda:now[0]),patch.object(socket,'create_connection',transient):
        assert resilience.connect(('192.0.2.1',443),10) is raw
    assert calls==[('dial',5.0),('dial',5.0),('restore',10)],calls
    now[0]=0;calls.clear()
    def unavailable(address,timeout):
        calls.append(timeout);now[0]+=timeout;raise TimeoutError()
    with patch.object(resilience.time,'monotonic',lambda:now[0]),patch.object(socket,'create_connection',unavailable):
        try:resilience.connect(('192.0.2.1',443),10)
        except TimeoutError:pass
        else:raise AssertionError('unavailable accepted')
    assert calls==[5,5] and now[0]==10
    with patch.object(socket,'create_connection',side_effect=PermissionError(13,'')) as call:
        try:resilience.connect(('192.0.2.1',443),10)
        except PermissionError:pass
        assert call.call_count==1
    with patch.object(resilience.subprocess,'run',side_effect=[
        subprocess.CompletedProcess([],1,b''),subprocess.CompletedProcess([],1,b'-----BEGIN CERTIFICATE-----')]) as call:
        assert resilience.discover(['fixture'],12).stdout
        assert call.call_count==2
    with patch.object(resilience.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'-----BEGIN CERTIFICATE-----')) as call:
        resilience.discover(['fixture'],12);assert call.call_count==1,'partial chain must reach strict validator without retry'


async def async_bounds():
    closed=[];made=[];calls=[]
    class Raw:
        def __init__(self,*a):made.append(self)
        def setblocking(self,value):assert value is False
        def close(self):closed.append(self)
    loop=asyncio.get_running_loop()
    async def transient(raw,address):
        calls.append(raw)
        if len(calls)==1:raise ConnectionRefusedError(61,'')
    with patch.object(resilience.socket,'socket',Raw),patch.object(loop,'sock_connect',transient):
        result=await resilience.connect_async(('192.0.2.1',443))
    assert len(made)==2 and closed==[made[0]] and result is made[1]
    made.clear();closed.clear()
    async def cancelled(*args):raise asyncio.CancelledError()
    with patch.object(resilience.socket,'socket',Raw),patch.object(loop,'sock_connect',cancelled):
        try:await resilience.connect_async(('192.0.2.1',443))
        except asyncio.CancelledError:pass
        else:raise AssertionError('cancel swallowed')
    assert len(made)==1 and closed==made


class Server(http.server.ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,context,mode):
        self.context=context;self.mode=mode;self.accepts=0;self.bodies=[]
        super().__init__(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.serve_forever,daemon=True);self.thread.start()
    def get_request(self):
        raw,address=super().get_request();self.accepts+=1
        try:return self.context.wrap_socket(raw,server_side=True),address
        except BaseException:raw.close();raise
    def finish(self):
        tls_policy.close_control();self.shutdown();self.server_close();self.thread.join(2)
    def handle_error(self,*args):
        # The production dataplane deliberately aborts its transport at cleanup.
        if isinstance(sys.exception(),ConnectionResetError):return
        raise AssertionError('fixture handler failure')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_POST(self):
        self.server.bodies.append(self.rfile.read(int(self.headers['Content-Length'])))
        if self.server.mode=='drop':
            self.close_connection=True;return
        self.send_response(200);self.send_header('Content-Length','2')
        self.send_header('Connection','close' if self.server.mode=='close' else 'keep-alive')
        self.end_headers();self.wfile.write(b'ok');self.wfile.flush()
        if self.server.mode=='stale':self.close_connection=True


def channel_tests():
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='cvr-channel-test-') as temp:
        base=Path(temp)
        (base/'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Test Root\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        beta_tls.openssl(base,'req','-new','-x509','-newkey','rsa:2048','-nodes','-days','1','-config','ca.cnf','-keyout','ca.key','-out','ca.pem')
        beta_tls.openssl(base,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Loopback','-keyout','leaf.key','-out','leaf.csr')
        (base/'leaf.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n')
        beta_tls.openssl(base,'x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','leaf.cnf','-out','leaf.pem')
        context=tls_policy.pinned_context(base/'ca.pem',hashlib.sha256(ssl.PEM_cert_to_DER_cert((base/'ca.pem').read_text())).hexdigest())
        server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_context.load_cert_chain(base/'leaf.pem',base/'leaf.key')
        real_connect=socket.create_connection
        for mode in ('keep','close','drop','stale'):
            fixture=Server(server_context,mode);ssl_ctx=SimpleNamespace();utils=SimpleNamespace()
            tls_policy.install(ssl_ctx,utils,'127.0.0.1',context,resilient=True)
            def dial(address,timeout):
                assert address==('127.0.0.1',443)
                return real_connect(('127.0.0.1',fixture.server_port),timeout=timeout)
            try:
                with patch.object(socket,'create_connection',dial):
                    if mode=='drop':
                        try:utils.do_https_request('https://127.0.0.1/clients/',data='DUMMY_OTP')
                        except http.client.RemoteDisconnected:pass
                        else:raise AssertionError('dropped response accepted')
                        assert fixture.accepts==1 and fixture.bodies==[b'DUMMY_OTP'],'application request replayed'
                    elif mode=='stale':
                        assert utils.do_https_request('https://127.0.0.1/clients/',data='FIRST')=='ok'
                        try:utils.do_https_request('https://127.0.0.1/clients/',data='SECOND')
                        except (OSError,http.client.HTTPException):pass
                        else:raise AssertionError('silently replayed stale connection')
                        assert fixture.accepts==1 and fixture.bodies==[b'FIRST']
                    else:
                        for body in ('ONE','TWO'):
                            assert utils.do_https_request('https://127.0.0.1/clients/',data=body)=='ok'
                        assert fixture.accepts==(1 if mode=='keep' else 2)
                        tls_policy.close_control() # exact hook called before human prompt
                        assert utils.do_https_request('https://127.0.0.1/clients/',data='AFTER_PROMPT')=='ok'
                        assert fixture.accepts==(2 if mode=='keep' else 3)
                        assert fixture.bodies==[b'ONE',b'TWO',b'AFTER_PROMPT']
            finally:fixture.finish()

        async def actual_dataplane():
            fixture=Server(server_context,'keep')
            loop=asyncio.get_running_loop();real_dial=loop.sock_connect
            attempts=[];hellos=[];closed=[]
            class Adapter:
                def __init__(self):
                    self.dev=SimpleNamespace(transport=None,counts={});self.proc=None;self.is_up=False
                def close(self):closed.append(True)
            class Protocol(asyncio.Protocol):
                def __init__(self,adapter,cookie,version,ranges,stop):self.stop=stop
                def send_client_hello(self):hellos.append(True);self.stop.set()
            async def dial(raw,address):
                assert address==('127.0.0.1',443);attempts.append(address)
                if len(attempts)==1:raise ConnectionRefusedError(61,'')
                return await real_dial(raw,('127.0.0.1',fixture.server_port))
            session.STATE.clear();session.STATE['close_reason']='local_signal'
            try:
                with patch.object(session,'RESILIENT',True),patch.object(session,'PacketVNA',Adapter),patch.object(loop,'sock_connect',dial),patch.object(session,'status',lambda stage,**v:session.STATE.update(stage=stage,**v)):
                    await session.dataplane(SimpleNamespace(cookie='DUMMY_NOT_LOGGED'),'127.0.0.1',context,SimpleNamespace(SNXHandler=Protocol),[])
                assert len(attempts)==2 and hellos==[True] and closed==[True]
                assert fixture.accepts==1 and fixture.bodies==[]
            finally:fixture.finish()
        asyncio.run(actual_dataplane())


bounded_tests();asyncio.run(async_bounds());beta_tls.main(resilient=True);channel_tests()
print('PASS 2 serial TCP dials within original budget, cancel cleanup, no partial-chain bypass, strict TLS, persistence/close fallback, no HTTP/OTP replay, prompt socket release')
