"""A real ocproxy with a private packet FD, no gateway, and no system routing changes."""
import json, os, select, socket, subprocess, sys, tempfile, time
from pathlib import Path
engine=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(engine))
from policy_control import synchronize, SOCKS_CONTROL

def wait_until(check):
    until=time.monotonic()+5
    while time.monotonic()<until:
        try:
            value=check()
            if value:return value
        except (OSError,ValueError):
            pass
        time.sleep(.04)
    raise AssertionError('worker did not become ready')

with tempfile.TemporaryDirectory() as tmp:
    data=Path(tmp)/'Library/Application Support/Corporate VPN Router'
    data.mkdir(parents=True)
    old=Path.cwd()
    os.chdir(data)
    def put(host):
        p=Path('pending')
        p.write_text(json.dumps(dict(version=1,sites=[dict(domain=host,scope='exact')],ports=[443],beforeLogin=[])))
        p.replace('work-sites.json')
    put('old.example')
    with socket.socket() as unused:
        unused.bind(('127.0.0.1',0))
        port=unused.getsockname()[1]
    packets,child_side=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    life,watch=os.pipe()
    env=dict(HOME=tmp, VPNFD=str(child_side.fileno()),INTERNAL_IP4_ADDRESS='192.0.2.9',
             INTERNAL_IP4_DNS='192.0.2.53',INTERNAL_IP4_MTU='1400')
    proc=subprocess.Popen([sys.executable,'-I','-B',engine/'proxy_supervisor.py',str(life),str(port)],env=env,pass_fds=(life,child_side.fileno()))
    os.close(life);child_side.close()
    def owner():
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as ctl:
            ctl.connect(SOCKS_CONTROL);ctl.sendall(b'P');return int(ctl.recv(32))
    def request(name):
        s=socket.create_connection(('127.0.0.1',port),1)
        s.sendall(bytes([5,1,0]));assert s.recv(2)==bytes([5,0])
        h=name.encode()
        s.sendall(bytes([5,1,0,3,len(h)])+h+bytes([1,187]))
        return s
    try:
        first=wait_until(owner)
        with request('old.example') as pending:
            put('new.example')
            synchronize(SOCKS_CONTROL,True)
            assert wait_until(owner)!=first
            assert pending.recv(16)==b''
        with request('old.example') as denied:
            assert denied.recv(10)[1]==2
        with request('new.example'):
            until=time.monotonic()+2
            while time.monotonic()<until:
                if select.select([packets],[],[],.2)[0] and b'\x03new\x07example' in packets.recv(65536):break
            else:raise AssertionError('no new in-tunnel DNS')
        os.close(watch);watch=None
        proc.wait(timeout=4)
        try:socket.create_connection(('127.0.0.1',port),.3)
        except OSError:pass
        else:raise AssertionError('worker survived lifetime pipe')
    finally:
        if watch is not None:os.close(watch)
        proc.wait(timeout=4);packets.close();os.chdir(old)
print('PASS real native SOCKS owner, resolve before edit, revoke old stream, reject removed name, remote DNS for added name and parent lifetime.')
