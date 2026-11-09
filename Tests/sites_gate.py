"""Exercise the packaged native listener, using a private socketpair as its only network."""
import os,select,socket,subprocess,sys,time
from pathlib import Path
engine=Path(sys.argv[1]);sys.path.insert(0,str(engine))
from sites import gate
policy={'version':1,'sites':[{'domain':'corp.test','scope':'tree'},{'domain':'single.test','scope':'exact'}],'beforeLogin':['login.corp.test'],'ports':[443]}
domains,ports=gate(policy)
def check(host,port,allowed):
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    with socket.socket() as temp:
        temp.bind(('127.0.0.1',0));local=temp.getsockname()[1]
    env=dict(VPNFD=str(right.fileno()),INTERNAL_IP4_ADDRESS='192.0.2.9',INTERNAL_IP4_DNS='192.0.2.53',
             INTERNAL_IP4_MTU='1400',CVR_DOMAINS=domains,CVR_PORTS=ports)
    child=subprocess.Popen([engine/'ocproxy','-D','127.0.0.1:'+str(local)],env=env,pass_fds=(right.fileno(),),stderr=subprocess.DEVNULL)
    right.close()
    try:
        for _ in range(80):
            try:s=socket.create_connection(('127.0.0.1',local),.3);break
            except OSError:time.sleep(.025)
        else:raise AssertionError('no listener')
        with s:
            s.settimeout(1);s.sendall(bytes([5,1,0]));assert s.recv(2)==bytes([5,0])
            h=host.encode();s.sendall(bytes([5,1,0,3,len(h)])+h+port.to_bytes(2,'big'))
            if not allowed:assert s.recv(10)[1]==2
            deadline=time.monotonic()+(.9 if allowed else .08);dns=False
            while time.monotonic()<deadline:
                if not select.select([left],[],[],max(0,deadline-time.monotonic()))[0]:break
                packet=left.recv(65535);dns |= len(packet)>28 and packet[9]==17 and packet[22:24]==b'\x00\x35'
                if dns:break
            assert dns==allowed,(host,dns,allowed)
    finally:child.terminate();child.wait(timeout=3);left.close()
for host,port,expected in [('CORP.test',443,True),('a.b.corp.test',443,True),('single.test',443,True),
      ('x.single.test',443,False),('logIN.corp.test',443,False),('notcorp.test',443,False),('corp.test',80,False)]:
    check(host,port,expected)
print('PASS: native allow/deny and DNS emission for seven host/port cases.')
