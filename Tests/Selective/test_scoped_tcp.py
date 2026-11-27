"""Run against the packaged ocproxy. Its entire network is a UNIX socket pair."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

engine = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(engine),str(engine/'Selective')]
from sites import approved, gate, grants, validate
from analyze import target

policy = validate({'version':2,'beforeLogin':['auth.corp.invalid'],'ports':[443],
    'sites':[{'domain':'corp.invalid','scope':'tree','tcp':[22,6443]},
             {'domain':'db.corp.invalid','scope':'exact','alias':'db','tcp':'*'},
             {'domain':'locked.corp.invalid','scope':'tree','tcp':[443]}]})
assert approved(policy,{'tcpRules':grants(policy)})
assert not approved(policy,{'approvedDomains':['corp.invalid'],'approvedPorts':[443]})
assert target('ssh://db') == ('db',22,'ssh')
for text in ('192.0.2.2:22','fd00::2','10.0.0.0/8','https://user:pass@test.invalid','udp://host.invalid'):
    try: target(text)
    except ValueError: pass
    else: raise AssertionError(text)

def checksum(data):
    if len(data)%2:data += b'\0'
    value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value >> 16:value=(value & 65535)+(value>>16)
    return (~value)&65535

def inbound(pkt, proto, data):
    src,dst=pkt[16:20],pkt[12:16]
    pos=6 if proto==17 else 16
    check=checksum(src+dst+struct.pack('!BBH',0,proto,len(data))+data)
    data=data[:pos]+struct.pack('!H',check)+data[pos+2:]
    ip=struct.pack('!BBHHHBBH4s4s',69,0,len(data)+20,1,0,64,proto,0,src,dst)
    return ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]+data

def run(host,port,case):
    raw,peer=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0)); local=probe.getsockname()[1]
    domains,ports=gate(policy)
    env=dict(VPNFD=str(peer.fileno()),INTERNAL_IP4_ADDRESS='192.0.2.9',INTERNAL_IP4_DNS='192.0.2.53',
             INTERNAL_IP4_MTU='1400',CVR_DOMAINS=domains,CVR_PORTS=ports)
    child=subprocess.Popen([engine/'ocproxy','-D',f'127.0.0.1:{local}'],env=env,pass_fds=(peer.fileno(),),stderr=subprocess.DEVNULL)
    peer.close();raw.settimeout(3)
    try:
        for attempt in range(60):
            try:stream=socket.create_connection(('127.0.0.1',local),.2);break
            except OSError:time.sleep(.025)
        else:raise AssertionError('not listening')
        with stream:
            stream.settimeout(3);stream.sendall(b'\x05\x01\0');assert stream.recv(2)==b'\x05\0'
            name=host.encode()
            stream.sendall(bytes([5,1 if port else 240,0,3,len(name)])+name+struct.pack('!H',port))
            if case=='denied':
                assert stream.recv(10)[1]==2
                assert not select.select([raw],[],[],.08)[0];return
            pkt=raw.recv(65535);assert pkt[9]==17
            udp=pkt[20:];q=udp[8:]
            ans=q[:2]+struct.pack('!HHHHH',0x8183 if case=='absent' else 0x8180,1,0 if case=='absent' else 1,0,0)+q[12:]
            if case!='absent':ans+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('192.0.2.25')
            raw.send(inbound(pkt,17,udp[2:4]+udp[:2]+struct.pack('!HH',len(ans)+8,0)+ans))
            if not port:
                assert stream.recv(10)[1] == (4 if case=='absent' else 0)
                # A completed lookup releases its accepted socket on both outcomes.
                assert stream.recv(1) == b''
                if case == 'dns':
                    # Exercise slot reuse across more lookups than the connection pool holds.
                    for _ in range(1100):
                        with socket.create_connection(('127.0.0.1', local), 2) as cached:
                            cached.sendall(b'\x05\x01\x00')
                            assert cached.recv(2) == b'\x05\x00'
                            cached.sendall(bytes([5,240,0,3,len(name)]) + name + bytes(2))
                            with cached.makefile('rb') as reply:
                                assert reply.read(10)[1] == 0
                                assert reply.read(1) == b''
                assert not select.select([raw],[],[],.08)[0];return
            pkt=raw.recv(65535);tcp=pkt[20:];assert pkt[9]==6 and tcp[13]&2
            source,dest,seq=struct.unpack('!HHI',tcp[:8]);assert dest==port
            def send(flags,server_seq,ack,payload=b''):
                packet=struct.pack('!HHIIBBHHH',dest,source,server_seq,ack,80,flags,16384,0,0)+payload
                raw.send(inbound(pkt,6,packet))
            send(18,999,seq+1);assert stream.recv(10)[1]==0
            stream.sendall(b'tcp-proof')
            while True:
                wire=raw.recv(65535)[20:];payload=wire[(wire[12]>>4)*4:]
                if payload:break
            assert payload==b'tcp-proof';send(24,1000,seq+1+len(payload),payload);assert stream.recv(32)==payload
    finally:
        child.terminate();child.wait(timeout=3);raw.close()

for item in [('node.corp.invalid',22,'ok'),('node.corp.invalid',6443,'ok'),('db.corp.invalid',5432,'ok'),
             ('db.corp.invalid',1,'ok'),('db.corp.invalid',65535,'ok'),
             ('db.corp.invalid',0,'dns'),('absent.corp.invalid',0,'absent'),
             ('x.locked.corp.invalid',22,'denied'),('x.db.corp.invalid',5432,'denied'),
             ('other.invalid',22,'denied'),('auth.corp.invalid',0,'denied')]:
    run(*item)
policy['sites'][0]['tcp'] = '*'
for item in [('node.corp.invalid',65535,'ok'),('x.locked.corp.invalid',443,'ok'),
             ('x.locked.corp.invalid',65535,'denied'),('auth.corp.invalid',65535,'denied'),
             ('other.invalid',65535,'denied')]:
    run(*item)
print('PASS packet-socket DNS, NXDOMAIN, selected ports, wildcard TCP boundaries, nested restrictions, exclusions, analyzer parsing')
