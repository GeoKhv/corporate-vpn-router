"""Verify real sing-box fake-IP to domain restoration, loopback only."""
import asyncio
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
from pool_config import build
from sparse_dns import decode_name

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def query(name,kind):
    return struct.pack('!6H',42,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)

async def main(binary):
    hostname='child.work.cvr-fixture.invalid';seen=[]
    async def witness(r,w):
        _,n=await r.readexactly(2);await r.readexactly(n);w.write(b'\x05\x00')
        assert await r.readexactly(4)==b'\x05\x01\x00\x03'
        n=(await r.readexactly(1))[0];name=(await r.readexactly(n)).decode();dest=struct.unpack('!H',await r.readexactly(2))[0]
        seen.append((name,dest));w.write(b'\x05\x00\x00\x01\0\0\0\0\0\0');await w.drain();w.close()
    srv=await asyncio.start_server(witness,'127.0.0.1',0);proxy=srv.sockets[0].getsockname()[1]
    incoming,dns=port(),port()
    cfg=build({'policy':{'sites':[{'domain':'work.cvr-fixture.invalid','scope':'tree'}],'beforeLogin':[],'ports':[443]},'password':'unused'})
    cfg['inbounds']=[{'type':'socks','tag':'work-tun','listen':'127.0.0.1','listen_port':incoming},
                     {'type':'direct','tag':'local-dns','listen':'127.0.0.1','listen_port':dns}]
    cfg['outbounds'][0].update(server_port=proxy);cfg['outbounds'][0].pop('username');cfg['outbounds'][0].pop('password')
    async def ask(name,kind):
        r,w=await asyncio.open_connection('127.0.0.1',dns);q=query(name,kind);w.write(struct.pack('!H',len(q))+q)
        n=struct.unpack('!H',await r.readexactly(2))[0];reply=await r.readexactly(n);w.close();return reply
    with tempfile.TemporaryDirectory(prefix='cvr-fakeip-') as temp:
        p=Path(temp)/'config.json';p.write_text(json.dumps(cfg))
        proc=await asyncio.create_subprocess_exec(binary,'run','-c',str(p),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:reply=await ask(hostname,1);break
                except OSError:await asyncio.sleep(.1)
            else:raise AssertionError('startup failed')
            for kind in (1,28):
                reply=await ask(hostname,kind);_,pos=decode_name(reply,12);pos+=4;_,pos=decode_name(reply,pos)
                typ,cls,ttl,n=struct.unpack('!HHIH',reply[pos:pos+10]);ip=ipaddress.ip_address(reply[pos+10:pos+10+n]);assert typ==kind
                r,w=await asyncio.open_connection('127.0.0.1',incoming);w.write(b'\x05\x01\x00');assert await r.readexactly(2)==b'\x05\x00'
                w.write(bytes([5,1,0,1 if kind==1 else 4])+ip.packed+struct.pack('!H',443));assert (await r.readexactly(4))[:2]==b'\x05\x00';w.close()
            assert seen==[(hostname,443),(hostname,443)],seen
            assert (await ask('outside.invalid',1))[3]&15==3
            reply=await ask(hostname,65);assert struct.unpack('!6H',reply[:12])[3]==0 and reply[3]&15==0
            print('PASS real sing-box: A/AAAA fake-IP -> original SOCKS DOMAIN; tree allowlist; outside NXDOMAIN; HTTPS NODATA; loopback only')
        finally:proc.terminate();await proc.wait()
    srv.close();await srv.wait_closed()

asyncio.run(main(sys.argv[1]))
