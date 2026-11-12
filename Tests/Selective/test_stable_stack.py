import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"Backend/Selective"))
"""Actual packet-stack SOCKS -> authenticated map bridge -> domain witness.

Only loopback and .invalid fixtures. Kill both real processes, reverse DNS
question order, then connect to the retained IPv4 and IPv6 addresses.
"""
import asyncio
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
from types import SimpleNamespace

from pool_config import build
from sparse_dns import decode_name
from services import serve


def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


async def child(directory):
    cfg=json.loads((directory/'trial-input.json').read_text())
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'Backend'))
    import http_router
    async def via_socks(name,port):
        with (directory/'forwarded.jsonl').open('a') as f:
            f.write(json.dumps({'name':name,'port':port})+'\n')
        return await asyncio.open_connection('127.0.0.1',cfg['fixture_port'])
    installed=SimpleNamespace(is_work=http_router.is_work,pump=http_router.pump,via_socks=via_socks)
    await serve(cfg,directory,installed)


async def main(binary):
    async def fixture(r,w):
        try:
            data=await r.read(64);w.write(data);await w.drain()
        finally:w.close()
    origin=await asyncio.start_server(fixture,'127.0.0.1',0)
    names=['alpha.work.cvr-fixture.invalid','beta.work.cvr-fixture.invalid']
    incoming,dns,bridge=free_port(),free_port(),free_port()
    cfg={'mode':'stable-map','host':names[0],'password':'test-only-secret',
         'dns_backend_port':dns,'socks_port':bridge,
         'fixture_port':origin.sockets[0].getsockname()[1],
         'policy':{'sites':[{'domain':'work.cvr-fixture.invalid','scope':'tree'}],
                   'ports':[443],'beforeLogin':['deny.work.cvr-fixture.invalid']}}
    config=build(cfg)
    config['inbounds']=[{'type':'socks','tag':'work-tun','listen':'127.0.0.1','listen_port':incoming}]
    async def query(name,kind):
        r,w=await asyncio.open_connection('127.0.0.1',dns)
        q=struct.pack('!6H',42,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)
        w.write(struct.pack('!H',len(q))+q);n=struct.unpack('!H',await r.readexactly(2))[0]
        answer=await r.readexactly(n);w.close()
        if answer[3]&15:return None
        _,p=decode_name(answer,12);p+=4;_,p=decode_name(answer,p)
        typ,cls,ttl,n=struct.unpack('!HHIH',answer[p:p+10])
        return str(ipaddress.ip_address(answer[p+10:p+10+n]))
    async def connect(address,success=True):
        r,w=await asyncio.open_connection('127.0.0.1',incoming)
        w.write(b'\x05\x01\x00');assert await r.readexactly(2)==b'\x05\x00'
        ip=ipaddress.ip_address(address)
        w.write(bytes([5,1,0,1 if ip.version==4 else 4])+ip.packed+struct.pack('!H',443))
        reply=await r.readexactly(4)
        if success:
            assert reply[:2]==b'\x05\x00',reply
            await r.readexactly((4 if reply[3]==1 else 16)+2)
            w.write(b'opaque-tls-placeholder');await w.drain()
            assert await r.readexactly(22)==b'opaque-tls-placeholder'
        else:assert reply[1]!=0
        w.close()
    with tempfile.TemporaryDirectory(prefix='cvr-stable-stack-') as tmp:
        d=Path(tmp);cfg['map_path']=str(d/'domain-map.json');(d/'trial-input.json').write_text(json.dumps(cfg));(d/'stack.json').write_text(json.dumps(config))
        async def launch():
            svc=await asyncio.create_subprocess_exec(sys.executable,'-B',__file__,'--child',str(d),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
            stack=await asyncio.create_subprocess_exec(binary,'run','-c',str(d/'stack.json'),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
            for _ in range(100):
                try:
                    r,w=await asyncio.open_connection('127.0.0.1',dns);w.close()
                    r,w=await asyncio.open_connection('127.0.0.1',incoming);w.close()
                    return svc,stack
                except OSError:await asyncio.sleep(.03)
            svc.kill();stack.kill();await svc.wait();await stack.wait();raise AssertionError('startup')
        svc,stack=await launch()
        try:
            retained=[await query(names[0],kind) for kind in (1,28)]
            await query(names[1],1)
        finally:svc.kill();stack.kill();await svc.wait();await stack.wait()
        svc,stack=await launch()
        try:
            assert await query(names[1],1)=='198.18.75.3'
            assert await query(names[0],1)==retained[0]
            for addr in retained:await connect(addr)
            for name in ['outside.invalid','deny.work.cvr-fixture.invalid']:
                assert await query(name,1) is None
            await connect('198.18.75.200',False)
            events=[json.loads(x) for x in (d/'forwarded.jsonl').read_text().splitlines()]
            assert events==[{'name':names[0],'port':443}]*2,events
            print(json.dumps({'passed':True,'retained':retained,'domain_after_sigkill':events,
                'unknown_and_excluded_names':'NXDOMAIN','unallocated_IP':'rejected','opaque_payload':'echoed unchanged'},indent=2))
        finally:svc.kill();stack.kill();await svc.wait();await stack.wait()
    origin.close();await origin.wait_closed()


if __name__=='__main__':
    if sys.argv[1]=='--child':asyncio.run(child(Path(sys.argv[2])))
    else:asyncio.run(asyncio.wait_for(main(sys.argv[1]),30))
