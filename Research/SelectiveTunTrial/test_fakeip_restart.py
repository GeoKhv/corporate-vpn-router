"""Measure domain identity across real sing-box restarts; loopback only.

No TUN, system DNS, administrator privilege, corporate names or production
SOCKS are used. A caller deliberately retains a previous DNS answer while the
adapter restarts and sees the same two names in the reverse order.
"""
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


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def question(name):
    labels=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))
    return struct.pack('!6H',42,0x100,1,0,0,0)+labels+b'\0'+struct.pack('!HH',1,1)


async def measure(binary, persistent, crash):
    alpha='alpha.work.cvr-fixture.invalid'
    beta='beta.work.cvr-fixture.invalid'
    observed=[]
    async def witness(r,w):
        try:
            _,n=await r.readexactly(2)
            await r.readexactly(n)
            w.write(b'\x05\x00')
            assert await r.readexactly(4)==b'\x05\x01\x00\x03'
            n=(await r.readexactly(1))[0]
            observed.append((await r.readexactly(n)).decode())
            await r.readexactly(2)
            w.write(b'\x05\x00\x00\x01\0\0\0\0\0\0')
            await w.drain()
        finally:w.close()
    server=await asyncio.start_server(witness,'127.0.0.1',0)
    incoming,dns=free_port(),free_port()
    cfg=build({'policy':{'sites':[{'domain':'work.cvr-fixture.invalid','scope':'tree'}],
                        'beforeLogin':[],'ports':[443]},'password':'unused'})
    cfg['inbounds']=[{'type':'socks','tag':'work-tun','listen':'127.0.0.1','listen_port':incoming},
                     {'type':'direct','tag':'local-dns','listen':'127.0.0.1','listen_port':dns}]
    out=cfg['outbounds'][0]
    out.update(server_port=server.sockets[0].getsockname()[1])
    out.pop('username');out.pop('password')

    async def ask(name):
        r,w=await asyncio.open_connection('127.0.0.1',dns)
        q=question(name);w.write(struct.pack('!H',len(q))+q)
        n=struct.unpack('!H',await r.readexactly(2))[0]
        response=await r.readexactly(n);w.close()
        _,p=decode_name(response,12);p+=4;_,p=decode_name(response,p)
        kind,cls,ttl,n=struct.unpack('!HHIH',response[p:p+10])
        assert kind==1
        return str(ipaddress.ip_address(response[p+10:p+10+n]))

    async def connect_cached(address):
        r,w=await asyncio.open_connection('127.0.0.1',incoming)
        w.write(b'\x05\x01\x00')
        assert await r.readexactly(2)==b'\x05\x00'
        w.write(b'\x05\x01\x00\x01'+ipaddress.ip_address(address).packed+struct.pack('!H',443))
        assert (await r.readexactly(4))[:2]==b'\x05\x00'
        w.close()

    with tempfile.TemporaryDirectory(prefix='cvr-fakeip-restart-') as tmp:
        directory=Path(tmp)
        if persistent:
            cfg['experimental']={'cache_file':{'enabled':True,'path':str(directory/'cache.db'),
                                               'store_fakeip':True}}
        path=directory/'config.json';path.write_text(json.dumps(cfg))
        async def start():
            p=await asyncio.create_subprocess_exec(binary,'run','-c',str(path),
                stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
            for _ in range(50):
                try:
                    r,w=await asyncio.open_connection('127.0.0.1',dns);w.close();return p
                except OSError:await asyncio.sleep(.05)
            p.kill();await p.wait();raise AssertionError('startup failed')
        process=await start()
        try:
            retained=await ask(alpha)
            await ask(beta)
        finally:
            process.kill() if crash else process.terminate()
            await process.wait()
        process=await start()
        try:
            new_beta=await ask(beta)
            new_alpha=await ask(alpha)
            await connect_cached(retained)
            result=dict(persistent=persistent,crash=crash,retained_alpha=retained,
                        new_alpha=new_alpha,new_beta=new_beta,forwarded=observed[-1],
                        identity_preserved=observed[-1]==alpha)
        finally:process.terminate();await process.wait()
    server.close();await server.wait_closed()
    return result


async def main():
    rows=[]
    for persistent,crash in [(False,False),(True,False),(True,True)]:
        rows.append(await measure(sys.argv[1],persistent,crash))
    print(json.dumps(rows,indent=2))
    assert not rows[0]['identity_preserved'], 'Uncached control changed; reassess the baseline'
    assert rows[1]['identity_preserved'] and rows[2]['identity_preserved'], 'Persistent identity not accepted'


if __name__=='__main__':asyncio.run(asyncio.wait_for(main(),30))
