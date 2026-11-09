"""CONNECT byte integrity, route changes, remote-only DNS and HTTP request isolation."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch, AsyncMock

sys.path.insert(0, sys.argv[1])
import http_router as proxy


async def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)/'sites'
        def save(extra=False):
            cfg = dict(version=1, sites=[dict(domain='work.example',scope='tree')],
                       beforeLogin=['login.work.example'],ports=[443])
            if extra:
                cfg['sites'].append(dict(domain='life.example',scope='exact'))
            stage=path.with_suffix('.tmp')
            stage.write_text(json.dumps(cfg))
            stage.replace(path)
        save()
        router = proxy.Router(path)
        server = await asyncio.start_server(router.handle, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        seen, direct = [], []
        async def echo(reader,writer):
            try:
                while chunk := await reader.read(65536):
                    writer.write(chunk)
                    await writer.drain()
            finally:
                writer.close()
        async def socks(reader,writer):
            try:
                assert await reader.readexactly(3)==bytes([5,1,0])
                writer.write(bytes([5,0]))
                req=await reader.readexactly(5)
                assert req[:4]==bytes([5,1,0,3])
                host=(await reader.readexactly(req[4])).decode()
                seen.append((host,int.from_bytes(await reader.readexactly(2),'big')))
                writer.write(bytes([5,0,0,1,0,0,0,0,0,0]))
                await echo(reader,writer)
            finally:
                writer.close()
        peer=await asyncio.start_server(socks,'127.0.0.1',0)
        peer_port=peer.sockets[0].getsockname()[1]
        origin=await asyncio.start_server(echo,'127.0.0.1',0)
        async def ordinary(host,port):
            direct.append(host)
            return await asyncio.open_connection('127.0.0.1',origin.sockets[0].getsockname()[1])
        async def tunnel(host, port):
            return await original(host,port,peer_port)
        async def open_proxy(host, expected=200, suffix=':443'):
            r,w=await asyncio.open_connection('127.0.0.1',port)
            w.write(f'CONNECT {host}{suffix} HTTP/1.1\r\nHost: {host}{suffix}\r\n\r\n'.encode())
            assert (await r.readuntil(b'\r\n\r\n')).startswith(f'HTTP/1.1 {expected} '.encode())
            return r,w
        original=proxy.via_socks
        async with server,origin,peer:
            with patch.object(proxy,'worker_identity',AsyncMock(return_value=b'fixture')), patch.object(proxy,'via_socks',tunnel),patch.object(router,'direct',ordinary):
                r,w=await open_proxy('files.WORK.example.')
                payload=os.urandom(4*1024*1024)
                w.write(payload)
                assert hashlib.sha256(await r.readexactly(len(payload))).digest()==hashlib.sha256(payload).digest()
                assert seen==[('files.work.example',443)] and direct==[]
                lr,lw=await open_proxy('life.example')
                ar,aw=await open_proxy('login.work.example')
                assert direct==['life.example','login.work.example']
                await open_proxy('files.work.example',502,':80')
                save(True)
                socketpath=str(Path(tmp)/'ctl')
                ctl=await asyncio.start_unix_server(router.confirm,socketpath)
                async with ctl:
                    cr,cw=await asyncio.open_unix_connection(socketpath)
                    cw.write(b'S')
                    assert await cr.read()==b'1'
                    cw.close()
                for reader,writer in [(r,w),(lr,lw),(ar,aw)]:
                    assert await asyncio.wait_for(reader.read(),1)==b''
                    writer.close()
                r,w=await open_proxy('life.example')
                assert seen[-1]==('life.example',443) and direct==['life.example','login.work.example']
                await asyncio.sleep(.2)
                w.write(b'still-alive');assert await r.readexactly(11)==b'still-alive'
                w.close()
                peer.close();await peer.wait_closed()
                await open_proxy('life.example',502)
                r,w=await open_proxy('ordinary.example');w.write(b'life');assert await r.readexactly(4)==b'life';w.close()
                path.write_text('{}');await open_proxy('ordinary.example',502)
                save()
                r,w=await asyncio.open_connection('127.0.0.1',port)
                w.write(b'GET http://work.example/ HTTP/1.1\r\nHost: life.example\r\n\r\n')
                assert (await r.read()).startswith(b'HTTP/1.1 502');w.close()
        for h in ['work.example:0','work.example:','user@work.example:443','[::1]x:443','bad..example:443','a\tb.example:443']:
            try:proxy.authority(h)
            except ValueError:pass
            else:raise AssertionError('invalid authority accepted')
    print('PASS CONNECT 4 MiB SHA-256, SOCKS ATYP=DOMAIN, separate Life route, exact auth exception, port denial, save barrier, stream revocation, tunnel loss and invalid policy.')

asyncio.run(asyncio.wait_for(main(),25))
