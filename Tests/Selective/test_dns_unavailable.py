import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"Backend/Selective"))
"""Real loopback DNS refuses conclusively when its backend is absent.

No TUN, root, system DNS, routes, Work names or external sockets are used.
"""
import asyncio
import json
from pathlib import Path
import socket
import struct
import tempfile

from sparse_dns import serve


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


async def main():
    policy={'sites':[{'domain':'work.cvr-fixture.invalid','scope':'tree'}],
            'beforeLogin':[],'ports':[443]}
    port,backend=free_port(),free_port()
    assert port!=backend
    stopped=False
    with tempfile.TemporaryDirectory(prefix='cvr-dns-refusal-') as tmp:
        directory=Path(tmp)
        retained = [(f'198.18.75.{slot}', f'fdc7:7652:9a10:75::{slot:x}') for slot in range(2, 21)]
        (directory/'trial-input.json').write_text(json.dumps(dict(
            mode='stable-map',dns_port=port,dns_backend_port=backend,
            retained_addresses=[address for pair in retained for address in pair])))
        ready = asyncio.Event()
        installed = []
        async def install(addresses):
            assert not ready.is_set() and not (directory/'dns-ready').exists()
            installed.append(tuple(map(str, addresses)))
        task=asyncio.create_task(serve(policy,directory,lambda:stopped,route_installer=install,ready=ready))
        try:
            for _ in range(100):
                if (directory/'dns-ready').exists():break
                if task.done():await task
                await asyncio.sleep(.01)
            else:raise AssertionError('DNS did not become ready')
            assert ready.is_set() and installed == retained
            for name in ('alpha.work.cvr-fixture.invalid','outside.cvr-fixture.invalid'):
                packet=struct.pack('!6H',42,0x100,1,0,0,0)+b''.join(
                    bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
                reader,writer=await asyncio.open_connection('127.0.0.1',port)
                writer.write(struct.pack('!H',len(packet))+packet)
                size=struct.unpack('!H',await reader.readexactly(2))[0]
                reply=await reader.readexactly(size)
                writer.close();await writer.wait_closed()
                assert reply[:2]==packet[:2] and reply[3]&15==3
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                sock.setblocking(False)
                try:
                    loop=asyncio.get_running_loop()
                    await loop.sock_connect(sock,('127.0.0.1',port))
                    await loop.sock_sendall(sock,packet)
                    reply=await loop.sock_recv(sock,4096)
                    assert reply[:2]==packet[:2] and reply[3]&15==3
                finally:sock.close()
            assert installed == retained
            assert set(json.loads((directory/'host-routes.json').read_text())) == {address for pair in retained for address in pair}
            print('PASS 38 retained routes in 19 requests before UDP/TCP readiness; unavailable DNS adds no routes')
        finally:
            stopped=True
            await task


if __name__=='__main__':asyncio.run(asyncio.wait_for(main(),10))
