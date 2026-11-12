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
        (directory/'trial-input.json').write_text(json.dumps(dict(
            mode='stable-map',dns_port=port,dns_backend_port=backend)))
        task=asyncio.create_task(serve(policy,directory,lambda:stopped))
        try:
            for _ in range(100):
                if (directory/'dns-ready').exists():break
                if task.done():await task
                await asyncio.sleep(.01)
            else:raise AssertionError('DNS did not become ready')
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
            assert not (directory/'host-routes.json').exists()
            print('PASS actual UDP/TCP NXDOMAIN with missing backend and outside name; no route changes')
        finally:
            stopped=True
            await task


if __name__=='__main__':asyncio.run(asyncio.wait_for(main(),10))
