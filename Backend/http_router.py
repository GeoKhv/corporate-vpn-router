"""Loopback HTTP/1.1 forward proxy. CONNECT payloads remain opaque."""
import asyncio
import os
import socket
import fcntl
import ipaddress
import json
import re
import struct
import sys
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sites import validate
from policy_control import bind_control, HTTP_CONTROL, SOCKS_CONTROL

DATA = Path.home() / 'Library/Application Support/Corporate VPN Router'
ADDRESS = '127.0.0.1'
PORT = 1091
LIMIT = 65536
FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def authority(value, default=None):
    if not value or any(ord(c) <= 32 or ord(c) == 127 for c in value) or any(c in value for c in '/?#@%\\') or not value.isascii():
        raise ValueError('invalid authority')
    url = urlsplit('//' + value)
    if '[' in value and not re.fullmatch(r'\[[0-9a-fA-F:.]+\](?::[0-9]+)?', value):
        raise ValueError('invalid IPv6 authority')
    host = (url.hostname or '').lower().removesuffix('.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*', host) or len(host) > 253:
            raise ValueError('invalid hostname')
    port = default if url.port is None else url.port
    if not port or value.endswith(':') or not 1 <= port <= 65535:
        raise ValueError('invalid port')
    return host, port


def is_work(cfg, host):
    return host not in cfg['beforeLogin'] and any(
        host == row['domain'] or (row['scope'] == 'tree' and host.endswith('.' + row['domain']))
        for row in cfg['sites'])


async def worker_identity():
    reader, writer = await asyncio.open_unix_connection(SOCKS_CONTROL)
    try:
        writer.write(b'P')
        pid = await asyncio.wait_for(reader.read(32), 4)
        if not pid.isdigit() or int(pid) < 2:
            raise OSError('no verified tunnel')
        return pid
    finally:
        writer.close()


async def via_socks(host, port, proxy_port=1090):
    owner = await worker_identity()
    reader, writer = await asyncio.open_connection(ADDRESS, proxy_port)
    try:
        writer.write(b'\x05\x01\x00')
        if await reader.readexactly(2) != b'\x05\x00':
            raise OSError('SOCKS authentication')
        if await worker_identity() != owner:
            raise OSError('SOCKS generation changed')
        name = host.encode('ascii')
        writer.write(bytes((5, 1, 0, 3, len(name))) + name + struct.pack('!H', port))
        version, status, reserved, kind = await reader.readexactly(4)
        if (version, status, reserved) != (5, 0, 0):
            raise OSError('SOCKS refused')
        size = {1: 4, 4: 16}.get(kind)
        if kind == 3:
            size = (await reader.readexactly(1))[0]
        if size is None:
            raise OSError('SOCKS reply')
        await reader.readexactly(size + 2)
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def pump(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            writer.write_eof()
            return
        writer.write(data)
        await writer.drain()


class Router:
    def __init__(self, policy):
        self.policy = policy
        self.config = None
        self.stamp = None
        self.clients = set()

    def refresh(self):
        try:
            s = self.policy.stat()
            stamp = (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_size)
            if stamp == self.stamp:
                return []
            cfg = validate(json.loads(self.policy.read_bytes()))
        except (ValueError, OSError, KeyError, TypeError):
            stamp, cfg = None, None
        stale = list(self.clients) if cfg != self.config else []
        if stale:
            for task in stale:
                task.cancel()
        self.stamp, self.config = stamp, cfg
        return stale

    async def confirm(self, reader, writer):
        try:
            command = await asyncio.wait_for(reader.readexactly(1), 2)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            writer.close()
            return
        if command != b'S':
            writer.close()
            return
        stale = self.refresh()
        # A watcher may have initiated cancellation just before this barrier.
        stale.extend(t for t in self.clients if t.cancelling() and t not in stale)
        if stale:
            await asyncio.gather(*stale, return_exceptions=True)
        writer.write(b"1" if self.config else b"0")
        writer.close()

    async def watch(self):
        while True:
            self.refresh()
            await asyncio.sleep(.1)

    async def handle(self, reader, writer):
        current = asyncio.current_task()
        upstream = None
        tasks = []
        started = False
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
            lines = head[:-4].split(b'\r\n')
            method, target, version = lines.pop(0).decode('ascii').split(' ')
            if version not in ('HTTP/1.0', 'HTTP/1.1') or not FIELD.fullmatch(method.encode()):
                raise ValueError()
            if any(ord(c) < 33 or ord(c) == 127 for c in target):
                raise ValueError()
            headers = []
            for line in lines:
                k, sep, v = line.partition(b':')
                if not sep or not FIELD.fullmatch(k) or any(c < 32 and c != 9 or c == 127 for c in v):
                    raise ValueError()
                headers.append((k.lower(), v.strip()))
            connect = method == 'CONNECT'
            if connect:
                host, port = authority(target)
            else:
                u = urlsplit(target)
                if u.scheme != 'http' or u.fragment:
                    raise ValueError()
                host, port = authority(u.netloc, 80)
                host_headers = [v for k, v in headers if k == b'host']
                if len(host_headers) != 1 or authority(host_headers[0].decode('ascii'), 80) != (host, port):
                    raise ValueError()
            self.refresh()
            cfg = self.config
            if not cfg:
                raise OSError('policy unavailable')
            self.clients.add(current)
            if is_work(cfg, host):
                if port not in cfg['ports']:
                    raise OSError('port denied')
                opening = via_socks(host, port)
            else:
                # Connect only to resolved non-loopback destinations. Never use HTTP proxy env/system APIs.
                opening = self.direct(host, port)
            remote, upstream = await asyncio.wait_for(opening, 20)
            if connect:
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                started = True
                tasks = [asyncio.create_task(pump(reader, upstream)), asyncio.create_task(pump(remote, writer))]
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    t.result()
                # A client may half-close its upload and continue reading the response.
                if tasks[0] in done:
                    await tasks[1]
            else:
                lengths = [v for k,v in headers if k == b'content-length']
                if len(lengths) > 1 or lengths and (not lengths[0].isdigit() or len(lengths[0]) > 18):
                    raise ValueError()
                if any(k in (b'transfer-encoding', b'upgrade', b'expect') for k,v in headers):
                    raise ValueError()
                hop = {b'connection', b'proxy-connection', b'proxy-authorization', b'keep-alive', b'te', b'trailer'}
                for k,v in headers:
                    if k == b'connection':
                        hop.update(x.strip().lower() for x in v.split(b','))
                if hop.intersection({b'host', b'content-length'}):
                    raise ValueError()
                path = (u.path or '/') + ('?' + u.query if u.query else '')
                upstream.write(f'{method} {path} HTTP/1.1\r\n'.encode('ascii'))
                for k,v in headers:
                    if k not in hop:
                        upstream.write(k + b': ' + v + b'\r\n')
                upstream.write(b'Connection: close\r\n\r\n')
                remain = int(lengths[0]) if lengths else 0
                while remain:
                    chunk = await reader.readexactly(min(65536, remain))
                    upstream.write(chunk)
                    await upstream.drain()
                    remain -= len(chunk)
                started = True
                await pump(remote, writer)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            if not started:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        finally:
            self.clients.discard(current)
            for task in tasks:
                task.cancel()
            if upstream:
                upstream.transport.abort()
            if current.cancelling():
                writer.transport.abort()
            else:
                writer.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def direct(self, host, port):
        loop = asyncio.get_running_loop()
        addrs = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        for family, kind, proto, _, addr in addrs:
            ip = ipaddress.ip_address(addr[0].split('%')[0])
            ipv4 = getattr(ip, 'ipv4_mapped', None) or ip
            if ipv4.is_loopback or ipv4.is_unspecified:
                continue
            sock = socket.socket(family, kind, proto)
            sock.setblocking(False)
            try:
                await loop.sock_connect(sock, addr)
                return await asyncio.open_connection(sock=sock)
            except OSError:
                sock.close()
            except BaseException:
                sock.close()
                raise
        raise OSError('direct connection failed')


async def main():
    os.umask(0o077)
    os.chdir(DATA)
    lock = open('http-router.lock','a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    router = Router(DATA / 'work-sites.json')
    router.refresh()
    server = await asyncio.start_server(router.handle, ADDRESS, PORT, limit=LIMIT)
    control = await asyncio.start_unix_server(router.confirm, sock=bind_control(HTTP_CONTROL))
    async with server, control:
        await asyncio.gather(router.watch(), server.serve_forever(), control.serve_forever())


if __name__ == '__main__':
    asyncio.run(main())
