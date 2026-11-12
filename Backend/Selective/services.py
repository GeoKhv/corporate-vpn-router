"""Private, exact-name DNS + authenticated SOCKS witness. No system mutations.

Only configured corporate names are answered; DNS is never forwarded. TCP/443
uses the installed beta.6 worker identity check and ATYP=DOMAIN. TLS is opaque.
Private selective TUN backend. The original transport and TLS remain unchanged.
"""
import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time


def dns_answer(packet, cfg, registry=None, is_allowed=None):
    if len(packet) < 12:
        raise ValueError('short DNS')
    ident, flags, count, _, _, _ = struct.unpack('!6H', packet[:12])
    if count != 1 or flags & 0xf800:
        raise ValueError('unsupported DNS question')
    pos, labels = 12, []
    while True:
        n = packet[pos]
        pos += 1
        if n == 0:
            break
        if n > 63 or pos + n > len(packet):
            raise ValueError('invalid label')
        labels.append(packet[pos:pos+n].decode('ascii').lower())
        pos += n
    name = '.'.join(labels)
    kind, cls = struct.unpack('!HH', packet[pos:pos+4])
    end = pos + 4
    allowed = (is_allowed(name) if is_allowed else name == cfg['host']) and cls == 1
    data = b''
    refusal=None
    if allowed and kind in (1, 28):
        try:
            address=registry.address(name,4 if kind==1 else 6) if registry else cfg['ipv4' if kind == 1 else 'ipv6']
            data = ipaddress.ip_address(address).packed
        except (OSError,ValueError) as exc:
            # A conclusive negative answer, never a timeout or public fallback.
            allowed=False;refusal=type(exc).__name__+': '+str(exc)
    # Exact name only; no wildcard, no upstream, no HTTPS/SVCB address hints.
    rcode = 0 if allowed else 3
    header = struct.pack('!6H', ident, 0x8480 | (flags & 0x0100) | rcode, 1, bool(data), 0, 0)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 1, len(data)) + data if data else b''
    return header + packet[12:end] + answer, dict(event='dns', name=name, type=kind, rcode=rcode, refusal=refusal)


async def serve(cfg, directory, installed=None):
    if installed is None:
        engine = Path(__file__).resolve().parent.parent
        sys.path.insert(0, str(engine))
        import http_router as installed
        installed.SOCKS_CONTROL = str(Path.home() / 'Library/Application Support/Corporate VPN Router/socks-worker.sock')
    stable=cfg.get('mode')=='stable-map'
    registry=None
    if stable:
        from domain_map import DomainMap
        registry=DomainMap(Path(cfg['map_path']))
    def allowed_dns(name):
        return installed.is_work(cfg['policy'],name)
    log = (directory / 'services.jsonl').open('a', buffering=1)

    def record(**event):
        log.write(json.dumps(dict(time=time.time(), **event)) + '\n')

    class DNS(asyncio.DatagramProtocol):
        def connection_made(self, transport): self.transport = transport
        def datagram_received(self, packet, addr):
            try:
                reply, event = dns_answer(packet, cfg, registry, allowed_dns if stable else None)
                record(**event)
                self.transport.sendto(reply, addr)
            except (ValueError, IndexError, struct.error, UnicodeError):
                record(event='dns_rejected')

    async def dns_tcp(reader, writer):
        try:
            while True:
                n = struct.unpack('!H', await asyncio.wait_for(reader.readexactly(2), 5))[0]
                reply, event = dns_answer(await asyncio.wait_for(reader.readexactly(n), 5), cfg, registry, allowed_dns if stable else None)
                record(**event)
                writer.write(struct.pack('!H', len(reply)) + reply)
                await writer.drain()
        except (ValueError, IndexError, struct.error, UnicodeError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()

    async def socks(reader, writer):
        upstream = None
        pumps = []
        try:
            version, n = await asyncio.wait_for(reader.readexactly(2), 4)
            methods = await reader.readexactly(n)
            if version != 5 or 2 not in methods:
                raise ValueError('authentication required')
            writer.write(b'\x05\x02')
            ver, n = await reader.readexactly(2)
            username = await reader.readexactly(n)
            n = (await reader.readexactly(1))[0]
            password = await reader.readexactly(n)
            if ver != 1 or username != b'trial' or password.decode('ascii') != cfg['password']:
                raise ValueError('authentication refused')
            writer.write(b'\x01\x00')
            ver, command, reserved, atyp = await reader.readexactly(4)
            if (ver, command, reserved) != (5,1,0) or atyp not in ((1,3,4) if stable else (3,)):
                record(event='socks_rejected', atyp=atyp, command=command)
                raise ValueError('requires CONNECT by domain')
            if atyp==3:
                n = (await reader.readexactly(1))[0]
                name = (await reader.readexactly(n)).decode('ascii')
            else:
                address=str(ipaddress.ip_address(await reader.readexactly(4 if atyp==1 else 16)))
                name=registry.name_for_ip(address)
                record(event='synthetic_to_domain',address=address,name=name,input_atyp=atyp)
            port = struct.unpack('!H', await reader.readexactly(2))[0]
            record(event='socks_domain', name=name, port=port, atyp=atyp)
            allowed = name == cfg['host']
            if cfg.get('mode') in ('domain-pool','stable-map'):
                allowed = installed.is_work(cfg['policy'], name)
            if not allowed or port not in cfg.get('policy', {}).get('ports', [443]):
                raise ValueError('outside exact allowlist')
            ur, uw = await asyncio.wait_for(installed.via_socks(name, port), 12)
            upstream = uw
            writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            record(event='work_connected', name=name)
            pumps = [asyncio.create_task(installed.pump(reader, uw)), asyncio.create_task(installed.pump(ur, writer))]
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        except Exception as exc:
            record(event='socks_error', error=type(exc).__name__, detail=str(exc))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        finally:
            for task in pumps: task.cancel()
            if upstream: upstream.close()
            writer.close()

    loop = asyncio.get_running_loop()
    udp = tcp = None
    if cfg.get('mode') != 'domain-pool':
        dns_port=cfg.get('dns_backend_port',53542) if stable else cfg['dns_port']
        udp, _ = await loop.create_datagram_endpoint(DNS, local_addr=('127.0.0.1', dns_port))
        tcp = await asyncio.start_server(dns_tcp, '127.0.0.1', dns_port)
    proxy = await asyncio.start_server(socks, '127.0.0.1', cfg['socks_port'])
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT): loop.add_signal_handler(sig, stop.set)
    (directory / 'services.pid').write_text(str(os.getpid()))
    record(event='ready')
    try: await stop.wait()
    finally:
        if udp: udp.close()
        if tcp: tcp.close()
        proxy.close(); log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    cfg = json.loads((args.directory / 'trial-input.json').read_text())
    asyncio.run(serve(cfg, args.directory))
