"""Unprivileged IPsec transport behind Router's pinned CCC and existing SOCKS policy.

No operating-system VPN, routes, DNS settings, persistent keys, or raw logs.
"""
from collections import deque
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import struct
import subprocess
import time

from trust import Refused
from tls_policy import close_control, require_strict, tls_name
from gateway_disconnect import disconnect_details, diagnostic_words

ROOT = Path(__file__).resolve().parent
BINARY = ROOT / 'cvr-ipsec'
MAX_LINE = 1048576


def gateway_snapshot(utils, cfg, address):
    request = {'CCCclientRequest': {
        'RequestHeader': {'id': 0, 'type': 'ClientHello'},
        'RequestData': {'client_info': {'client_type': 'TRAC', 'client_version': 1}}}}
    return utils.do_ccc_request(address + '/clients', data=cfg.CPRR(request).serialize())


def _read_exact(stream, count):
    data = b''
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError('Control channel closed')
        data += chunk
    return data


def select_transport(address, context, cfg, utils):
    """Only an explicit, pinned SSL 205 selects IPsec; never guess after TLS failure.

    Empty cookie: no authentication or VPN session is created by this probe.
    Existing builds without the separately packaged bridge keep their behavior.
    """
    if not BINARY.is_file():
        return 'ssl'
    hello = utils.as_bytes(cfg.CPRR({'client_hello': {
        'client_version': 2, 'protocol_version': 2,
        'OM': {'ipaddr': '0.0.0.0', 'keep_address': 'false'},
        'optional': {'client_type': 4}, 'cookie': ''}}).serialize())
    with socket.create_connection((address, 443), timeout=8) as raw:
        with require_strict(context).wrap_socket(raw, server_hostname=tls_name(context, address)) as tls:
            tls.sendall(struct.pack('!II', len(hello), 1) + hello)
            length, kind = struct.unpack('!II', _read_exact(tls, 8))
            if kind != 1 or not 0 < length <= 8192:
                raise Refused('TRANSPORT_PREFLIGHT_INVALID')
            reply = cfg.CPRR(utils.as_text(_read_exact(tls, length)))
    if reply.root() != 'disconnect':
        raise Refused('TRANSPORT_PREFLIGHT_INVALID')
    details = disconnect_details(reply)
    if details['server_code'] == 205:
        return 'ipsec'
    # 201 is the expected refusal for an empty SSL session. Other explicit
    # responses retain the existing SSL path rather than retrying credentials.
    return 'ssl'


def control_rpc(op, fields, utils, cfg, address):
    sid = fields.get('session_id')
    if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_./+=>:-]{1,4096}', sid):
        raise Refused('IPSEC_CONTROL_INVALID')
    if op != 'signout':
        raise Refused('IPSEC_CONTROL_INVALID')
    req = {'CCCclientRequest': {'RequestHeader': {
        'id': 3, 'type': 'Signout', 'session_id': sid, 'protocol_version': 100}, 'RequestData': {}}}
    body = cfg.CPRR(req).serialize()
    return utils.do_ccc_request(address + '/clients/', data=body).serialize()


def socks_ready(adapter):
    try:
        with socket.create_connection(('127.0.0.1', 1090), timeout=0.3) as sock:
            sock.sendall(b'\x05\x01\x00')
            if _read_exact(sock, 2) != b'\x05\x00':
                raise Refused('SOCKS_OWNER_NOT_VERIFIED')
    except (ConnectionRefusedError, TimeoutError):
        return False
    rows = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-iTCP:1090', '-sTCP:LISTEN', '-Fp'],
                          capture_output=True, timeout=8).stdout.splitlines()
    pids = [row[1:] for row in rows if row.startswith(b'p')]
    if len(pids) != 1 or not pids[0].isdigit():
        raise Refused('SOCKS_OWNER_NOT_VERIFIED')
    parent = subprocess.run(['/bin/ps', '-o', 'ppid=', '-p', pids[0].decode()],
                            capture_output=True, timeout=4)
    if parent.stdout.strip() != str(adapter.proc.pid).encode():
        raise Refused('SOCKS_OWNER_NOT_VERIFIED')
    return True


def run_ipsec(address, snapshot, username, realm, utils, cfg, adapter, request, status, state):
    """Bounded pipe protocol and packet relay; all cleanup runs on failure/cancel."""
    proc = None
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    for endpoint in (parent, child):
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    parent.setblocking(False)
    selector = selectors.DefaultSelector()
    pending = {parent: deque(), adapter.dev.sock: deque()}
    pending_bytes = 0
    buffer = b''
    verified = authenticated = configured = ready = False
    deadline = time.monotonic() + 60
    next_stats = 0

    def cancelled(_sig, _frame):
        raise Refused('INPUT_CANCELLED')

    old_handlers = {sig: signal.signal(sig, cancelled) for sig in (signal.SIGTERM, signal.SIGINT)}

    def reply(value, ok=True):
        proc.stdin.write((json.dumps({'ok': ok, 'value': value}) + '\n').encode())
        proc.stdin.flush()

    def queue(endpoint, packet):
        nonlocal pending_bytes
        pending[endpoint].append(packet)
        pending_bytes += len(packet)
        if pending_bytes > 4 * 1024 * 1024:
            raise Refused('PACKET_QUEUE_LIMIT')
        selector.modify(endpoint, selectors.EVENT_READ | selectors.EVENT_WRITE)

    try:
        close_control()
        proc = subprocess.Popen([str(BINARY)], pass_fds=(child.fileno(),),
            env={'CVR_PACKET_FD': str(child.fileno())}, start_new_session=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        config = dict(address=address, gateway_response=snapshot.serialize(), username=username, realm=realm)
        proc.stdin.write((json.dumps(config) + '\n').encode()); proc.stdin.flush()
        child.close()
        os.set_blocking(proc.stdout.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            now = time.monotonic()
            if not ready and now > deadline:
                raise Refused('IPSEC_START_TIMEOUT')
            if adapter.proc and adapter.proc.poll() is not None:
                raise Refused('PROXY_EXITED')
            if configured and not ready and socks_ready(adapter):
                ready = True
                status('connected', socks_port=1090)
            if ready and now >= next_stats:
                status('traffic', counters=adapter.dev.counts)
                next_stats = now + 2
            events = selector.select(0.1)
            for key, mask in events:
                endpoint = key.fileobj
                if endpoint is proc.stdout:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    if not chunk:
                        raise Refused('IPSEC_TRANSPORT_LOST')
                    buffer += chunk
                    if len(buffer) > MAX_LINE:
                        raise Refused('IPSEC_CONTROL_INVALID')
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        msg = json.loads(line)
                        if not isinstance(msg, dict):
                            raise Refused('IPSEC_CONTROL_INVALID')
                        if 'rpc' in msg:
                            op, fields = msg['rpc'], msg.get('fields', {})
                            if not isinstance(fields, dict):
                                raise Refused('IPSEC_CONTROL_INVALID')
                            if op == 'challenge':
                                if not verified or authenticated:
                                    raise Refused('IPSEC_CONTROL_INVALID')
                                prompt = fields.get('prompt')
                                if not isinstance(prompt, str):
                                    raise Refused('IPSEC_CONTROL_INVALID')
                                value = request('secret', prompt)
                                reply(value)
                                del value
                                deadline = time.monotonic() + 60
                            elif op == 'signout' and authenticated:
                                # Cleanup can fail after a gateway closes its session.
                                # Let the bridge report the original transport failure.
                                try:
                                    value = control_rpc(op, fields, utils, cfg, address)
                                except Exception:
                                    reply(None, ok=False)
                                else:
                                    reply(value)
                            else:
                                raise Refused('IPSEC_CONTROL_INVALID')
                        else:
                            stage = msg.get('stage')
                            if stage == 'ipsec_negotiating':
                                status(stage)
                            elif stage == 'ipsec_gateway_verified' and not verified:
                                verified = True
                                status(stage)
                            elif stage == 'authenticated' and verified and not authenticated:
                                authenticated = True
                                deadline = time.monotonic() + 45
                                status(stage)
                            elif stage == 'ipsec_connected' and authenticated and not configured:
                                address4 = ipaddress.IPv4Address(msg.get('address'))
                                if address4.is_unspecified or address4.is_multicast or address4.is_loopback:
                                    raise Refused('IPSEC_CONTROL_INVALID')
                                dns = msg.get('dns')
                                if not isinstance(dns, list) or not 1 <= len(dns) <= 8:
                                    raise Refused('IPSEC_CONTROL_INVALID')
                                adapter.set_ips(str(address4), None)
                                adapter.set_dns(dns, [])
                                adapter.up()
                                configured = True
                                selector.register(parent, selectors.EVENT_READ)
                                selector.register(adapter.dev.sock, selectors.EVENT_READ)
                                deadline = time.monotonic() + 15
                                status(stage)
                            elif stage == 'failed':
                                status('ipsec_error', server_words=diagnostic_words(msg.get('detail')))
                                raise Refused('IPSEC_FAILED')
                            elif stage == 'disconnected':
                                raise Refused('IPSEC_TRANSPORT_LOST')
                            else:
                                raise Refused('IPSEC_CONTROL_INVALID')
                else:
                    if mask & selectors.EVENT_READ:
                        packet = endpoint.recv(65536)
                        if not configured:
                            raise Refused('IPSEC_CONTROL_INVALID')
                        outgoing = endpoint is adapter.dev.sock
                        if not packet and outgoing:
                            adapter.dev.counts['empty_liveness_messages_ignored'] += 1
                        else:
                            if not 20 <= len(packet) <= (1400 if outgoing else 2048) or packet[0] >> 4 != 4:
                                raise Refused('IPSEC_PACKET_INVALID')
                            adapter.dev.count(packet, outgoing)
                            queue(parent if outgoing else adapter.dev.sock, packet)
                    if mask & selectors.EVENT_WRITE:
                        packets = pending[endpoint]
                        while packets:
                            try:
                                n = endpoint.send(packets[0])
                            except OSError as error:
                                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS):
                                    raise
                                adapter.dev.counts['backpressure_events'] += 1
                                break
                            if n != len(packets[0]):
                                raise Refused('IPSEC_PACKET_INVALID')
                            pending_bytes -= n
                            packets.popleft()
                        if not packets:
                            selector.modify(endpoint, selectors.EVENT_READ)
    except BaseException:
        state.setdefault('failure_stage', state.get('stage'))
        raise
    finally:
        # Close stdin first to release any pending RPC; stop only this owned process.
        if proc:
            proc.stdin.close()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=3)
            proc.stdout.close()
        selector.close(); parent.close(); child.close()
        adapter.close()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        state['packet_counters'] = adapter.dev.counts
        status('dataplane_closed', socks_port=None)
