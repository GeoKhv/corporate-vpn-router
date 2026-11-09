# SPDX-License-Identifier: GPL-3.0-or-later
"""Single interactive SLIM session, using anonymous pipes to the menu app."""
import asyncio
from collections import deque
import errno, fcntl, ipaddress, json, logging, os, signal, socket, struct, subprocess, sys, time, threading
from pathlib import Path
from types import SimpleNamespace
ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from trust import DATA, anchor, Refused
from tls_policy import install as install_tls_policy, require_strict
RUN=DATA/'SSL'
STATE={}
def status(stage, **values):
    STATE.update(stage=stage, **values)
    print(json.dumps({'stage':stage,**values}),flush=True)
def request(kind,prompt, **fields):
    print(json.dumps({'request':kind,'prompt':str(prompt)[:300], **fields}),flush=True)
    line=sys.stdin.buffer.readline(8193)
    if not line or len(line)>8192: raise Refused('INPUT_CANCELLED')
    answer=json.loads(line)
    if not isinstance(answer,str): raise Refused('INPUT_CANCELLED')
    return answer
class PrivateUI:
    def print_header(self, header): pass
    # Every dynamic challenge is secret, including SMS prompts via ask_str.
    def ask_str(self,prompt): return request('challenge',prompt)
    def ask_pwd(self,prompt): return request('secret',prompt)
    def wait_input(self,values): return values
    def ask_sel(self,*args): raise Refused('AMBIGUOUS_REALM')
def approve(receipt):
    if request('trust', receipt['site']+' ('+receipt['ip']+')\nSHA-256 CA: '+receipt['ca_sha256'])!='accept':
        raise Refused('TRUST_CANCELLED')
def guard_parent():
    parent=os.getppid()
    if parent==1: os._exit(2)
    def watch():
        while os.getppid()==parent: time.sleep(0.25)
        os._exit(2)
    threading.Thread(target=watch,daemon=True).start()
class PacketDevice:
    def __init__(self):
        self.sock, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        # Darwin defaults to only 2 KiB per message / 4 KiB receive queue.
        # A short TLS-certificate burst can produce ENOBUFS after two packets.
        # These options apply to this socketpair only, never system sysctls.
        for endpoint in (self.sock, self.peer):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        self.sock.setblocking(False)
        self.pending = deque()
        self.pending_bytes = 0
        self.retry = None
        self.transport = None
        self.addresses = set()
        self.counts = {'out_packets': 0, 'in_packets': 0, 'out_dns': 0, 'in_dns': 0,
                       'empty_liveness_messages_ignored': 0, 'backpressure_events': 0,
                       'max_in_packet_bytes': 0, 'max_out_packet_bytes': 0}

    def count(self, data, outgoing):
        direction = 'out' if outgoing else 'in'
        self.counts[direction + '_packets'] += 1
        key = 'max_' + direction + '_packet_bytes'
        self.counts[key] = max(self.counts[key], len(data))
        if len(data) >= 20 and data[0] >> 4 == 4:
            # Private diagnostic addresses only; never packet payloads or tokens.
            self.addresses.add(socket.inet_ntoa(data[16:20] if outgoing else data[12:16]))
        if len(data) >= 28 and data[0] >> 4 == 4 and data[9] == 17:
            offset = (data[0] & 15) * 4
            if len(data) >= offset + 4:
                ports = struct.unpack('!HH', data[offset:offset + 4])
                if ports[1 if outgoing else 0] == 53:
                    self.counts[direction + '_dns'] += 1

    def read(self):
        try:
            data = self.sock.recv(65535)
        except BlockingIOError:
            return None
        # ocproxy cb_housekeeping writes a zero-length datagram every second
        # to test the parent fd. It is not an IP packet. Upstream SocketPairDev
        # also maps it to None; forwarding it creates an invalid SLIM record.
        if not data:
            self.counts['empty_liveness_messages_ignored'] += 1
            return None
        self.count(data, True)
        return data

    def write(self, data):
        self.count(data, False)
        # The reviewed ocproxy build has a 2048-byte packet read buffer.
        # Refuse oversize packets explicitly instead of silently truncating.
        if len(data) > 2048:
            raise RuntimeError('INCOMING_PACKET_EXCEEDS_OCPROXY_BUFFER')
        self.pending.append(data)
        self.pending_bytes += len(data)
        if self.pending_bytes > 4 * 1024 * 1024:
            raise RuntimeError('PACKET_QUEUE_LIMIT')
        if self.retry is None:
            self.flush()
        return len(data)

    def flush(self):
        self.retry = None
        while self.pending:
            packet = self.pending[0]
            try:
                written = self.sock.send(packet)
            except OSError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.ENOBUFS):
                    raise
                self.counts['backpressure_events'] += 1
                if self.transport:
                    self.transport.pause_reading()
                self.retry = asyncio.get_running_loop().call_later(0.002, self.flush)
                return
            if written != len(packet):
                raise RuntimeError('PARTIAL_DATAGRAM_WRITE')
            self.pending.popleft()
            self.pending_bytes -= written
        if self.transport:
            self.transport.resume_reading()

    def close(self):
        if self.retry:
            self.retry.cancel()
        self.pending.clear()
        self.sock.close()
        self.peer.close()

    def fileno(self):
        return self.sock.fileno()


class PacketVNA:
    def __init__(self):
        self.dev = PacketDevice()
        self.addr = None
        self.dns = []
        self.is_up = False
        self.proc = None
        self.lifetime = None

    def set_routes(self, _routes):
        pass

    def set_dns(self, servers, _domains):
        self.dns = [str(ipaddress.IPv4Address(value)) for value in servers]
        if not self.dns:
            raise RuntimeError('CORPORATE_DNS_REQUIRED')

    def set_ips(self, address, _gateway, _netmask=None):
        self.addr = str(ipaddress.IPv4Address(address))

    def om_ip(self):
        return self.addr

    def tun_up(self):
        return self.is_up

    def tundev(self):
        return self.dev

    def up(self):
        if self.is_up or not self.dns or not self.addr:
            raise RuntimeError('INVALID_PACKET_CONFIGURATION')
        lifetime_read, self.lifetime = os.pipe()
        packet_fd = self.dev.peer.fileno()
        env = {'VPNFD': str(packet_fd), 'INTERNAL_IP4_ADDRESS': self.addr,
               'INTERNAL_IP4_DNS': ' '.join(self.dns), 'INTERNAL_IP4_MTU': '1400',
               'CVR_DOMAINS': POLICY[0], 'CVR_PORTS': POLICY[1]}
        self.proc = subprocess.Popen([sys.executable, '-I', '-B', str(ROOT / 'proxy_supervisor.py'), str(lifetime_read)],
            pass_fds=(packet_fd, lifetime_read), env=env, start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(lifetime_read)
        self.dev.peer.close()
        self.is_up = True
        status('socks_starting', socks_port=1090, corporate_dns_count=len(self.dns))

    def close(self):
        self.is_up = False
        if self.lifetime is not None:
            os.close(self.lifetime)
            self.lifetime = None
        if self.proc:
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=3)
        self.dev.close()


async def dataplane(session, address, context, client, ranges):
    stop = asyncio.Event()
    adapter = PacketVNA()
    transport = None
    closing = False
    loop = asyncio.get_running_loop()
    def signal_stop():
        STATE['close_reason'] = 'local_signal'
        stop.set()
    loop.add_signal_handler(signal.SIGINT, signal_stop)
    loop.add_signal_handler(signal.SIGTERM, signal_stop)
    def safe_async_error(_loop, details):
        error = details.get('exception')
        status('dataplane_error', error_type=type(error).__name__ if error else 'ASYNC_ERROR')
        stop.set()
    loop.set_exception_handler(safe_async_error)
    class Handler(client.SNXHandler):
        def on_connection_lost(self, error):
            if not closing:
                status('transport_lost', close_reason='peer_eof' if error is None else 'transport_error',
                       transport_error_type=type(error).__name__ if error else None,
                       transport_errno=getattr(error, 'errno', None))
            super().on_connection_lost(error)

        def disconnect(self, reply):
            code = str(reply.find('code'))
            status('server_disconnect', close_reason='server_disconnect', server_code=code if code.isdigit() else 'unknown')
            self.reconnect = False
            self.evt.set()

    try:
        transport, protocol = await asyncio.wait_for(loop.create_connection(
            lambda: Handler(adapter, session.cookie, 2, ranges, stop),
            host=address, port=443, ssl=require_strict(context), server_hostname=address), timeout=15)
        status('ssl_dataplane_connected')
        adapter.dev.transport = transport
        protocol.send_client_hello()
        start = time.monotonic()
        ready = False
        next_stats=0
        while not stop.is_set():
            if ready and (protocol.is_ka_timeout() or protocol.is_auth_timeout()):
                raise Refused('SESSION_TIMED_OUT')
            if ready and loop.time() >= next_stats:
                status('traffic', counters=adapter.dev.counts)
                next_stats=loop.time()+2
            if not ready and time.monotonic() - start > 20:
                raise Refused('SSL_HELLO_TIMEOUT')
            if adapter.proc and adapter.proc.poll() is not None:
                raise Refused('PROXY_EXITED')
            if adapter.is_up and not ready:
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', 1090)
                    writer.write(b'\x05\x01\x00')
                    await writer.drain()
                    greeting = await asyncio.wait_for(reader.readexactly(2), 2)
                    writer.close()
                    await writer.wait_closed()
                    if greeting != b'\x05\x00':
                        raise RuntimeError('BAD_SOCKS_GREETING')
                    ids=subprocess.run(['/usr/sbin/lsof','-nP','-a','-iTCP:1090','-sTCP:LISTEN','-Fp'],capture_output=True,timeout=8).stdout.splitlines()
                    ids=[row for row in ids if row.startswith(b'p')]
                    if len(ids)!=1 or not ids[0][1:].isdigit(): raise Refused('SOCKS_OWNER_NOT_VERIFIED')
                    parent=subprocess.run(['/bin/ps','-o','ppid=','-p',ids[0][1:].decode()],capture_output=True,timeout=4)
                    if parent.stdout.strip()!=str(adapter.proc.pid).encode(): raise Refused('SOCKS_OWNER_NOT_VERIFIED')
                    ready = True
                    status('connected', socks_port=1090)
                except ConnectionRefusedError:
                    pass
            try:
                await asyncio.wait_for(stop.wait(), 0.5)
            except asyncio.TimeoutError:
                pass
        if STATE.get('close_reason') != 'local_signal':
            raise Refused('TRANSPORT_LOST' if ready else 'SSL_SESSION_REFUSED')
    finally:
        closing = True
        if transport:
            transport.abort()
        adapter.close()
        STATE['packet_counters'] = adapter.dev.counts
        status('dataplane_closed', socks_port=None)



def main():
    os.umask(0o077)
    guard_parent()
    RUN.mkdir(parents=True,mode=0o700,exist_ok=True)
    lock=(RUN/'instance.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    policy=DATA/'ssl-policy.json'
    config=json.loads((policy if policy.exists() else DATA/'config.json').read_text())
    import re
    global POLICY
    domains=config['domains']; ports=config['ports']
    if not (1<=len(domains)<=256 and all(isinstance(d,str) and len(d)<=253 and '.' in d and
       all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in d.split('.'))
       and not d.split('.')[-1].isdigit() for d in domains)): raise Refused('INVALID_DOMAINS')
    if not (1<=len(ports)<=32 and all(type(v) is int and 1<=v<=65535 for v in ports)): raise Refused('INVALID_PORTS')
    POLICY=('|'+ '|'.join(domains)+'|','|'+ '|'.join(map(str,ports))+'|')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as check:
        check.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try: check.bind(('127.0.0.1',1090))
        except OSError: raise Refused('SOCKS_PORT_OCCUPIED')
    logging.disable(logging.CRITICAL)
    status('verifying_gateway')
    address,context=anchor(approve)
    from cpyvpn import auth,client,utils,ssl_ctx
    install_tls_policy(ssl_ctx,utils,address,context)
    browser = sys.argv[1:] == ['--browser']
    options=SimpleNamespace(server=address,nocert=False,mode='a',realm='',user='',
        os='Darwin',ct='TRAC',force_logout=False,cookies=None,support_saml=browser)
    session=auth.SNXAuth(options,PrivateUI())
    factors = ['identity_provider'] if browser else ['password','password']
    realms = [r for r in session.gw_info.realms if
              [v.get('factor_type') for _,v in sorted(r.get('factors',{}).items())] == factors]
    if len(realms) != 1:
        raise Refused('IDP_REALM_NOT_FOUND' if browser else 'EXPECTED_TWO_FACTOR_REALM_NOT_FOUND')
    realm = realms[0]
    options.realm = realm['id']
    receipt = json.loads((DATA/'ssl-site.json').read_text())
    status('gateway_verified')
    try:
        if browser:
            from browser_auth import authenticate
            def launch(url):
                handler = request('browser', '', url=url)
                if not handler.startswith('/') or not handler.endswith('.app'):
                    raise Refused('BROWSER_OPEN_FAILED')
                return handler
            username = authenticate(session, realm, receipt['site'], address, context, launch, status)
            # Only the typed, successfully authenticated CCC username is eligible.
            # Keep identity out of diagnostics, stderr and the public status file.
            print(json.dumps({'identity':username, 'site':receipt['site'],
                              'pin':receipt['ca_sha256'], 'realm':realm['id']}), flush=True)
        else:
            # Supply the explicit UserPass username. Prompt strings and subsequent
            # challenges never determine which value can be remembered.
            options.user = request('username', 'Логин', site=receipt['site'],
                                   pin=receipt['ca_sha256'], realm=realm['id'])
            if not options.user.strip():
                raise Refused('USERNAME_REQUIRED')
            session.init()
        status('authenticated')
        session.auth_obj.login=session.auth_obj.pwd=None
        ranges=utils.get_ranges(session.auth_obj.url,session.auth_obj.sid)
        asyncio.run(dataplane(session,address,context,client,ranges))
    finally:
        if session.auth_obj and session.auth_obj.sid:
            try: session.close()
            except Exception: pass
if __name__=='__main__':
    try:
        main()
        status('disconnected')
    except BaseException as error:
        status('failed',code=str(error) if isinstance(error,Refused) else type(error).__name__,errno=getattr(error,'errno',None))
        sys.exit(1)
