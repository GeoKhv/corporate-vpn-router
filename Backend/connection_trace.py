"""Opt-in private connection metadata; never log payloads or exception text.

Installed only in a diagnostic process. No probes, retries, TLS changes or
timeouts are introduced. route/lsof are passive OS observations, not evidence
of the VPN provider's remote egress. Each process writes its own exclusive log.
"""
import contextlib
import contextvars
import datetime
import errno
import functools
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import uuid

_phase = contextvars.ContextVar('connection_phase', default='startup')
_file = None
_lock = threading.Lock()
_sequence = itertools.count(1)
_installed = False
_run = subprocess.run
_socket = socket.socket
_popen = subprocess.Popen


def endpoint(value):
    try:
        return [str(ipaddress.ip_address(value[0])), int(value[1])]
    except (ValueError, TypeError, IndexError):
        return None


def sockmeta(sock):
    result = {}
    if sock is None:
        return {'local': None, 'peer': None}
    for key, method in [('local', sock.getsockname), ('peer', sock.getpeername)]:
        try:
            result[key] = endpoint(method())
        except OSError:
            result[key] = None
    return result


def route(destination):
    try:
        ip = str(ipaddress.ip_address(destination))
        p = _run(['/sbin/route', '-n', 'get', ip], capture_output=True, text=True, timeout=2)
        result = {'rc': p.returncode}
        for line in p.stdout.splitlines():
            key, sep, value = line.strip().partition(':')
            if sep and key in ('destination', 'gateway', 'interface', 'flags', 'ifscope'):
                result[key] = value.strip()[:160]
        return result
    except Exception as error:
        return {'error_class': type(error).__name__}


def emit(event, **fields):
    if _file is None:
        return
    row = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds'),
               monotonic_ns=time.monotonic_ns(), pid=os.getpid(), ppid=os.getppid(),
               phase=_phase.get(), event=event, **fields)
    try:
        with _lock:
            _file.write(json.dumps(row, separators=(',', ':')) + '\n')
            _file.flush()
    except OSError:
        pass  # Diagnostics cannot change connection cleanup or trust.


def set_phase(value):
    _phase.set(value)
    emit('phase')


@contextlib.contextmanager
def step(name):
    token = _phase.set(_phase.get() + '.' + name)
    started = time.monotonic_ns()
    emit('begin')
    try:
        yield
    except BaseException as error:
        emit('error', duration_ms=(time.monotonic_ns()-started)/1e6,
             error_class=type(error).__name__, errno=getattr(error, 'errno', None))
        raise
    else:
        emit('ok', duration_ms=(time.monotonic_ns()-started)/1e6)
    finally:
        _phase.reset(token)


def wrap(obj, name, label):
    original = getattr(obj, name)
    @functools.wraps(original)
    def call(*args, **kwargs):
        with step(label):
            return original(*args, **kwargs)
    setattr(obj, name, call)
    return call


class ObservedSocket(_socket):
    def _begin(self, address):
        target = endpoint(address)
        if self.family not in (socket.AF_INET, socket.AF_INET6) or target is None or self.type != socket.SOCK_STREAM:
            return False
        self._trace = (next(_sequence), time.monotonic_ns(), target, _phase.get())
        emit('tcp_begin', connection=self._trace[0], target=target, family=int(self.family),
             timeout=self.gettimeout(), route=route(target[0]))
        return True

    def _end(self, event, error=None):
        trace = getattr(self, '_trace', None)
        if trace is None:
            return
        number, started, target, phase = trace
        token = _phase.set(phase)
        try:
            emit(event, connection=number, target=target, duration_ms=(time.monotonic_ns()-started)/1e6,
                 error_class=type(error).__name__ if error else None,
                 errno=getattr(error, 'errno', None), route=route(target[0]), **sockmeta(self))
        finally:
            _phase.reset(token)
        self._trace = None

    def connect(self, address):
        tracked = self._begin(address)
        try:
            result = super().connect(address)
        except OSError as error:
            if tracked and error.errno not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                self._end('tcp_error', error)
            raise
        if tracked:
            self._end('tcp_ok')
        return result

    def connect_ex(self, address):
        tracked = self._begin(address)
        result = super().connect_ex(address)
        if tracked and result not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            self._end('tcp_ok' if result == 0 else 'tcp_error', OSError(result, '') if result else None)
        return result

    def getsockopt(self, level, option, *args):
        value = super().getsockopt(level, option, *args)
        if level == socket.SOL_SOCKET and option == socket.SO_ERROR and getattr(self, '_trace', None):
            self._end('tcp_ok' if value == 0 else 'tcp_error', OSError(value, '') if value else None)
        return value

    def close(self):
        if getattr(self, '_trace', None):
            self._end('tcp_closed_before_verdict')
        return super().close()


class ObservedPopen(_popen):
    def __init__(self, args, *rest, **kwargs):
        self._chain_trace = None
        if isinstance(args, (list, tuple)) and args[:2] == ['/usr/bin/openssl', 's_client']:
            target = endpoint(args[args.index('-connect')+1].rsplit(':', 1))
            if target:
                self._chain_trace = (next(_sequence), time.monotonic_ns(), target, _phase.get())
        super().__init__(args, *rest, **kwargs)
        if self._chain_trace:
            number, _, target, _ = self._chain_trace
            emit('openssl_begin', connection=number, child_pid=self.pid, target=target, route=route(target[0]))
            self._observed_stop = threading.Event()
            self._observer = threading.Thread(target=self._observe, daemon=True)
            self._observer.start()

    def _observe(self):
        number, _, target, phase = self._chain_trace
        _phase.set(phase)
        seen = set()
        while not self._observed_stop.is_set():
            try:
                p = _run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(self.pid), '-iTCP:443', '-FnT'],
                         capture_output=True, text=True, timeout=1)
                for line in p.stdout.splitlines():
                    if line.startswith('n') and '->' in line and line not in seen:
                        local, peer = line[1:].split('->', 1)
                        local, peer = endpoint(local.rsplit(':', 1)), endpoint(peer.rsplit(':', 1))
                        if local and peer:
                            emit('openssl_socket_observed', connection=number, child_pid=self.pid, local=local, peer=peer)
                            seen.add(line)
            except Exception:
                pass
            self._observed_stop.wait(.1)

    def communicate(self, *args, **kwargs):
        if not self._chain_trace:
            return super().communicate(*args, **kwargs)
        number, started, target, _ = self._chain_trace
        try:
            result = super().communicate(*args, **kwargs)
        except BaseException as error:
            emit('openssl_error', connection=number, child_pid=self.pid, target=target,
                 error_class=type(error).__name__, duration_ms=(time.monotonic_ns()-started)/1e6)
            raise
        else:
            emit('openssl_exit', connection=number, child_pid=self.pid, target=target, rc=self.returncode,
                 duration_ms=(time.monotonic_ns()-started)/1e6)
            return result
        finally:
            self._observed_stop.set()
            self._observer.join(timeout=1.1)


def install(directory, role='session'):
    global _file, _installed
    if _installed:
        return
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError('UNSAFE_TRACE_DIRECTORY')
    path = directory / ('connections-' + uuid.uuid4().hex + '.jsonl')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    _file = os.fdopen(fd, 'w', buffering=1)
    _installed = True
    emit('process', role=role, executable=sys.executable, python=sys.version.split()[0],
         executable_sha256=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest())
    socket.socket = ObservedSocket
    subprocess.Popen = ObservedPopen
    original_wrap = ssl.SSLContext.wrap_socket
    def tls_wrap(self, sock, *args, **kwargs):
        emit('tls_begin', **sockmeta(sock))
        with step('tls_handshake'):
            result = original_wrap(self, sock, *args, **kwargs)
        emit('tls_ok', version=result.version(), **sockmeta(result))
        return result
    ssl.SSLContext.wrap_socket = tls_wrap
    # Asyncio uses MemoryBIO rather than SSLContext.wrap_socket.
    from asyncio.sslproto import SSLProtocol
    start, complete = SSLProtocol._start_handshake, SSLProtocol._on_handshake_complete
    def tls_start(self):
        self._trace_started = time.monotonic_ns()
        emit('async_tls_begin', **sockmeta(self._transport.get_extra_info('socket')))
        return start(self)
    def tls_complete(self, error):
        emit('async_tls_error' if error else 'async_tls_ok',
             duration_ms=(time.monotonic_ns()-getattr(self, '_trace_started', time.monotonic_ns()))/1e6,
             error_class=type(error).__name__ if error else None, errno=getattr(error, 'errno', None),
             **sockmeta(self._transport.get_extra_info('socket')))
        return complete(self, error)
    SSLProtocol._start_handshake, SSLProtocol._on_handshake_complete = tls_start, tls_complete
    import trust
    for name in ('official_info', 'site', 'accepted', 'pinned_context', 'preapproved', 'anchor'):
        wrap(trust, name, name)
    from cpyvpn import auth, utils
    wrap(utils, 'get_ranges', 'ranges')
    wrap(auth.SNXAuth, 'close', 'session_logout')
    return path
