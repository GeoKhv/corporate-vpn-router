"""Private trial: at most two serial TCP dials, never replay application data."""
import asyncio
import errno
import http.client
import ipaddress
import socket
import subprocess
import time

MAX_TCP_SECONDS = 10.0
MAX_DIALS = 2
RETRY_ERRNOS = {errno.ECONNREFUSED, errno.ETIMEDOUT}


def event(name, **fields):
    try:
        import connection_trace
        connection_trace.emit(name, **fields)
    except ImportError:
        pass


def destination(address):
    host, port = address
    host = str(ipaddress.IPv4Address(host))
    if port != 443:
        raise RuntimeError('UNEXPECTED_TCP_DESTINATION')
    return host, port


def retryable(error):
    return isinstance(error, TimeoutError) or getattr(error, 'errno', None) in RETRY_ERRNOS


def discover(command, timeout=12):
    """Retry only certificate inventory with no returned certificate, no auth.

    Any returned certificate is passed directly to the unchanged pin/chain
    validation; a partial or mismatched chain is never retried as a bypass.
    """
    deadline=time.monotonic()+timeout
    for attempt in range(1,MAX_DIALS+1):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
        allowance=min(remaining,timeout/2) if attempt==1 else remaining
        event('bounded_discovery_attempt',attempt=attempt,budget_ms=timeout*1000,allowance_ms=allowance*1000)
        try:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,timeout=allowance)
        except subprocess.TimeoutExpired as error:
            if attempt==MAX_DIALS or b'-----BEGIN CERTIFICATE-----' in (error.stdout or b''):
                raise
        else:
            if b'-----BEGIN CERTIFICATE-----' in result.stdout or attempt==MAX_DIALS:
                return result


def connect(address, timeout=10, source_address=None, **kwargs):
    """Return an unauthenticated TCP socket. TLS and HTTP are outside retries.

    Two attempts share <=min(original timeout,10s). The first gets half the
    budget; the second gets only what remains. No wait, backoff or parallelism.
    Restore the caller's socket timeout for its unchanged TLS/read policy.
    """
    address = destination(address)
    if source_address is not None or kwargs or not isinstance(timeout,(int,float)) or timeout <= 0:
        raise RuntimeError('UNEXPECTED_TCP_OPTIONS')
    budget = min(float(timeout), MAX_TCP_SECONDS)
    deadline = time.monotonic() + budget
    for attempt in range(1, MAX_DIALS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('TCP_CONNECT_BUDGET_EXHAUSTED')
        allowance = min(remaining, budget/2) if attempt == 1 else remaining
        event('bounded_tcp_attempt', attempt=attempt, budget_ms=budget*1000, allowance_ms=allowance*1000)
        try:
            raw = socket.create_connection(address, timeout=allowance)
        except OSError as error:
            event('bounded_tcp_error', attempt=attempt, error_class=type(error).__name__, errno=error.errno)
            if not retryable(error) or attempt == MAX_DIALS:
                raise
        else:
            raw.settimeout(timeout)
            return raw


async def connect_async(address, budget=10):
    address = destination(address)
    budget = min(float(budget), MAX_TCP_SECONDS)
    deadline = time.monotonic() + budget
    for attempt in range(1, MAX_DIALS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('TCP_CONNECT_BUDGET_EXHAUSTED')
        allowance = min(remaining,budget/2) if attempt == 1 else remaining
        raw = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        raw.setblocking(False)
        event('bounded_tcp_attempt',attempt=attempt,budget_ms=budget*1000,allowance_ms=allowance*1000)
        try:
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(raw,address),allowance)
        except BaseException as error:
            raw.close()
            event('bounded_tcp_error',attempt=attempt,error_class=type(error).__name__,errno=getattr(error,'errno',None))
            if not isinstance(error,OSError) or not retryable(error) or attempt == MAX_DIALS:
                raise
        else:
            return raw


class ControlChannel:
    """One origin, one connection; strict TLS every fresh connection.

    Reuse only a fully consumed HTTP/1.1 response explicitly allowing reuse,
    and only for immediately adjacent requests. Never retry request/send/read,
    even if the server closed a persistent connection before a request.
    """
    def __init__(self,address,strict_context):
        self.address=destination((address,443))[0]
        self.strict_context=strict_context
        self.connection=None
        self.last_used=0.0

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection=None

    def request(self,path,data,rawval=False):
        try:
            context=self.strict_context()
            if (self.connection is not None and
                    (self.connection.sock is None or time.monotonic()-self.last_used>1.0)):
                self.close()
            if self.connection is None:
                self.connection=http.client.HTTPSConnection(self.address,443,context=context,timeout=45)
                self.connection._create_connection=connect
                # Only explicit connect() can dial. HTTP send must never reopen.
                self.connection.auto_open=0
                self.connection.connect()
                event('control_channel_opened')
            else:
                event('control_channel_reused')
            self.connection.request('POST',path,body=(data or '').encode('ascii'),
                headers={'Content-Type':'application/x-www-form-urlencoded','Connection':'keep-alive'})
            response=self.connection.getresponse()
            if response.status != 200:
                raise RuntimeError('CONTROL_HTTP_%d'%response.status)
            body=response.read(1024*1024)
            if len(body)>=1024*1024:
                raise RuntimeError('OVERSIZED_CONTROL_RESPONSE')
            reusable=not response.will_close and self.connection.sock is not None
            event('control_response',http_status=response.status,reusable=reusable)
            if not reusable:self.close()
            self.last_used=time.monotonic()
            return body if rawval else body.decode('utf_8_sig')
        except BaseException:
            self.close()
            raise
