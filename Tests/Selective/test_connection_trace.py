"""Real loopback TLS, async TLS and refusal with metadata-only instrumentation."""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(engine))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import beta_tls
import connection_trace as trace

with tempfile.TemporaryDirectory(dir='/private/tmp', prefix='cvr-trace-test-') as temp:
    root = Path(temp)
    trace.install(root, role='loopback_fixture')
    # Reuse all strict production-path rejection tests with instrumentation on.
    with patch.object(trace, 'route', return_value={'interface':'lo0'}):
        beta_tls.main()
        listener = trace._socket()
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        listener.close()
        try:
            socket.create_connection(('127.0.0.1', port), timeout=.2)
        except ConnectionRefusedError:
            pass
        else:
            raise AssertionError('expected TCP refusal')
        trace.set_phase('fixture_ranges')
        try:
            with trace.step('ranges'):
                raise TimeoutError('PASSWORD OTP SID COOKIE MUST NOT APPEAR')
        except TimeoutError:
            pass
    rows = [json.loads(line) for path in root.glob('connections-*.jsonl') for line in path.read_text().splitlines()]
    events = {r['event'] for r in rows}
    assert {'tcp_begin','tcp_ok','tcp_error','tls_begin','tls_ok','async_tls_begin','async_tls_ok','async_tls_error'} <= events, events
    assert any(r.get('phase') == 'fixture_ranges.ranges' and r['event'] == 'error' for r in rows)
    assert all(r.get('local') and r.get('peer') for r in rows if r['event'] == 'tcp_ok')
    assert all('time' in r and 'monotonic_ns' in r and 'pid' in r for r in rows)
    assert not any(secret in json.dumps(rows) for secret in ['PASSWORD','OTP','SID','COOKIE','MUST NOT APPEAR'])
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in root.glob('connections-*.jsonl'))
print('PASS traced production TLS paths, async endpoints, refusal, exact stage, secret exclusion and permissions')
