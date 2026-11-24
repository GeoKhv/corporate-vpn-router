"""Two-phase startup, DNS conflict handling and independent cleanup verification."""
import asyncio
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(engine / 'Selective'), str(engine)]
import controller
import helper_client
import sparse_dns
import trust

original_sleep = asyncio.sleep


async def fast_sleep(_):
    await original_sleep(0)


def test_dns_addresses():
    valid = "resolver #1\n  nameserver[0] : 10.0.0.53\n  nameserver[1] : fe80::1%utun4\n"
    controller.verify_dns_addresses(valid)
    scoped = valid + "DNS configuration (for scoped queries)\nresolver #2\n nameserver[0] : "
    for output, expected in [
        ('', 'SYSTEM_DNS_UNKNOWN'), (scoped + 'invalid', 'SYSTEM_DNS_UNKNOWN'),
        *((scoped + address, 'SYSTEM_DNS_ADDRESS_CONFLICT') for address in
          ['198.18.75.2', '198.18.73.1', 'fdc7:7652:9a10:75::1', 'fdc7:7652:9a10::1'])
    ]:
        try:
            controller.verify_dns_addresses(output)
        except RuntimeError as exc:
            assert str(exc) == expected
        else:
            raise AssertionError(output)


async def test(mode):
    cfg = dict(version=1, sites=[dict(domain='work.example.invalid', scope='tree')],
               ports=[443], beforeLogin=['gateway.invalid'])
    events, calls = [], []
    service_down = mode == 'recover_then_cancel'
    dns_checks = 0
    clock_offset = 0
    read_fd, write_fd = os.pipe()
    with ExitStack() as stack:
        base = Path(stack.enter_context(tempfile.TemporaryDirectory(dir='/private/tmp')))
        stage = base / 'stage'
        def make_stage(**kwargs):
            stage.mkdir()
            return str(stage)
        stack.callback(os.close, write_fd)
        reader = stack.enter_context(os.fdopen(read_fd))
        stack.enter_context(patch.object(sys, 'stdin', reader))
        loop = asyncio.get_running_loop()
        monotonic = loop.time
        stack.enter_context(patch.object(loop, 'time', lambda: monotonic() + clock_offset))

        def status():
            if 'stop' in calls and mode == 'missing_status':
                return {}
            pending = mode == 'pending_on_open' or ('stop' in calls and mode == 'cleanup_pending')
            return dict(active=False, cleanupPending=pending)

        class FakeHelper:
            def __init__(self, _): pass
            async def open(self):
                return dict(version='0.3.0-alpha.3', build='0.3.10', allowCheckPointStart=True, approvedDomains=['work.example.invalid'],
                            approvedPorts=[443], approvedRDPHost='desk.work.example.invalid' if mode=='partial_begin' else None, **status())
            async def call(self, op, **kwargs):
                nonlocal clock_offset, service_down
                calls.append(op)
                if op == 'ensureCheckPointService':
                    assert service_down and not stage.exists()
                    service_down = False
                if op == 'begin' and mode == 'partial_begin':
                    assert kwargs['rdpSlot'] == 7 and kwargs['ports'] == [443]
                    raise RuntimeError('FIXTURE_PARTIAL_BEGIN')
                if op == 'publish' and mode == 'publish_failure':
                    raise RuntimeError('FIXTURE_PUBLISH_FAILED')
                if op == 'heartbeat':
                    if mode == 'dns_live':
                        clock_offset += 11
                        return dict(ok=True)
                    raise RuntimeError('FIXTURE_TRANSPORT_LOST')
                if op == 'stop' and mode in ('partial_begin', 'cleanup_pending'):
                    raise RuntimeError('NO_SESSION')
                if op == 'status':
                    return status()
                return dict(ok=True)
            async def close(self): pass

        def emit(state, message, **extra):
            events.append(dict(state=state, message=message, **extra))
            if state == 'awaitingTunnel' and mode == 'partial_begin':
                assert extra['rdpHost'] == 'desk.work.example.invalid'
            if state == 'awaitingTunnel':
                assert 'begin' not in calls and not stage.exists()
                token = b'cancel\n' if mode in ('cancel_login', 'recover_then_cancel') else b'activate\n'
                os.write(write_fd, token)

        async def dns():
            nonlocal dns_checks
            dns_checks += 1
            conflict = {'dns_preflight': 1, 'dns_after_mfa': 2, 'dns_before_publish': 3, 'dns_live': 4}.get(mode)
            if dns_checks == conflict:
                raise RuntimeError('SYSTEM_DNS_ADDRESS_CONFLICT')

        async def service(cfg, stage, *, stop_event, held):
            if mode == 'partial_begin':
                assert cfg['rdp_host'] == 'desk.work.example.invalid'
            (stage / 'services.pid').touch()
            await stop_event.wait()

        async def front(cfg, stage, stop, *, route_installer, ready):
            if mode == 'slow_dns_start':
                for _ in range(200):
                    await original_sleep(0)
                assert 'publish' not in calls
            (stage / 'dns-ready').touch()
            ready.set()
            await asyncio.Event().wait()

        class Registry:
            names = []
            def allocate(self, name):
                assert name == 'desk.work.example.invalid'
                return 7
        def official_info():
            if service_down:
                raise trust.Refused('OFFICIAL_SERVICE_NOT_STARTED')
            return ('gateway.invalid', '192.0.2.1', 'Idle')
        for obj, name, value in [
            (trust, 'official_info', official_info),
            (controller, 'policy', lambda: (cfg, None)), (helper_client, 'RouteHelper', FakeHelper),
            (controller, 'initialize_map', Registry), (controller, 'STATE', base),
            (controller.tempfile, 'mkdtemp', make_stage), (controller, 'serve', service),
            (sparse_dns, 'serve', front), (controller, 'emit', emit),
            (controller, 'check_system_dns', dns), (controller.asyncio, 'sleep', fast_sleep)
        ]:
            stack.enter_context(patch.object(obj, name, value))
        controller.CLEANUP_CONFIRMED = True
        try:
            await asyncio.wait_for(controller.start(1), 20 if mode == 'dns_live' else 4)
        except RuntimeError as exc:
            cause = str(exc)
            errors = [e for e in events if e['state'] == 'error']
            assert errors and errors[0]['message'] == cause, events
        else:
            assert mode in ('cancel_login', 'recover_then_cancel'), mode
        if mode == 'recover_then_cancel':
            assert calls.count('ensureCheckPointService') == 1
            states = [event['state'] for event in events]
            assert states.index('restoringCheckPoint') < states.index('awaitingTunnel')

        if mode in ('pending_on_open', 'cancel_login', 'recover_then_cancel', 'dns_preflight', 'dns_after_mfa'):
            assert 'begin' not in calls and 'stop' not in calls and not stage.exists(), (mode, calls)
            assert controller.CLEANUP_CONFIRMED == (mode != 'pending_on_open')
        else:
            assert calls.count('begin') == calls.count('stop') == 1, calls
            assert 'status' in calls[calls.index('stop') + 1:], calls
            assert not (stage / 'trial-input.json').exists()
            if mode == 'dns_before_publish':
                assert 'publish' not in calls
            if mode == 'dns_live':
                assert 'publish' in calls and cause == 'SYSTEM_DNS_ADDRESS_CONFLICT'
            if mode == 'slow_dns_start':
                assert 'publish' in calls and cause == 'FIXTURE_TRANSPORT_LOST'
            confirmed = mode not in ('cleanup_pending', 'missing_status')
            assert controller.CLEANUP_CONFIRMED == confirmed
            assert (stage / 'cleanup.json').exists() == confirmed
            assert events[-1]['state'] == ('stopped' if confirmed else 'error')


test_dns_addresses()
for mode in ('pending_on_open', 'cancel_login', 'recover_then_cancel', 'dns_preflight', 'dns_after_mfa', 'dns_before_publish', 'dns_live', 'slow_dns_start',
             'partial_begin', 'publish_failure', 'transport_failure', 'cleanup_pending', 'missing_status'):
    asyncio.run(test(mode))
print('PASS DNS overlap IPv4/IPv6 and scoped resolvers, no routes on cancellation or preflight failure, '
      'partial begin, publish and transport failures, independent cleanup status and pending/unknown block')
