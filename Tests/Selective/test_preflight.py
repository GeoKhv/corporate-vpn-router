"""Official-client failures must stop before authorization or network setup."""
import asyncio
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(engine / 'Selective'))
sys.path.insert(0, str(engine))
import controller
import trust

idle = b'Conn gateway.example.invalid:\n  gw: 192.0.2.1\n  status: Idle\n'
cases = [
    (1, b'service is not started\n', b'', 'OFFICIAL_SERVICE_NOT_STARTED'),
    (0, b'', b'service is not started\n', 'OFFICIAL_SERVICE_NOT_STARTED'),
    (1, b'', b'command failed', 'OFFICIAL_INFO_FAILED'),
    (1, b'VPN Service is down', b'', 'OFFICIAL_SERVICE_NOT_STARTED'),
    (1, b'Connectivity with the Check Point Endpoint Security service is lost', b'', 'OFFICIAL_SERVICE_NOT_STARTED'),
    (0, b'', b'', 'OFFICIAL_SITE_MISSING'),
    (0, b'Conn Work VPN:\n  gw: 192.0.2.1\n  status: Idle\n', b'', 'OFFICIAL_SITE_FORMAT_UNSUPPORTED'),
    (0, idle + idle.replace(b'gateway.', b'other.'), b'', 'OFFICIAL_SITE_AMBIGUOUS'),
    (0, idle + b'Conn Work VPN:\n  gw: 192.0.2.2\n', b'', 'OFFICIAL_SITE_AMBIGUOUS'),
    (0, idle.replace(b'  status: Idle\n', b''), b'', 'OFFICIAL_STATE_UNKNOWN'),
]
for rc, output, errors, expected in cases:
    replies = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], rc, output, errors)]
    with patch.object(trust, 'owned'), patch.object(trust.subprocess, 'run', side_effect=replies), \
         patch.object(controller, 'initialize_map') as state, \
         patch.object(controller.tempfile, 'mkdtemp') as stage, \
         patch.object(controller.asyncio, 'create_subprocess_exec') as authorized:
        try:
            asyncio.run(controller.start(1))
        except trust.Refused as error:
            assert str(error) == expected, (expected, str(error))
        else:
            raise AssertionError('refused official state accepted')
        state.assert_not_called(); stage.assert_not_called(); authorized.assert_not_called()

with patch.object(trust, 'owned'), patch.object(trust.subprocess, 'run', side_effect=[
        subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, idle, b'')]):
    assert trust.official_info() == ('gateway.example.invalid', '192.0.2.1', 'Idle')
with patch.object(trust, 'owned'), patch.object(trust.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as command:
    try: trust.official_info()
    except trust.Refused as error: assert str(error) == 'OFFICIAL_SIGNATURE_INVALID'
    else: raise AssertionError('official signature bypassed')
    assert command.call_count == 1
with patch.object(trust,'official_info',return_value=('gateway.example.invalid','192.0.2.1','Idle')), \
     patch.object(controller,'policy',return_value=({'version':1,'sites':[{'domain':'example.invalid','scope':'tree'}],'beforeLogin':[],'ports':[443]},None)), \
     patch.object(controller,'initialize_map') as state:
    try:asyncio.run(controller.start(1))
    except ValueError as error:assert 'Шлюз VPN' in str(error)
    else:raise AssertionError('first-use gateway captured by Work DNS')
    state.assert_not_called()
print('PASS stopped service/stdout/stderr, failed command, missing/unsupported/ambiguous sites and unknown state refuse before map/admin/network; signed single-site parsing preserved')

with patch.object(trust, 'owned'), patch.object(trust.subprocess, 'run', side_effect=[subprocess.CompletedProcess([],0), subprocess.TimeoutExpired('trac',10)]):
    try:trust.official_info()
    except trust.Refused as error:assert str(error)=='OFFICIAL_INFO_TIMEOUT'
    else:raise AssertionError('timeout not classified')
