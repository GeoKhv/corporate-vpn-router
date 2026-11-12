"""Injected post-MFA failures preserve the actual stage and always log out."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
from unittest.mock import MagicMock, patch
sys.path.insert(0,str(Path(sys.argv[1]).resolve()))
import session
import sites
import official_handoff
from cpyvpn import auth, utils

with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
    root=Path(tmp);(root/'work-sites.json').write_text('{}')
    (root/'ssl-site.json').write_text(json.dumps({'site':'fixture.invalid','ca_sha256':'fixture'}))
    closed=[];events=[]
    class FakeSession:
        def __init__(self,*args):
            self.gw_info=SimpleNamespace(realms=[{'id':'otp','factors':{'1':{'factor_type':'password'},'2':{'factor_type':'password'}}}])
            self.auth_obj=SimpleNamespace(sid='NEVER_LOG_SID',url='fixture.invalid',login=None,pwd=None)
        def init(self):pass
        def close(self):closed.append(True)
    def failing_run(coroutine):
        coroutine.close()
        session.status('dataplane_opening')
        try:raise ConnectionRefusedError(61,'NEVER_LOG_AUTH')
        except BaseException:
            session.STATE.setdefault('failure_stage',session.STATE.get('stage'));raise
        finally:session.status('dataplane_closed')
    original_status=session.status
    def status(stage,**values):
        session.STATE.update(stage=stage,**values);events.append(stage)
    with patch.object(session,'DATA',root),patch.object(session,'RUN',root/'run'),patch.object(session,'ROOT',root/'engine'),patch.object(session,'RESILIENT',True),patch.object(session,'guard_parent'),patch.object(session.fcntl,'flock'),patch.object(session,'anchor',return_value=('192.0.2.1',None)),patch.object(session,'install_tls_policy'),patch.object(session,'request',return_value='fixture-user'),patch.object(session,'status',status),patch.object(session.socket,'socket',MagicMock()),patch.object(sites,'validate'),patch.object(official_handoff,'prepare'),patch.object(auth,'SNXAuth',FakeSession):
        with patch.object(utils,'get_ranges',side_effect=TimeoutError('NEVER_LOG_AUTH')):
            try:session.main()
            except TimeoutError:pass
            else:raise AssertionError('ranges failure swallowed')
        assert session.STATE['failure_stage']=='ranges_request' and 'ranges_received' not in events and len(closed)==1
        session.STATE.clear();events.clear()
        with patch.object(utils,'get_ranges',return_value=[]),patch.object(session.asyncio,'run',failing_run):
            try:session.main()
            except ConnectionRefusedError:pass
            else:raise AssertionError('dataplane failure swallowed')
        assert session.STATE['failure_stage']=='dataplane_opening' and len(closed)==2
        assert events.index('ranges_request')<events.index('ranges_received')<events.index('dataplane_opening')<events.index('dataplane_closed')
print('PASS ranges/dataplane failures separated, original stage survives cleanup, logout preserved')
