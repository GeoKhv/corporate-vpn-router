#!/usr/bin/env python3
"""One sequential public-capability check; no credentials, auth or routes."""
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

os.umask(0o077)
app,output=map(Path,sys.argv[1:])
res=app/'Contents/Resources'
sys.path.insert(0,str(res/'Engine'))
import trust
import tls_policy
import connection_trace as trace
from cpyvpn import auth,ssl_ctx,utils
logging.disable(logging.CRITICAL)
trace.install(output,role='resilience_public_capability_canary')
original_data=trust.DATA
saved=original_data/'ssl-site.json'
before=hashlib.sha256(saved.read_bytes()).hexdigest()
h=subprocess.run([str(res/'RouteHelper/RouteClient')],input='{"op":"status"}\n',
                 text=True,capture_output=True,timeout=8)
helper=json.loads(h.stdout)
if helper.get('ok') is not True or helper.get('active') is not False or helper.get('cleanupPending') is not False:
    raise SystemExit('HELPER_NOT_CLEAN')
result={'base':'alpha.5','variant':'resilience.1','capabilities_ok':False,'authenticated':False}
try:
    with tempfile.TemporaryDirectory(prefix='cvr-resilience-canary-') as tmp:
        trust.DATA=Path(tmp)
        (trust.DATA/'ssl-site.json').write_bytes(saved.read_bytes())
        def refuse_approval(_):raise trust.Refused('UNEXPECTED_FIRST_USE_APPROVAL')
        trace.set_phase('canary_anchor')
        address,context=trust.anchor(refuse_approval,require_idle=True,resilient=True)
        tls_policy.install(ssl_ctx,utils,address,context,resilient=True)
        options=SimpleNamespace(server=address,nocert=False,mode='a',realm='',user='',os='Darwin',
                                ct='TRAC',force_logout=False,cookies=None,support_saml=False)
        trace.set_phase('canary_capabilities_first')
        session=auth.SNXAuth(options,None)
        assert session.auth_obj is None
        trace.set_phase('canary_capabilities_adjacent')
        utils.get_gw_info(address+':443',False)
        assert session.auth_obj is None
        result['capabilities_ok']=True
except Exception as error:
    result.update(error_class=type(error).__name__,errno=getattr(error,'errno',None))
    trace.emit('canary_error',error_class=type(error).__name__,errno=getattr(error,'errno',None))
finally:
    tls_policy.close_control()
    trust.DATA=original_data
    result['receipt_unchanged']=hashlib.sha256(saved.read_bytes()).hexdigest()==before
(output/'canary-result.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
