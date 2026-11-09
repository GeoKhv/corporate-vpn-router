"""Verify unsupported or unknown browser capabilities never disconnect a VPN."""
import sys,tempfile,json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import session, official_handoff
from cpyvpn import auth
from trust import Refused

for case, realms, failure, expected in [
 ('absent',[],None,'BROWSER_NOT_ADVERTISED'),
 ('ambiguous',[{'factors':{'0':{'factor_type':'identity_provider'}}}]*2,None,'BROWSER_REALM_AMBIGUOUS'),
 ('network',[],TimeoutError(),'BROWSER_CAPABILITY_UNKNOWN'),
 ('available',[{'factors':{'0':{'factor_type':'identity_provider'}},'id':'fixture'}],None,'HANDOFF_REACHED')]:
 with tempfile.TemporaryDirectory() as temp:
  root=Path(temp); (root/'config.json').write_text(json.dumps({'domains':['corp.invalid'],'ports':[443]}))
  with patch.object(session,'DATA',root),patch.object(session,'RUN',root/'SSL'),patch.object(session,'guard_parent'),patch.object(session.socket,'socket'),patch.object(session,'anchor',return_value=('127.0.0.1',None)) as anchor,patch.object(session,'install_tls_policy'),patch.object(auth,'SNXAuth',side_effect=failure,return_value=SimpleNamespace(gw_info=SimpleNamespace(realms=realms))),patch.object(official_handoff,'prepare',side_effect=Refused('HANDOFF_REACHED')) as prepare,patch.object(sys,'argv',['session.py','--browser']):
   try:session.main()
   except Refused as error:assert str(error)==expected,(case,str(error))
   else:raise AssertionError(case)
   assert prepare.call_count == (1 if case=='available' else 0)
   assert anchor.call_args.kwargs=={'require_idle':False}
print('PASS unsupported, ambiguous and network-unknown capabilities refuse before any official handoff.')
