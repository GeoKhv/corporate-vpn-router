"""Exercise consent and cancellation at the official-client handoff boundary."""
import sys
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import official_handoff as h
from trust import Refused
from types import SimpleNamespace

def run(states, answers, local_available=True):
    calls=[]
    def request(kind,prompt, **fields):
        if kind == 'check_official_gui': return 'available' if local_available else 'unavailable'
        calls.append(kind)
        return answers[kind]
    with patch.object(h,'official_info',side_effect=[('fixture','127.0.0.1',s) for s in states]), patch.object(h.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as cli, patch.object(h.socket,'socket'):
        try:h.prepare(request);error=None
        except Refused as e:error=str(e)
        return calls,cli.call_count,error
assert run(['Idle','Idle'],{'close_official_gui':'closed'})==(['close_official_gui'],0,None)
assert run(['Connected'],{'switch_official':'cancel'})==(['switch_official'],0,'INPUT_CANCELLED')
assert run(['Connected','Connected','Idle','Idle'],{'switch_official':'accept','close_official_gui':'closed'})==(['switch_official','close_official_gui'],1,None)
assert run(['Idle'],{'close_official_gui':'failed'})==(['close_official_gui'],0,'OFFICIAL_GUI_HANDOFF_FAILED')
assert run(['Unknown'],{})==([],0,'OFFICIAL_STATE_UNKNOWN')
assert run(['Connected'],{},False)==([],0,'BROWSER_LOCAL_UNAVAILABLE')
print('PASS idle GUI handoff, explicit connected switch, cancel without disconnect, GUI refusal and unknown state.')
