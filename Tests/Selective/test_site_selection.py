"""Exercise controller selection before any helper, DNS listener or route setup."""
import asyncio,json,io,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
engine=Path(sys.argv[1]).resolve()
sys.path[:0]=[str(engine/'Selective'),str(engine)]
import controller,trust
class Done(Exception):pass
first='primary.example.invalid';second='alternate.example.invalid'
def native(state='Idle',selected=False):
 return (f'Conn {first}:\n gw: 192.0.2.1\n status: Idle\n active site: false\n'
         f'Conn {second}:\n gw: 192.0.2.2\n status: {state}\n active site: '+str(selected).lower()+'\n')
with tempfile.TemporaryDirectory() as tmp:
 data=Path(tmp)
 with (patch.object(controller,'DATA',data),patch.object(trust,'DATA',data),
       patch.object(trust,'approved_receipt',return_value={'site':first}),
       patch.object(trust,'approved_site_pin',return_value={'site':second}),
       patch.object(controller,'policy',side_effect=Done),
       patch.object(controller,'emit') as emit):
  for text,answer,expect_prompt in [
    (native(),second,True),
    (native(),'',False),
    (native(selected=True),'',False),
    (native('Connected'),'',False)]:
   if text!=native():(data/'preferred-site.json').unlink(missing_ok=True)
   emit.reset_mock()
   stream=SimpleNamespace(buffer=io.BytesIO((json.dumps({'site':answer})+'\n').encode()))
   with patch.object(trust,'official_output',return_value=text),patch.object(sys,'stdin',stream):
    try:asyncio.run(controller.start(1))
    except Done:pass
    else:raise AssertionError('must stop before helper')
   assert emit.called==expect_prompt
   if expect_prompt:
    assert emit.call_args.kwargs['sites']==sorted([first,second])
    assert json.loads((data/'preferred-site.json').read_bytes())=={'site':second}
  (data/'preferred-site.json').unlink(missing_ok=True)
  with patch.object(trust,'official_output',return_value=native()),patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO())):
   try:asyncio.run(controller.start(1))
   except RuntimeError as exc:assert str(exc)=='INPUT_CANCELLED'
   else:raise AssertionError('EOF must cancel')
  assert not (data/'preferred-site.json').exists()
print('PASS controller automatic active/native-selected/saved choice, one ambiguous prompt, cancellation before network changes')
