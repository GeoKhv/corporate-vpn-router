"""Partial begin and route failures preserve cause and explicitly verify cleanup."""
import asyncio, json, sys, tempfile, os
from pathlib import Path
from unittest.mock import patch
engine=Path(sys.argv[1]).resolve();sys.path[:0]=[str(engine/'Selective'),str(engine)]
import controller,helper_client,trust,sparse_dns
original_sleep=asyncio.sleep
async def fast_sleep(_):await original_sleep(0)
async def test(mode):
 with tempfile.TemporaryDirectory(prefix='cvr-controller-failure-',dir='/private/tmp') as d:
  base=Path(d);events=[];calls=[]
  cfg=dict(version=1,sites=[dict(domain='work.example.invalid',scope='tree')],ports=[443],beforeLogin=['gateway.invalid'])
  class FakeHelper:
   def __init__(self,_):pass
   async def open(self):return dict(version='0.3.0-alpha.3',approvedDomains=['work.example.invalid'],approvedPorts=[443],active=mode=='cleanup_pending',cleanupPending=mode=='cleanup_pending')
   async def call(self,op,**kwargs):
    calls.append(op)
    if op=='begin' and mode=='partial_begin':raise RuntimeError('FIXTURE_PARTIAL_BEGIN')
    if op=='publish' and mode=='publish_failure':raise RuntimeError('FIXTURE_PUBLISH_FAILED')
    if op=='heartbeat':raise RuntimeError('FIXTURE_TRANSPORT_LOST')
    if op=='stop' and mode in ('partial_begin','cleanup_pending'):raise RuntimeError('NO_SESSION')
    if op=='status':return dict(active=mode=='cleanup_pending',cleanupPending=mode=='cleanup_pending')
    return dict(ok=True)
   async def close(self):pass
  async def service(cfg,stage):
   (stage/'services.pid').write_text('1');await asyncio.Event().wait()
  async def front(cfg,stage,*args,**kwargs):
   (stage/'dns-ready').write_text('');await asyncio.Event().wait()
  class Registry:names=[]
  stage=base/'stage';stage.mkdir();controller.CLEANUP_CONFIRMED=True
  with patch.object(trust,'official_info',return_value=('gateway.invalid','192.0.2.1','Idle')),patch.object(controller,'policy',return_value=(cfg,None)),patch.object(helper_client,'RouteHelper',FakeHelper),patch.object(controller,'initialize_map',return_value=Registry()),patch.object(controller,'STATE',base),patch.object(controller.tempfile,'mkdtemp',return_value=str(stage)),patch.object(controller,'serve',service),patch.object(sparse_dns,'serve',front),patch.object(controller,'emit',side_effect=lambda state,message,**extra:events.append(dict(state=state,message=message,**extra))),patch.object(controller.asyncio,'sleep',fast_sleep):
   try:await controller.start(1)
   except RuntimeError:pass
   else:raise AssertionError('fixture did not fail')
  failures=[e for e in events if e['state']=='error']
  assert failures and failures[0]['message'].startswith('FIXTURE_'),events
  assert calls.count('begin')==1 and calls.count('stop')==1,calls
  assert not (stage/'trial-input.json').exists()
  if mode=='cleanup_pending':
   assert not controller.CLEANUP_CONFIRMED and events[-1]['code']=='CLEANUP_UNCONFIRMED'
  else:
   assert controller.CLEANUP_CONFIRMED and events[-1]['state']=='stopped'
   assert next(i for i,e in enumerate(events) if e['state']=='error')<len(events)-1
read_fd,write_fd=os.pipe()
old_stdin=sys.stdin
try:
 with os.fdopen(read_fd) as pipe:
  sys.stdin=pipe
  for mode in ['partial_begin','publish_failure','transport_failure','cleanup_pending']:asyncio.run(test(mode))
finally:
 sys.stdin=old_stdin;os.close(write_fd)
print('PASS partial begin, publish and heartbeat failures; original cause precedes cleanup; unconfirmed cleanup blocked; no automatic begin retry')
