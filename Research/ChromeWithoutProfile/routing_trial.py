"""Policy-free browser + private relay; production beta.6 remains connected.
Private result paths/netlogs may contain internal hostnames. Do not publish them.
"""
import argparse,json,os,socket,subprocess,tempfile,time,uuid
from pathlib import Path
from browser import Browser
from user_proxy import create_profile,apply,restore
p=argparse.ArgumentParser();p.add_argument('--chrome',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args();args.chrome=args.chrome.resolve()
root=Path(__file__).resolve().parents[2];data=Path.home()/'Library/Application Support/Corporate VPN Router';app=Path.home()/'Applications/Corporate VPN Router.app';py=app/'Contents/Resources/Runtime/bin/python3.13'
rows={};b=None;relay=None
with tempfile.TemporaryDirectory(prefix='cvr-route-',dir='/private/tmp') as temp:
 d=Path(temp);rules=d/'rules';rules.mkdir();profile=d/'Chrome';prefs=profile/'Default/Preferences';create_profile(profile)
 cfg=json.loads((data/'work-sites.json').read_text());host=json.loads((data/'certificate-endpoints.json').read_text())['hosts'][1]
 original=json.loads(json.dumps(cfg))
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 def save():
  f=rules/'new.json';f.write_text(json.dumps(cfg));f.replace(rules/'work-sites.json')
 save()
 def start():
  proc=subprocess.Popen([str(py),'-I','-B',str(Path(__file__).with_name('relay.py')), '--data',str(rules),'--port',str(port)],stdout=subprocess.DEVNULL)
  for _ in range(100):
   try:
    with socket.create_connection(('127.0.0.1',port),.2):return proc
   except OSError:time.sleep(.05)
  raise RuntimeError('Private router did not start')
 endpoint='http://127.0.0.1:'+str(port)
 receipt=apply(profile,dict(mode='fixed_servers',server=endpoint,bypass_list=''))
 def browser(label):return Browser(args.chrome,profile,['--log-net-log='+str(args.output.parent/(label+'-netlog.json'))])
 def page(label,url,ok=True,expected=None):
  err,body=b.page(url+('?' if '?' not in url else '&')+'cvr-isolated='+uuid.uuid4().hex)
  passed=not err and body.startswith('complete|') and 'ERR_' not in body and (not expected or expected in body.lower())
  assert passed==ok,(label,err,body[:100]);rows[label]=dict(ok=passed,error=err)
 work='https://'+host+'/robots.txt';life='https://example.com/'
 try:
  relay=start();b=browser('initial')
  page('work-live-beta6-peer',work,expected='user-agent:');page('life-live-sota',life,expected='example')
  cfg['sites'].append(dict(domain='example.com',scope='exact'));save();time.sleep(.3)
  page('added-domain-no-restart',life,ok=False)
  cfg=original;save();time.sleep(.3);page('removed-domain-no-restart',life,expected='example')
  (rules/'work-down').touch();page('work-isolated-fault',work,ok=False);page('life-during-work-fault',life,expected='example')
  (rules/'work-down').unlink();page('work-after-fault',work,expected='user-agent:')
  b.close();b=browser('ordinary-restart');page('work-ordinary-restart-no-flags',work,expected='user-agent:');page('life-ordinary-restart-no-flags',life,expected='example')
  relay.kill();relay.wait();page('router-death-work',work,ok=False);page('router-death-life',life,ok=False)
  relay=start();page('life-router-restored',life,expected='example');page('work-router-restored',work,expected='user-agent:')
  b.close();b=None
  rows['pref-persisted']=json.loads(prefs.read_text()).get('proxy')==dict(mode='fixed_servers',server=endpoint,bypass_list='')
  assert rows['pref-persisted'];rows['rollback']=restore(profile,receipt);assert 'proxy' not in json.loads(prefs.read_text())
  print(json.dumps(rows,indent=2));args.output.write_text(json.dumps(rows,indent=2))
 finally:
  if b:b.close()
  if relay:relay.terminate();relay.wait()
