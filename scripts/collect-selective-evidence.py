#!/usr/bin/env python3
"""Read-only diagnostics. Never collect credentials, packet data or raw registry."""
import collections, datetime, hashlib, json, os, pathlib, plistlib, re, stat, subprocess, tempfile
P=pathlib.Path
DATA=P.home()/'Library/Application Support/Corporate VPN Router'
APP=P.home()/'Applications/Corporate VPN Router TUN Trial.app'
RES=APP/'Contents/Resources'
def run(args, input=None):
 try:
  p=subprocess.run(args,input=input,capture_output=True,text=True,timeout=8)
  return {'code':p.returncode,'text':p.stdout[:16000]}
 except Exception as e:return {'error':type(e).__name__}
def load(path):
 try:
  st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_size>8*1024*1024:return {'unavailable':'unsafe or oversized file'}
  return json.loads(path.read_text())
 except Exception as e:return {'unavailable':type(e).__name__}
def metadata(path):
 try:
  s=path.stat();return {'created':s.st_birthtime,'modified':s.st_mtime,'bytes':s.st_size}
 except OSError:return None
def summarize_log(path):
 result={'file':metadata(path),'events':{},'errors':[],'first_time':None,'last_time':None}
 try:
  if path.is_symlink() or path.stat().st_uid!=os.getuid():return result
  counts=collections.Counter()
  with path.open() as f:
   for i,line in enumerate(f):
    if i>200000:result['truncated']=True;break
    try:v=json.loads(line)
    except ValueError:continue
    event=v.get('event','unknown');counts[event]+=1
    t=v.get('time')
    if isinstance(t,(int,float)):
     if result['first_time'] is None:result['first_time']=t
     result['last_time']=t
    if 'error' in v:
     e=str(v['error']);safe=e if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9 .:-]{0,140}',e) else '<redacted>'
     result['errors']=(result['errors']+[{'time':t,'event':event,'error':safe}])[-30:]
  result['events']=dict(counts)
 except OSError:result['unavailable']=True
 return result
os.umask(0o077)
report={'schema':'cvr-alpha4-evidence-v1','time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'macOS':run(['/usr/bin/sw_vers']), 'architecture':run(['/usr/bin/uname','-m']),
 'version':run([str(APP/'Contents/MacOS/CorporateVPNRouter'),'--version'])}
status=load(DATA/'ssl-status.json')
report['current_status']={k:status[k] for k in ('state','message','connected','checks','updated') if k in status}
receipt=load(DATA/'ssl-site.json');report['gateway_receipt']={k:receipt[k] for k in ('site','ip','cn','ca_sha256','unavailable') if k in receipt}
report['gateway_receipt_file']=metadata(DATA/'ssl-site.json')
helper=run([str(RES/'RouteHelper/RouteClient')],'{"op":"status"}\n')
try:
 v=json.loads(helper.get('text',''));report['helper']={k:v[k] for k in ('ok','version','active','cleanupPending','error') if k in v}
except ValueError:report['helper']={'error':'STATUS_UNAVAILABLE'}
report['sessions']=[]
for stage in sorted(P('/private/tmp').glob('cvr-selective-input-*'),key=lambda p:p.stat().st_mtime,reverse=True)[:40]:
 if stage.is_symlink() or stage.stat().st_uid!=os.getuid():continue
 report['sessions'].append({'id':stage.name,'directory':metadata(stage),
  'ready':load(stage/'ready.json'),'cleanup':load(stage/'cleanup.json'),
  'services':summarize_log(stage/'services.jsonl'),'dns':summarize_log(stage/'dns-front.jsonl')})
report['certificate_endpoints']=load(DATA/'certificate-endpoints.json')
for family in ('inet','inet6'):
 r=run(['/usr/sbin/netstat','-rn','-f',family]);lines=r.get('text','').splitlines()
 report['routes_'+family]=[re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<ip>',l) for l in lines if re.search(r'^default\s|utun73|198\.18\.75|fdc7:7652:9a10',l)]
processes=run(['/bin/ps','-axo','comm='])
report['vpn_processes']=[P(l.strip()).name for l in processes.get('text','').splitlines() if any(k in l.lower() for k in ('adguard','corporatevpnrouter','routehelper','tracsrvwrapper'))]
report['limitations']=['alpha.4 did not persist the SSL event stream; historical gateway errors may not be recoverable', 'No authentication, disconnect, trust change, key/registry extraction or elevation was performed']
folder=P(tempfile.mkdtemp(prefix='CVR-alpha4-evidence-',dir=str(P.home()/'Desktop')))
path=folder/'report.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2));path.chmod(0o600)
print('Готово. VPN и доверие не изменялись. Локальный отчёт:',path)
print('Файл содержит адрес рабочего шлюза и его публичный pin; передавайте только приватно.')
