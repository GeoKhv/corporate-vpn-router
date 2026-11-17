"""Print only sanitized Work resolver task summaries, never request URLs."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--logs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
host=json.loads((Path.home()/'Library/Application Support/Corporate VPN Router/certificate-endpoints.json').read_text())['hosts'][1]
rows=[]
for f in a.logs.glob('*-netlog.json'):
 n=json.loads(f.read_text());types={v:k for k,v in n['constants']['logEventTypes'].items()};requests=[]
 for i,e in enumerate(n['events']):
  if types[e['type']]!='HOST_RESOLVER_MANAGER_REQUEST' or e['phase']!=1 or host not in e.get('params',{}).get('host',''):continue
  tasks=[];end=None
  for x in n['events'][i+1:]:
   if x['source']!=e['source']:continue
   if types[x['type']]=='HOST_RESOLVER_MANAGER_TASK_SEQUENCE_CREATED':tasks+=x['params']['tasks']
   if types[x['type']]=='HOST_RESOLVER_MANAGER_REQUEST' and x['phase']==2:end=x.get('params',{}).get('net_error');break
  requests.append(dict(tasks=tasks,localOnly=all(t in (4,5,6,7,9) for t in tasks),endError=end))
 rows.append(dict(log=f.name,workResolverRequests=requests))
print(json.dumps(rows,indent=2));a.output.write_text(json.dumps(rows,indent=2))
