"""Control: stable Chrome remains under beta.6 policy, not profile-free evidence."""
import argparse,json,tempfile
from pathlib import Path
from browser import Browser
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();home=Path.home();host=json.loads((home/'Library/Application Support/Corporate VPN Router/certificate-endpoints.json').read_text())['hosts'][1]
rows={}
with tempfile.TemporaryDirectory(prefix='cvr-stable-control-',dir='/private/tmp') as d:
 profile=Path(d);pref=profile/'Default/Preferences';pref.parent.mkdir();pref.write_text(json.dumps({'proxy':{'mode':'fixed_servers','server':'http://127.0.0.1:1'}}))
 b=Browser('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',profile,['--proxy-server=http://127.0.0.1:1'])
 try:
  for key,url,expected in [('work','https://'+host+'/robots.txt','user-agent:'),('life','https://example.com/','example')]:
   err,body=b.page(url);assert not err and expected in body.lower(),(key,err,body[:80]);rows[key]='rendered under unchanged beta.6 policy'
 finally:b.close()
a.output.write_text(json.dumps(rows,indent=2));print(json.dumps(rows,indent=2))
