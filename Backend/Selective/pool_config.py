"""Build sing-box config with domain rules and local-only fake DNS.
The synthetic pool is NOT installed as a subnet route. The root DNS frontend
adds a host route only when replying with that exact synthetic address.
"""
import json
from pathlib import Path
import sys

def build(cfg):
    policy = cfg['policy']
    if cfg.get('mode')=='stable-map':
        # IP ownership and domain gating live in the authenticated local
        # bridge. The packet stack never resolves or guesses a domain.
        return {'log':{'level':'debug','timestamp':True},
            'inbounds':[{'type':'tun','tag':'work-tun','interface_name':'utun73',
                'address':['198.18.73.1/32','fdc7:7652:9a10::1/128'],'mtu':1500,
                'auto_route':False,'dns_mode':'disabled','stack':'gvisor'}],
            'outbounds':[{'type':'socks','tag':'verified-work','server':'127.0.0.1',
                'server_port':cfg['socks_port'],'version':'5','username':'trial','password':cfg['password']}],
            'route':{'rules':[{'inbound':['work-tun'],'network':'tcp','port':policy['ports'],
                'action':'route','outbound':'verified-work'},{'action':'reject','no_drop':True}]}}
    exact = [r['domain'] for r in policy['sites'] if r['scope']=='exact']
    trees = [r['domain'] for r in policy['sites'] if r['scope']=='tree']
    allowed = {'domain': exact+['work.cvr-probe.invalid'], 'domain_suffix': trees}
    allowed = {k:v for k,v in allowed.items() if v}
    deny = {'domain':policy['beforeLogin']}
    dns_rules=[]
    if deny['domain']:dns_rules.append(dict(**deny,action='predefined',rcode='NXDOMAIN'))
    dns_rules += [dict(**allowed, query_type=['A','AAAA'], action='route', server='local-fake',rewrite_ttl=1),
                  dict(**allowed, action='predefined',rcode='NOERROR'),
                  dict(action='predefined',rcode='NXDOMAIN')]
    route_rules=[{'inbound':['local-dns'],'action':'hijack-dns'}]
    if deny['domain']:route_rules.append(dict(**deny,action='reject',no_drop=True))
    route_rules += [dict(**allowed,inbound=['work-tun'],network='tcp',port=policy['ports'],action='route',outbound='verified-work'),
                    dict(action='reject',no_drop=True)]
    return {
        'log':{'level':'debug','timestamp':True},
        'dns':{'servers':[{'type':'hosts','tag':'empty-local','path':['/dev/null']},
                          {'type':'fakeip','tag':'local-fake','inet4_range':'198.18.74.0/24','inet6_range':'fdc7:7652:9a10:74::/120'}],
               'final':'empty-local','rules':dns_rules,'disable_cache':True},
        'inbounds':[
            {'type':'tun','tag':'work-tun','interface_name':'utun73','address':['198.18.73.1/32','fdc7:7652:9a10::1/128'],
             'mtu':1500,'auto_route':False,'dns_mode':'disabled','stack':'gvisor'},
            {'type':'direct','tag':'local-dns','listen':'127.0.0.1','listen_port':53542}
        ],
        'outbounds':[{'type':'socks','tag':'verified-work','server':'127.0.0.1','server_port':11090,'version':'5',
                      'username':'trial','password':cfg['password']}],
        'route':{'rules':route_rules}
    }

if __name__=='__main__':
    directory=Path(sys.argv[1]);cfg=json.loads((directory/'trial-input.json').read_text())
    (directory/'sing-box.json').write_text(json.dumps(build(cfg),indent=2));(directory/'sing-box.json').chmod(0o600)
