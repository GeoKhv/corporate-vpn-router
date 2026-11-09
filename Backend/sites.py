"""Private, versioned routing policy shared by the HTTP router and SOCKS gate."""
import re

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
def hostname(s):
    if not isinstance(s,str) or not (1 <= len(s) <= 253) or '.' not in s or s.split('.')[-1].isdigit() or s.endswith(('.onion','.localhost','.local')): return False
    return all(LABEL.fullmatch(x) for x in s.split('.'))

def validate(cfg):
    if set(cfg) != {'version','sites','beforeLogin','ports'} or cfg['version'] != 1: raise ValueError('profile format')
    sites, before, ports = cfg['sites'], cfg['beforeLogin'], cfg['ports']
    if not isinstance(sites,list) or not 1 <= len(sites) <= 256 or not all(isinstance(r,dict) and set(r)=={'domain','scope'} and hostname(r['domain']) and r['scope'] in ('exact','tree') for r in sites): raise ValueError('sites')
    if len({r['domain'] for r in sites}) != len(sites): raise ValueError('duplicate site')
    if not isinstance(before,list) or len(before)>64 or not all(hostname(s) for s in before): raise ValueError('beforeLogin')
    if not isinstance(ports,list) or not 1 <= len(ports) <= 32 or not all(type(p) is int and 1<=p<=65535 for p in ports): raise ValueError('ports')
    return cfg

def gate(cfg):
    validate(cfg)
    tokens = ['!' + x for x in cfg['beforeLogin']] + [('=' if r['scope']=='exact' else '')+r['domain'] for r in cfg['sites']]
    return '|'+ '|'.join(tokens)+'|', '|'+ '|'.join(map(str,cfg['ports']))+'|'
