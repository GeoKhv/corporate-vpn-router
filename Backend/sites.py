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

def rdp_host_for_profile(cfg, host):
    """RDP is an extra port for one approved name inside the active work profile."""
    if not hostname(host) or host in cfg['beforeLogin']:
        return None
    if any(row['domain'] == host or (row['scope'] == 'tree' and host.endswith('.' + row['domain']))
           for row in cfg['sites']):
        return host
    return None


def gate(cfg, rdp_host=None):
    validate(cfg)
    tokens = ['!' + x for x in cfg['beforeLogin']] + [('=' if r['scope']=='exact' else '')+r['domain'] for r in cfg['sites']]
    ports = [str(port) for port in cfg['ports'] if not (rdp_host and port == 3389)]
    if rdp_host_for_profile(cfg, rdp_host):
        ports.append(rdp_host + ':3389')
    return '|'+ '|'.join(tokens)+'|', '|'+ '|'.join(ports)+'|'
