"""Private, versioned routing policy shared by the HTTP router and SOCKS gate."""
import re

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
def hostname(s):
    if not isinstance(s,str) or not (1 <= len(s) <= 253) or '.' not in s or s.split('.')[-1].isdigit() or s.endswith(('.onion','.localhost','.local')): return False
    return all(LABEL.fullmatch(x) for x in s.split('.'))

def validate(cfg):
    if set(cfg) != {'version','sites','beforeLogin','ports'} or type(cfg['version']) is not int or cfg['version'] not in (1,2): raise ValueError('profile format')
    sites, before, ports = cfg['sites'], cfg['beforeLogin'], cfg['ports']
    if not isinstance(sites,list) or not 1 <= len(sites) <= 256 or not all(isinstance(r,dict) and {'domain','scope'} <= set(r) <= ({'domain','scope'} if cfg['version']==1 else {'domain','scope','tcp','alias'}) and hostname(r['domain']) and r['scope'] in ('exact','tree') for r in sites): raise ValueError('sites')
    if len({r['domain'] for r in sites}) != len(sites): raise ValueError('duplicate site')
    if not isinstance(before,list) or len(before)>64 or not all(hostname(s) for s in before): raise ValueError('beforeLogin')
    if not isinstance(ports,list) or not 1 <= len(ports) <= 32 or not all(type(p) is int and 1<=p<=65535 for p in ports): raise ValueError('ports')
    aliases = set()
    for row in sites:
        ports_for_row = row.get('tcp', ports)
        if ports_for_row != '*' and not (isinstance(ports_for_row, list)
                and 1 <= len(ports_for_row) <= 32 and
                all(type(p) is int and 1 <= p <= 65535 for p in ports_for_row)):
            raise ValueError('Укажите TCP-порты от 1 до 65535 или *.')
        if 'alias' in row:
            alias = row['alias']
            if (not isinstance(alias, str) or not LABEL.fullmatch(alias) or
                    alias.isdigit() or alias in aliases or alias in ('local','localhost','onion','com','net','org') or
                    alias != row['domain'].split('.')[0] or row['domain'] in before):
                raise ValueError('Короткое имя должно однозначно обозначать этот узел.')
            aliases.add(alias)
    if cfg['version'] == 2 and sum(len(t) + 1 for t in scoped_tokens(cfg)) > 49152:
        raise ValueError('Набор TCP-правил слишком велик для пакетного транспорта.')
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
    if cfg['version'] == 2:
        ports = ['@scoped'] + scoped_tokens(cfg)
    if rdp_host_for_profile(cfg, rdp_host):
        ports.append(('=' if cfg['version'] == 2 else '') + rdp_host + ':3389')
    return '|'+ '|'.join(tokens)+'|', '|'+ '|'.join(ports)+'|'

def matched_rule(cfg, host):
    if host in cfg['beforeLogin']:
        return None
    return max((row for row in cfg['sites'] if host == row['domain'] or
        (row['scope'] == 'tree' and host.endswith('.' + row['domain']))),
        key=lambda row: len(row['domain']), default=None)


def allowed_tcp(cfg, host, port, desktop=None):
    rule = matched_rule(cfg, host)
    if not rule or not 1 <= port <= 65535:
        return False
    permitted = rule.get('tcp', cfg['ports'])
    return permitted == '*' or port in permitted or (host == desktop and port == 3389)


def scoped_tokens(cfg):
    tokens = []
    for row in cfg['sites']:
        host = row['domain']
        ports = row.get('tcp', cfg['ports'])
        tokens.extend(host + ':' + str(port) for port in ports)
    return tokens


def grants(cfg):
    result = []
    for row in cfg['sites']:
        ports = row.get('tcp', cfg['ports'])
        grant = dict(domain=row['domain'], scope=row['scope'], anyTCP=ports == '*',
                     ports=[] if ports == '*' else sorted(set(ports)))
        if 'alias' in row:
            grant['alias'] = row['alias']
        result.append(grant)
    return result


def approved(cfg, status):
    if 'tcpRules' in status:
        return grants(cfg) == status['tcpRules']
    return (cfg['version'] == 1 and
            set(row['domain'] for row in cfg['sites']) <= set(status.get('approvedDomains', [])) and
            set(cfg['ports']) <= set(status.get('approvedPorts', [])))
