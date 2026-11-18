"""Local, shareable support report. Export typed fields, never free-form log lines."""
from collections import Counter
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import plistlib
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time

ENGINE = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE))  # Resolve bundled modules before imports under python -I.
from gateway_disconnect import DISCONNECT_WORDS
RES = ENGINE.parent
HOME = Path.home()
DATA = HOME / 'Library/Application Support/Corporate VPN Router'
LOGS = HOME / 'Library/Logs'
LIMIT = 512 * 1024
CHECKS = ('Шлюз и pin', 'Авторизация', 'SSL-туннель', 'VPN-туннель', 'SOCKS5 · 1090', 'DNS в туннеле', 'Корпоративный HTTPS', 'HTTPS одного сайта')
COUNTERS = ('out_packets', 'in_packets', 'out_dns', 'in_dns', 'backpressure_events',
            'empty_liveness_messages_ignored', 'max_out_packet_bytes', 'max_in_packet_bytes')
WORDS = ('phase', 'component', 'event', 'code', 'helper', 'role', 'error_class', 'failed_phase',
         'error', 'refusal', 'stage')
NUMBERS = ('pid', 'attempt', 'dial_attempt', 'errno', 'rc', 'duration_ms', 'budget_ms', 'allowance_ms', 'http_status',
           'reusable', 'connection', 'type', 'rcode', 'atyp', 'command', 'port', 'errorCode', 'server_code')
MISSING = 'Данные отсутствуют или недоступны.'


def read_tail(path, limit=LIMIT):
    if any(parent.is_symlink() for parent in path.parents):
        raise OSError('linked directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError('unexpected file')
        clipped = info.st_size > limit
        if clipped:
            stream.seek(-limit, os.SEEK_END)
        data = stream.read(limit)
        if clipped:
            data = data.partition(b'\n')[2]
        return data.decode(errors='replace'), clipped


def document(path):
    text, clipped = read_tail(path)
    if clipped:
        raise ValueError('too large')
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError('unexpected shape')
    return value


def number(value):
    return type(value) in (bool, int, float) and -1e16 < value < 1e16


def utc(value):
    try:
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                return None
        elif type(value) in (int, float) and math.isfinite(value):
            parsed = datetime.fromtimestamp(value, timezone.utc)
        else:
            return None
        return parsed.astimezone(timezone.utc).isoformat(timespec='milliseconds')
    except (ValueError, OverflowError, OSError):
        return None


def version(value):
    return value if isinstance(value,str) and re.fullmatch(r'\d{1,4}(?:\.\d{1,4}){0,3}(?:-(?:alpha|beta)\.\d{1,3})?',value) else None


def run(args, timeout=4, payload=None, cap=LIMIT):
    """Bound memory and wall time for system commands, including the unified log."""
    try:
        with subprocess.Popen(args, stdin=subprocess.PIPE if payload else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
            try:
                if payload:
                    child.stdin.write(payload)
                    child.stdin.close()
                output = bytearray()
                end = time.monotonic() + timeout
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while len(output) < cap:
                        if time.monotonic() >= end or not selector.select(end-time.monotonic()):
                            return 'тайм-аут', output.decode(errors='replace')
                        part = os.read(child.stdout.fileno(), min(65536, cap-len(output)))
                        if not part:
                            rc = child.wait(timeout=max(0,end-time.monotonic()))
                            return ('ok' if rc==0 else 'ошибка '+str(rc)), output.decode(errors='replace')
                        output.extend(part)
                return 'достигнут лимит чтения', output.decode(errors='replace')
            finally:
                if child.poll() is None:
                    child.kill()
    except (OSError, subprocess.TimeoutExpired):
        return 'недоступно', ''


class Report:
    def __init__(self, terms):
        self.terms = set(terms)
        self.lines = []
        self.last_failure = None

    def section(self, title, collect):
        self.lines.extend(['', '## '+title])
        try:
            collect()
        except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError):
            self.lines.append(MISSING)

    def row(self, values):
        self.lines.append(json.dumps(values, ensure_ascii=False, separators=(', ', ': '), allow_nan=False))

    def term(self, value):
        if isinstance(value, str):
            if value in self.terms or re.fullmatch(r'(?:EXIT_-?\d{1,3}|CONTROL_HTTP_[1-5]\d\d)',value):
                return value
            if value in {'HELPER_'+s.upper() for s in ('missing','updateRequired','repairRequired','checkFailed','unavailable','previousSession')}:
                return value
            if '.' in value and len(value)<140 and all(p in self.terms for p in value.split('.')):
                return value
        return 'unknown'

    def event(self, row):
        out = {k:self.term(row[k]) for k in WORDS if row.get(k) is not None}
        out.update({k:row[k] for k in NUMBERS if number(row.get(k))})
        words = row.get('server_words')
        if isinstance(words, list):
            out['server_words'] = [word for word in words[:40] if isinstance(word, str) and word in DISCONNECT_WORDS]
        for k in ('appVersion','updateVersion','python'):
            if version(row.get(k)):
                out[k]=row[k]
        stamp=utc(row.get('time'))
        if stamp:
            out['UTC']=stamp
        route=row.get('route')
        if isinstance(route,dict):
            out['interface']=interface(route.get('interface'))
        return out

    def journal(self, path, label, max_rows=700, connection=False):
        try:
            raw, clipped = read_tail(path)
        except OSError:
            self.lines.append(label+' — '+MISSING)
            return
        lines = raw.splitlines()
        self.lines.append(f'{label} — последние {min(len(lines),max_rows)} строк'
                          + (' (начало опущено).' if clipped or len(lines)>max_rows else '.'))
        malformed=0
        for line in lines[-max_rows:]:
            try:
                event=json.loads(line)
                if not isinstance(event,dict):
                    raise ValueError()
                result=self.event(event)
                if result:
                    self.row(result)
                    if connection and result.get('event') in ('failed','failure','error') and result.get('code'):
                        if (not self.last_failure or result.get('failed_phase') or
                            (result.get('pid'),result.get('attempt'),result.get('code')) !=
                            tuple(self.last_failure.get(k) for k in ('pid','attempt','code'))):
                            self.last_failure=result
            except (ValueError, RecursionError):
                malformed+=1
        if malformed:
            self.lines.append(f'Нечитаемых строк: {malformed}.')

    def status(self):
        state=document(DATA/'ssl-status.json')
        self.row({k:state[k] for k in ('connected','activeAttempt','port') if number(state.get(k))}
                 | {'UTC':utc(state.get('updated'))})
        checks=state.get('checks',{})
        for name in CHECKS:
            item=checks.get(name) if isinstance(checks,dict) else None
            if isinstance(item,dict):
                self.row({'check':name,'status':self.term(item.get('status')),'UTC':utc(item.get('checked'))})
        probe=state.get('httpsProbe')
        if isinstance(probe,dict) and probe:
            safe={k:probe[k] for k in ('curlExit','httpStatus','tlsVerify','reachable') if number(probe.get(k))}
            if probe.get('method') in ('GET','HEAD'):safe['method']=probe['method']
            safe.update(check='HTTPS одного сайта',UTC=utc(probe.get('checked')))
            self.row(safe)
        counters=state.get('counters')
        if isinstance(counters,dict):
            self.row({k:counters[k] for k in COUNTERS if number(counters.get(k))})

    def services(self):
        pointer, clipped=read_tail(DATA/'Selective/last-session.txt',512)
        stage=Path(pointer.strip())
        if (clipped or stage.parent!=Path('/private/tmp') or not re.fullmatch(r'cvr-selective-input-[A-Za-z0-9_-]+',stage.name)
                or stage.is_symlink() or stage.stat().st_uid!=os.getuid()):
            raise ValueError()
        self.journal(stage/'services.jsonl','DNS и SOCKS')
        self.journal(stage/'dns-front.jsonl','DNS рабочих сайтов')
        for name in ('ready','cleanup'):
            try:
                data=document(stage/(name+'.json'))
            except (OSError,ValueError):
                self.lines.append(name+' — '+MISSING)
                continue
            self.row({'event':name, **{k:data[k] for k in ('interface_present','resolver_present','recovered')
                                       if isinstance(data.get(k),bool)}, 'UTC':utc(data.get('started'))})

    def traces(self):
        paths=recent(DATA/'Selective/ConnectionDiagnostics','connections-*.jsonl',6)
        if not paths:
            self.lines.append('Подробная трассировка TLS не записана. Основные этапы входа приведены в журнале попыток.')
        for i,path in enumerate(paths,1):
            self.journal(path,f'Трасса {i}',400)

    def startup(self):
        paths=recent(LOGS/'Corporate VPN Router','launch-*.txt',6)
        if not paths:
            self.lines.append(MISSING)
        for i,path in enumerate(paths,1):
            self.lines.append(f'Запуск {i}')
            for line in read_tail(path)[0].splitlines()[-100:]:
                parts=line.split(maxsplit=2)
                if len(parts)>=2 and utc(parts[0]):
                    self.row({'UTC':utc(parts[0]),'event':self.term(parts[1])})

    def helper(self):
        status, text=run([str(RES/'RouteHelper/RouteClient')],payload=b'{"op":"status"}\n')
        self.lines.append('Запрос status: '+status)
        reply=json.loads(text)
        if not isinstance(reply,dict):raise ValueError()
        item={k:reply[k] for k in ('ok','active','cleanupPending') if isinstance(reply.get(k),bool)}
        for k in ('version','build'):
            item[k]=version(reply.get(k))
        if reply.get('error'):
            item['error']=self.term(reply['error'])
        self.row(item)
        rules=reply.get('tcpRules')
        if isinstance(rules,list):
            for index,rule in enumerate(rules[:256]):
                if not isinstance(rule,dict):continue
                self.row({'rule':index+1,'scope':rule.get('scope') if rule.get('scope') in ('tree','exact') else 'unknown',
                          'any_tcp':rule.get('anyTCP') is True,'short_name':bool(rule.get('alias')),
                          'tcp_ports':[port for port in rule.get('ports',[]) if type(port) is int and 1<=port<=65535][:32]})
        elif isinstance(reply.get('approvedPorts'),list):
            self.row({'approved_tcp_ports':[p for p in reply['approvedPorts'] if type(p) is int and 1<=p<=65535][:32]})
        try:
            stage=document(DATA/'Selective'/'last-analysis.json')['stage']
            if stage in ('invalid','short_name','excluded','no_rule','port','helper','inactive','dns','route','tcp','tls','reachable','timeout'):
                self.row({'last_tcp_check':stage})
        except (OSError,KeyError,ValueError):pass
        failure=reply.get('lastAdapterFailure')
        if isinstance(failure,dict):
            self.row({'lastAdapterFailure':self.term(failure.get('stage')),'UTC':utc(failure.get('time')),
                      **{k:failure[k] for k in ('elapsedMilliseconds','identityMilliseconds','interfaceIndex',
                         'childPID','childRunning','waitStatus','waitErrno','processState','processInfoErrno')
                         if number(failure.get(k))}})

    def checkpoint(self):
        import trust
        try:
            raw=trust.official_output()
            rows=trust.parse_sites(raw)
        except trust.Refused as exc:
            self.row({'official_status':self.term(str(exc))})
            return
        try:
            saved=document(DATA/'ssl-site.json')
        except (OSError,ValueError):
            saved={}
        primary=trust.approved_receipt() or {}
        self.row({'configured_sites':len(rows),'saved_binding':bool(saved),
                  'saved_dns_identity':'dns_name' in saved,'saved_leaf_pin':'leaf_sha256' in saved,
                  'preconfigured_alternate_pin':bool(trust.approved_site_pin())})
        selected=None
        try:
            selected=trust.choose_site(rows,raw)[0]
        except trust.Refused as exc:
            self.row({'selection':self.term(str(exc))})
        for i,(host,ip,state) in enumerate(rows.values(),1):
            self.row({'profile':i,'state':state,'selected':host==selected,'primary':host==primary.get('site'),
                      'saved':host==saved.get('site'),'gateway_route':route_interface(['-inet',ip])})

    def network(self):
        for name,args in [('default_ipv4',['-inet','default']),('default_ipv6',['-inet6','default']),
                          ('public_ipv4',['-inet','1.1.1.1'])]:
            self.row({name:route_interface(args)})
        status,dns=run(['/usr/sbin/scutil','--dns'])
        self.row({'DNS':status,'resolver_sections':len(re.findall(r'^resolver #',dns,re.M)),
                  'router_resolvers':len(re.findall(r'^\s*port\s*:\s*53541\s*$',dns,re.M))})
        status,proxies=run(['/usr/sbin/scutil','--proxy'])
        fields=dict(re.findall(r'^\s*(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*:\s*([01])\s*$',proxies,re.M))
        self.row({'proxy':status, **{k:v=='1' for k,v in fields.items()}})
        status,vpns=run(['/usr/sbin/scutil','--nc','list'])
        self.lines.append('Сетевые службы macOS: '+status)
        for label in ('SOTA','AdGuard'):
            matches=[m.group(1) for line in vpns.splitlines() if label.lower() in line.lower()
                     for m in [re.search(r'\((Connected|Disconnected|Connecting|Disconnecting)\)',line)] if m]
            self.row({label:matches or ['не указан службой macOS']})

    def unified(self):
        processes=('TracSrvWrapper','Endpoint Security','Sota Connect','CorporateVPNRouter','RouteHelper','sing-box')
        pred='('+' OR '.join(f'process == "{p}"' for p in processes)+') AND (messageType == error OR messageType == fault)'
        status,text=run(['/usr/bin/log','show','--last','1h','--style','ndjson','--predicate',pred],timeout=8,cap=1024*1024)
        categories=('certificate','dns','timeout','route','proxy','authentication','permission','connection')
        counts=Counter()
        for line in text.splitlines():
            try:
                entry=json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(entry,dict):continue
            process=str(entry.get('processImagePath','')).rsplit('/',1)[-1]
            if process in processes:
                msg=str(entry.get('eventMessage','')).lower()
                category=next((c for c in categories if c in msg),'other')
                counts[(process,category)]+=1
        self.lines.append('Доступные ошибки и сбои за последний час, по процессу и категории. Состояние чтения: '+status)
        for (process,category),count in sorted(counts.items()):
            self.row({'process':process,'category':category,'count':count})
        if not counts:self.lines.append('Подходящих сообщений в прочитанной части нет.')

    def crashes(self):
        found=False
        for name in ('CorporateVPNRouter','RouteHelper','TracSrvWrapper','sing-box'):
            for path in recent(LOGS/'DiagnosticReports',name+'-*.ips',3):
                text,clipped=read_tail(path)
                found=True
                self.row({'process':name,'file_UTC':utc(path.stat().st_mtime),'partial':clipped})
                if clipped:continue
                # Apple IPS files have a metadata JSON line followed by the report.
                _,_,body=text.partition('\n')
                try: crash=json.loads(body)
                except ValueError:continue
                if isinstance(crash,dict):
                    exc=crash.get('exception')
                    if isinstance(exc,dict):
                        self.row({'type':self.term(exc.get('type')),'signal':self.term(exc.get('signal'))})
        if not found:self.lines.append(MISSING)

    def sota_reports(self):
        found=False
        for folder in (HOME/'Desktop',HOME/'Downloads'):
            for path in recent(folder,'Router-SOTA-*.txt',2):
                found=True
                self.row({'file_UTC':utc(path.stat().st_mtime)})
                for line in read_tail(path)[0].splitlines():
                    if re.fullmatch(r'\[(?:SOTA_ON|SOTA_OFF|AFTER_[A-Z_]{1,24})\]',line) and line in (
                            '[SOTA_ON]','[SOTA_OFF]','[AFTER_CLEANUP]','[AFTER_DNS_REFRESH]'):
                        self.lines.append(line)
                    key,sep,val=line.partition('=')
                    if not sep:continue
                    if re.fullmatch(r'(?:tcp_443_to_(?:1\.1\.1\.1|8\.8\.8\.8)|(?:system_dns|configured_dns|direct_https[46])_(?:example\.com|www\.apple\.com)|sota_system_service|default_ipv[46]|configured_dns_route|utun73)',key):
                        if val in ('ok','failed','no_answer','unavailable','route_mismatch','not_observed',
                                   'router_address_present','other_address','Connected','Disconnected','not_reported','unknown') or (
                                interface(val)!='unknown' or re.fullmatch(r'curl:\d{1,3},http:\d{3}',val)):
                            self.row({key:val})
        if not found:self.lines.append('Сохранённых результатов проверки SOTA не найдено.')


def recent(folder, glob, limit):
    if folder.is_symlink() or not folder.is_dir():
        return []
    paths=[]
    for p in folder.glob(glob):
        try:
            meta=p.lstat()
            if meta.st_uid==os.getuid() and stat.S_ISREG(meta.st_mode):paths.append((meta.st_mtime,p))
        except OSError:
            continue
    return [p for _,p in sorted(paths)[-limit:]]


def interface(name):
    return name if isinstance(name,str) and re.fullmatch(r'(?:utun|ipsec|ppp|en|lo|bridge|gif|awdl)\d{1,4}',name) else 'unknown'


def route_interface(args):
    status,text=run(['/sbin/route','-n','get',*args],timeout=2)
    hit=re.search(r'^\s*interface:\s*(\S+)',text,re.M)
    return interface(hit[1]) if status=='ok' and hit else 'unknown'


def render():
    report=Report(json.loads((RES/'ReportTerms.json').read_bytes()))
    info=plistlib.loads((RES.parent/'Info.plist').read_bytes())
    report.lines=['# Corporate VPN Router — отчёт диагностики',
        'Время событий указано в UTC. Снимок текущего состояния может отличаться от состояния в момент сбоя.',
        'В журнале попыток события одного запуска связаны полями pid и attempt. Начните с последнего failure или failed и предшествующего этапа.',
        'Неизвестные текстовые значения обозначены unknown. Интерфейс utun сам по себе не указывает владельца VPN.']
    report.row({'UTC':utc(time.time()),'version':version(info.get('CFBundleShortVersionString')),
                'build':version(info.get('CFBundleVersion')),'macOS':version(platform.mac_ver()[0]),
                'arch':platform.machine() if platform.machine() in ('arm64','x86_64') else 'unknown'})
    summary_position=len(report.lines)
    report.lines.extend(['','## Попытки подключения (от старых к новым)'])
    for name,label in [('connection-events.previous.jsonl','Предыдущий файл'),('connection-events.jsonl','Текущий файл')]:
        report.journal(DATA/'Selective'/name,label,2500,connection=True)
    summary=(json.dumps(report.last_failure,ensure_ascii=False) if report.last_failure else
             'В прочитанной части журнала попыток нет ошибки с кодом.')
    report.lines[summary_position:summary_position]=['','Последняя записанная ошибка подключения:',summary]
    for title,method in [('Последнее состояние Router и проверки',report.status),
            ('Штатный Check Point и выбор сайта',report.checkpoint),('Помощник маршрутов',report.helper),
            ('Маршруты, DNS, прокси и другие VPN сейчас',report.network),('DNS и SOCKS последнего сеанса',report.services),
            ('Трассировки соединений (до 6 последних)',report.traces),('История запусков',report.startup),
            ('Обновления',lambda:report.journal(DATA/'update-events.jsonl','Sparkle')),
            ('Системный журнал macOS',report.unified),('Сбои процессов (.ips)',report.crashes),
            ('Ранее сохранённые проверки SOTA',report.sota_reports)]:
        report.section(title,method)
    return '\n'.join(report.lines)+'\n'


def save(destination):
    result=render()
    with tempfile.NamedTemporaryFile('w',dir=destination.parent,encoding='utf-8',delete=False) as tmp:
        path=Path(tmp.name)
        try:
            tmp.write(result)
            tmp.flush()
            os.replace(path,destination)
        finally:
            path.unlink(missing_ok=True)


if __name__=='__main__':
    save(Path(sys.argv[1]))
