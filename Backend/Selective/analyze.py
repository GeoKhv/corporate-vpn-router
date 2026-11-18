"""One explicit destination, with no system resolution or direct connection."""
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import struct
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
from domain_map import DomainMap
from helper_client import RouteHelper
from sites import allowed_tcp, approved, hostname, matched_rule, validate
from http_router import pump, via_socks


def parse(text):
    text = text.strip()
    server = text.startswith('server:')
    if server:
        text = text[7:].strip().strip('"').strip("'")
        if not text.startswith(('http://', 'https://')):
            raise ValueError('После server: нужен полный HTTP(S) URL.')
    if not text or len(text) > 2048 or any(c.isspace() or ord(c)<32 for c in text) or chr(92) in text:
        raise ValueError('Нужно одно имя или ссылка в строке.')
    tree = text.startswith('*.')
    if tree:
        text = text[2:]
        if not hostname(text.lower()):
            raise ValueError('Маска поддерживается только в виде *.domain.example.')
    if text.startswith('jdbc:postgresql://'):
        text = text[5:]
    implicit_ssh = re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+', text)
    if implicit_ssh:
        text = 'ssh://' + text
    if '://' not in text and any(ch in text for ch in '/@?#'):
        raise ValueError('Укажите полный URL со схемой или имя и порт. IP/CIDR не поддерживаются.')
    defaults = {'':443, 'https':443, 'http':80, 'ssh':22, 'rdp':3389, 'redis':6379, 'postgresql':5432, 'tcp':None}
    try:
        url = urlsplit(text if '://' in text else '//' + text)
        host = (url.hostname or '').lower().removesuffix('.')
        explicit = url.port
    except ValueError:
        raise ValueError('Некорректный URL или TCP-порт.') from None
    if url.password is not None:
        raise ValueError('Удалите пароль из URL перед проверкой.')
    if url.scheme not in defaults or url.netloc.endswith(':'):
        raise ValueError('Неизвестная схема или отсутствует TCP-порт.')
    if not hostname(host) and not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',host):
        raise ValueError('Укажите DNS-имя. IP, CIDR и сложные маски не поддерживаются.')
    if host.isdigit() or host in ('localhost','local','onion'):
        raise ValueError('Нужно рабочее DNS-имя.')
    port = explicit if explicit is not None else defaults[url.scheme]
    if not port or not 1 <= port <= 65535:
        raise ValueError('Укажите TCP-порт от 1 до 65535.')
    return dict(host=host, port=port, scheme=url.scheme or ('https' if port == 443 else 'tcp'),
                assumed=explicit is None, tree=tree)


def target(text):
    item = parse(text)
    return item['host'], item['port'], item['scheme']


async def preview(request, cfg):
    from http_router import CorporateDNSFailure
    suffixes = list(dict.fromkeys(request.get('suffixes', [])))
    if len(suffixes)>24 or not all(hostname(s) for s in suffixes):
        raise ValueError('Проверьте список суффиксов.')
    rows = []
    for line in request['text'].splitlines():
        if not line.strip():
            continue
        if len(rows) >= 64:
            raise ValueError('За один раз можно добавить до 64 строк.')
        try:
            row = parse(line)
            host = row['host']
            if '.' not in host:
                alias = next((r['domain'] for r in cfg['sites'] if r.get('alias') == host), None)
                if alias:
                    row.update(host=alias, alias=host)
                else:
                    candidates = [host+'.'+s for s in suffixes]
                    if not candidates:
                        raise ValueError('Укажите суффиксы поиска или полное имя узла.')
                    async def lookup(name):
                        if not matched_rule(cfg, name):
                            return 'policy'
                        try:
                            _, writer = await asyncio.wait_for(via_socks(name,0,resolve_only=True),3)
                            writer.close()
                            return 'found'
                        except CorporateDNSFailure as exc:
                            return 'absent' if exc.rcode in (0,3) else 'error'
                        except (OSError, asyncio.IncompleteReadError):
                            return 'error'
                    states = await asyncio.gather(*(lookup(n) for n in candidates))
                    if 'error' in states:
                        raise ValueError('Корпоративный DNS недоступен. Результат поиска неполный.')
                    if 'policy' in states:
                        raise ValueError('Для проверки всех суффиксов нужно утвердить точное полное имя через черновик или уточнить суффиксы поиска.')
                    found = [n for n,v in zip(candidates,states) if v=='found']
                    if not found:
                        raise ValueError('Корпоративный DNS не нашёл это имя.')
                    row.update(host=found[0], choices=found, alias=host)
            rows.append(row)
        except ValueError as exc:
            rows.append(dict(error=str(exc)))
    return dict(rows=rows)


async def https_over_tunnel(host, port, upstream_reader, upstream_writer):
    """Use macOS certificate trust on the corporate TCP stream already opened."""
    with tempfile.TemporaryDirectory(prefix='cvr-https-', dir='/private/tmp') as directory:
        path = os.path.join(directory, 'socket')
        peer = asyncio.get_running_loop().create_future()

        def accept(reader, writer):
            if peer.done():
                writer.close()
            else:
                peer.set_result((reader, writer))

        server = await asyncio.start_unix_server(accept, path=path)
        async with server:
            proc = await asyncio.create_subprocess_exec('/usr/bin/curl', '-q',
                '--noproxy', '*', '--unix-socket', path, '--proto', '=https',
                '--head', '--silent', '--max-time', '8', '--output', '/dev/null',
                '--write-out', '%{http_code}', f'https://{host}:{port}/',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/bin'})
            tasks = []
            try:
                reader, writer = await asyncio.wait_for(peer, 3)
                server.close()
                tasks = [asyncio.create_task(pump(reader, upstream_writer)),
                         asyncio.create_task(pump(upstream_reader, writer))]
                status, _ = await proc.communicate()
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                if peer.done() and not peer.cancelled():
                    peer.result()[1].close()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        if proc.returncode in (35, 51, 58, 60, 77, 90, 91):
            return dict(stage='tls', message='TCP-соединение установлено. macOS не подтвердила TLS для этого имени.')
        if proc.returncode or not status.isdigit() or status == b'000':
            return dict(stage='https', message='TCP-соединение установлено. Ответ HTTPS не подтверждён.')
        code = int(status)
        return dict(stage='reachable', message=f'{host}, TCP {port}: TLS проверен, HTTP {code}. ' +
                    ('Сервис требует вход или дополнительных прав.' if code in (401, 403) else 'Вход в сервис не проверялся.'))


async def analyze(text, data, resources):
    requested, port, scheme = target(text)
    host = requested
    cfg = validate(json.loads((data/'work-sites.json').read_bytes()))
    short = '.' not in host
    if short:
        aliases = [r['domain'] for r in cfg['sites'] if r.get('alias') == host]
        if len(aliases) != 1:
            return dict(stage='short_name', message='Короткое имя не привязано. Укажите его полное рабочее имя и включите короткое имя в правиле.')
        host = aliases[0]
    if host in cfg['beforeLogin']:
        return dict(stage='excluded', message='Это имя предназначено для доступа до входа.')
    rule = matched_rule(cfg, host)
    proposal = dict(host=host, port=port)
    if not rule:
        return dict(stage='no_rule', message=f'Правило отсутствует. Если это рабочий ресурс, можно разрешить только {host}, TCP {port}.', **proposal)
    step = "helper"
    helper = RouteHelper(resources)
    try:
        status = await helper.open()
        if not allowed_tcp(cfg,host,port,status.get('approvedRDPHost')):
            return dict(stage='port', message=f'Порт исключён правилом. Можно добавить TCP {port} только для {host}.', **proposal)
        if not approved(cfg,status):
            return dict(stage='helper', message='Помощник не подтвердил этот набор правил. Откройте настройку правил и подтвердите изменения.')
        if status.get('active') is not True or status.get('cleanupPending') is not False:
            return dict(stage='inactive', message='Правило разрешает порт. Корпоративный туннель сейчас недоступен.')
        # Local DNS front creates the host route only after an in-tunnel lookup.
        step = 'dns'
        name = b''.join(bytes([len(x)])+x.encode('ascii') for x in host.split('.')) + b'\0'
        import secrets
        ident = secrets.randbits(16)
        q = struct.pack('!6H',ident,256,1,0,0,0)+name+struct.pack('!HH',1,1)
        reader, writer = await asyncio.open_connection('127.0.0.1',53541)
        try:
            writer.write(struct.pack('!H',len(q))+q)
            size, = struct.unpack('!H',await reader.readexactly(2))
            answer = await reader.readexactly(size)
        finally:
            writer.close()
        if (len(answer) != len(q)+16 or answer[:2] != q[:2] or answer[3]&15 or
                answer[12:len(q)] != q[12:] or answer[len(q):len(q)+6] != b'\xc0\x0c\x00\x01\x00\x01'):
            return dict(stage='dns', message='Рабочий DNS не подтвердил адрес назначения. TCP ещё не проверен.')
        ip = ipaddress.ip_address(answer[-4:])
        registry = DomainMap(data/'Selective/domain-map.json')
        if registry.name_for_ip(ip) != host:
            return dict(stage='dns', message='Не подтверждено соответствие адреса рабочему имени.')
        step = 'route'
        proc = await asyncio.create_subprocess_exec('/sbin/route','-n','get',str(ip),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        output,_ = await proc.communicate()
        if not re.search(rb'^\s*interface:\s*utun73\s*$',output,re.M):
            return dict(stage='route', message='Маршрут к адресу не указывает на рабочий интерфейс. TCP не проверен.')
        step = 'tcp'
        reader, writer = await asyncio.wait_for(via_socks(host, port),8)
        try:
            if scheme == 'https':
                step = 'tls'
                result = await https_over_tunnel(requested, port, reader, writer)
            else:
                result = dict(stage='reachable', message=f'{host}, TCP {port}: соединение установлено через рабочий туннель. Вход в сервис не проверялся.')
            if short:
                result['message'] += ' Адрес для TCP взят из алиаса. Системный поиск имени проверяется отдельно.'
            return result
        finally:
            writer.close()
    except (OSError, asyncio.IncompleteReadError, RuntimeError, ValueError):
        messages = {'helper':'Помощник недоступен. Проверка сети ещё не началась.',
                    'dns':'Корпоративный DNS не подтвердил адрес. TCP ещё не проверен.',
                    'route':'Не удалось проверить маршрут до рабочего адреса.',
                    'tcp':'DNS и рабочий маршрут подтверждены. Корпоративное TCP-соединение не установлено.',
                    'tls':'TCP установлен. Проверка TLS не завершена.'}
        return dict(stage=step, message=messages[step])
    finally:
        await helper.close()


if __name__ == '__main__':
    try:
        data = Path.home()/'Library/Application Support/Corporate VPN Router'
        # The signed SOCKS supervisor uses a relative Unix socket to fit sun_path.
        os.chdir(data)
        if '--preview' in sys.argv:
            request = json.load(sys.stdin)
            cfg = validate(json.loads((data/'work-sites.json').read_bytes()))
            result = asyncio.run(asyncio.wait_for(preview(request,cfg),45))
        else:
            address = sys.stdin.readline(2049)
            result=asyncio.run(asyncio.wait_for(analyze(address, data, HERE.parents[1]),18))
            cfg = validate(json.loads((data/'work-sites.json').read_bytes()))
            name = target(address)[0]
            name = next((r['domain'] for r in cfg['sites'] if r.get('alias')==name),name)
            rule = matched_rule(cfg,name)
            if rule:
                result['message'] = f"Правило {rule['domain']} · TCP {rule.get('tcp',cfg['ports'])}. " + result['message']
    except ValueError as exc:
        result=dict(stage="invalid",message=str(exc))
    except (OSError, asyncio.TimeoutError):
        result=dict(stage='timeout', message='Проверку завершить не удалось. Доступность сервиса не подтверждена.')
    if '--preview' in sys.argv:
        print(json.dumps(result,ensure_ascii=False))
        sys.exit()
    folder = Path.home()/'Library/Application Support/Corporate VPN Router/Selective'
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=folder,delete=False) as log:
            json.dump({'stage':result.get('stage','invalid')},log)
        os.replace(log.name,folder/'last-analysis.json')
    except OSError:
        pass
    print(json.dumps(result,ensure_ascii=False))
