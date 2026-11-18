"""One explicit destination, with no system resolution or direct connection."""
import asyncio
import ipaddress
import json
from pathlib import Path
import re
import ssl
import struct
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
from domain_map import DomainMap
from helper_client import RouteHelper
from sites import allowed_tcp, approved, hostname, matched_rule, validate
from http_router import via_socks


def target(text):
    text = text.strip()
    if not text or len(text) > 2048 or any(c.isspace() for c in text):
        raise ValueError('Введите одно имя, имя:порт или URL.')
    for value in [text.strip('[]'), text.split('/')[0].strip('[]')]:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        raise ValueError('Прямые IP и сети CIDR пока не поддерживаются.')
    url = urlsplit(text if '://' in text else '//' + text)
    defaults = {'':443, 'https':443, 'http':80, 'ssh':22, 'rdp':3389, 'tcp':None}
    if url.scheme not in defaults or url.username is not None or url.password is not None:
        raise ValueError('Поддерживаются TCP, SSH, RDP и HTTP(S) без данных входа.')
    host = (url.hostname or '').lower().rstrip('.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError('Прямые IP и сети CIDR пока не поддерживаются.')
    if not hostname(host) and not re.fullmatch('[a-z][a-z0-9-]{0,62}',host):
        raise ValueError('Недопустимое имя назначения.')
    port = url.port if url.port is not None else defaults[url.scheme]
    if not port or not 1 <= port <= 65535:
        raise ValueError('Укажите TCP-порт от 1 до 65535.')
    return host, port, url.scheme


async def analyze(text, data, resources):
    host, port, scheme = target(text)
    cfg = validate(json.loads((data/'work-sites.json').read_bytes()))
    if '.' not in host:
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
        proc = await asyncio.create_subprocess_exec('/sbin/route','-n','get',str(ip),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        output,_ = await proc.communicate()
        if not re.search(rb'^\s*interface:\s*utun73\s*$',output,re.M):
            return dict(stage='route', message='Маршрут к адресу не указывает на рабочий интерфейс. TCP не проверен.')
        reader, writer = await via_socks(host, port)
        try:
            if scheme == 'https':
                await writer.start_tls(ssl.create_default_context(),server_hostname=host)
            return dict(stage='reachable', message=f'{host}, TCP {port}: соединение установлено через рабочий туннель. '+('Сертификат TLS проверен. ' if scheme=='https' else '')+'Вход в сервис не проверялся.')
        finally:
            writer.close()
    except ssl.SSLError:
        return dict(stage='tls', message='TCP-соединение установлено, проверка TLS завершилась ошибкой.')
    except (OSError, asyncio.IncompleteReadError, RuntimeError, ValueError):
        return dict(stage='tcp', message='Корпоративный путь или соединение не подтвердились. Данных для вывода о запрете порта нет.')
    finally:
        await helper.close()


if __name__ == '__main__':
    try:
        result=asyncio.run(asyncio.wait_for(analyze(sys.stdin.readline(2049),
            Path.home()/'Library/Application Support/Corporate VPN Router', HERE.parents[1]),18))
    except ValueError as exc:
        result=dict(stage="invalid",message=str(exc))
    except (OSError, asyncio.TimeoutError):
        result=dict(stage='timeout', message='Проверку завершить не удалось. Доступность сервиса не подтверждена.')
    import tempfile, os
    folder = Path.home()/'Library/Application Support/Corporate VPN Router/Selective'
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=folder,delete=False) as log:
            json.dump({'stage':result.get('stage','invalid')},log)
        os.replace(log.name,folder/'last-analysis.json')
    except OSError:
        pass
    print(json.dumps(result,ensure_ascii=False))
