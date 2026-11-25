"""Unprivileged application-owned selective session and native authorization."""
import asyncio
import json
import ipaddress
import re
import os
from pathlib import Path
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from domain_map import DomainMap, V4, V6
from policy import validate_selective
from services import serve

RESOURCES=Path(__file__).resolve().parents[2]
DATA=Path.home()/'Library/Application Support/Corporate VPN Router'
STATE=DATA/'Selective'
CLEANUP_CONFIRMED=True


def emit(state, message, **extra):
    print(json.dumps(dict(state=state,message=message,**extra)),flush=True)


def identity(pid):
    r=subprocess.run(['/bin/ps','-p',str(pid),'-o','lstart=','-o','comm='],capture_output=True,text=True)
    return r.stdout.strip() if r.returncode==0 else ''


def policy():
    cfg=json.loads((DATA/'work-sites.json').read_text())
    gateway=json.loads((DATA/'ssl-site.json').read_text()).get('site') if (DATA/'ssl-site.json').exists() else None
    return validate_selective(cfg,gateway),gateway


def initialize_map():
    STATE.mkdir(mode=0o700,exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid!=os.getuid() or STATE.stat().st_mode&0o077:
        raise ValueError('Папка таблицы имён должна принадлежать пользователю с правами 0700.')
    target=STATE/'domain-map.json'; marker=STATE/'initialized'
    if marker.exists() and not target.exists():
        raise ValueError('Устойчивая таблица имён отсутствует. Восстановите её из копии; адреса нельзя выделять повторно.')
    if not target.exists():
        seed=DATA/'Provisioning/DefaultDomainMap.json'
        if not seed.exists():seed=RESOURCES/'DefaultDomainMap.json'
        value=seed.read_bytes() if seed.exists() else b'{"schema":"cvr-stable-domain-map-v1","names":{}}'
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())
    registry=DomainMap(target)
    with marker.open('a') as f:f.flush();os.fsync(f.fileno())
    fd=os.open(STATE,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return registry


def quote(value):return "'"+str(value).replace("'","'\\''")+"'"


def helper_is_idle(status):
    return status.get('active') is False and status.get('cleanupPending') is False


def verify_dns_addresses(output):
    """Protect macOS resolver endpoints, including scoped VPN DNS servers."""
    nameservers = re.findall(r'^\s*nameserver\[\d+\]\s*:\s*(\S+)', output, re.M)
    if not nameservers:
        raise RuntimeError('SYSTEM_DNS_UNKNOWN')
    for value in nameservers:
        try:
            address = ipaddress.ip_address(value.split('%', 1)[0])
        except ValueError:
            raise RuntimeError('SYSTEM_DNS_UNKNOWN') from None
        if address in (ipaddress.ip_address('198.18.73.1'), ipaddress.ip_address('fdc7:7652:9a10::1')) or address in V4 or address in V6:
            raise RuntimeError('SYSTEM_DNS_ADDRESS_CONFLICT')


async def check_system_dns():
    process = await asyncio.create_subprocess_exec('/usr/sbin/scutil', '--dns',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        output, _ = await asyncio.wait_for(process.communicate(), 3)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if process.returncode is None:
            try: process.kill()
            except ProcessLookupError: pass
        await process.wait()
        if isinstance(exc, asyncio.TimeoutError):
            raise RuntimeError('SYSTEM_DNS_UNKNOWN') from exc
        raise
    if process.returncode:
        raise RuntimeError('SYSTEM_DNS_UNKNOWN')
    verify_dns_addresses(output.decode(errors='replace'))


async def connection_site():
    """A user-initiated connect is the only entry point allowed to start the service."""
    global CLEANUP_CONFIRMED
    import trust
    from helper_client import RouteHelper
    try:
        return trust.official_info()
    except trust.Refused as exc:
        if str(exc) != 'OFFICIAL_SERVICE_NOT_STARTED':
            raise

    # Closing the menu's command pipe cancels preflight before the main reader exists.
    disconnect = select.poll()
    disconnect.register(sys.stdin.fileno(), select.POLLHUP | select.POLLERR)
    def check_cancelled():
        if disconnect.poll(0):
            raise RuntimeError('INPUT_CANCELLED')

    check_cancelled()
    helper = RouteHelper(RESOURCES)
    try:
        status = await helper.open()
        if not helper_is_idle(status):
            CLEANUP_CONFIRMED = False
            raise RuntimeError('HELPER_SESSION_PENDING')
        if status.get('allowCheckPointStart') is not True:
            raise RuntimeError('CHECKPOINT_START_NOT_AUTHORIZED')
        emit('restoringCheckPoint', 'Служба Check Point недоступна. Восстанавливаем её и продолжаем подключение…')
        check_cancelled()
        await helper.call('ensureCheckPointService')
    finally:
        await helper.close()

    deadline = time.monotonic() + 15
    while True:
        check_cancelled()
        try:
            return trust.official_info()
        except trust.Refused as exc:
            if str(exc) != 'OFFICIAL_SERVICE_NOT_STARTED':
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError('CHECKPOINT_SERVICE_STILL_UNAVAILABLE') from exc
        await asyncio.sleep(0.5)


async def start(app_pid):
    global CLEANUP_CONFIRMED
    # Signed official IPC state is checked before listeners or route mutation.
    # An Idle VPN is normal; only explicit service errors are classified as such.
    from trust import official_info
    from helper_client import RouteHelper
    from sites import rdp_host_for_profile, approved, matched_rule
    from sparse_dns import serve as serve_front
    import trust
    try:
        gateway,gateway_ip,_=await connection_site()
    except trust.Refused as exc:
        if str(exc)!='OFFICIAL_SITE_AMBIGUOUS':raise
        rows=trust.official_records(trust.official_output(), trust.GatewayDNS())
        approved_sites={p['site'] for p in (trust.approved_receipt(),trust.approved_site_pin()) if p}
        choices=sorted(set(rows)&approved_sites)
        if not choices or any(row.state!='Idle' for row in rows.values()):raise
        selected=choices[0]
        if len(choices)>1:
            emit('selectingSite','Выберите рабочий сайт.',sites=choices)
            line=sys.stdin.buffer.readline(8193)
            if not line or len(line)>8192:raise RuntimeError('INPUT_CANCELLED')
            value=json.loads(line)
            if not isinstance(value,dict) or value.get('site') not in choices:raise RuntimeError('INVALID_SITE_SELECTION')
            selected=value['site']
        target=DATA/'preferred-site.json'
        if target.is_symlink():raise RuntimeError('INVALID_SITE_SELECTION')
        with tempfile.NamedTemporaryFile('w',dir=DATA,delete=False) as stream:
            temp=Path(stream.name)
            try:
                json.dump({'site':selected},stream);stream.flush()
                os.replace(temp,target)
            finally:temp.unlink(missing_ok=True)
        gateway,gateway_ip,_=official_info()
    cfg,_=policy()
    validate_selective(cfg,gateway)
    helper=RouteHelper(RESOURCES)
    stage=None; tasks=[]; stop=asyncio.Event(); prepared=False; reader=False
    loop=asyncio.get_running_loop()
    activation=asyncio.Event()
    held=asyncio.Event()
    published=False
    repair_task = None
    async def repair_dns(host):
        outcome = 'unconfirmed'
        try:
            # Check both resolvers twice in an unprivileged, time-bounded child.
            proc = await asyncio.create_subprocess_exec(sys.executable, '-I', '-B',
                str(Path(__file__).with_name('system_dns_check.py')), host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                output, _ = await asyncio.wait_for(proc.communicate(), 16)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            if proc.returncode == 0 and output.strip() in (b'missing', b'different') and not held.is_set() and not stop.is_set():
                await helper.call('refreshDNS', name=host)
                outcome = 'refreshed'
            elif proc.returncode == 0 and output.strip() == b'ok':
                outcome = 'healthy'
        except (OSError, RuntimeError, asyncio.TimeoutError) as error:
            outcome = 'cooldown' if str(error) == 'DNS_REPAIR_COOLDOWN' else 'failed'
        finally:
            emit('dnsRepairResult', outcome)

    def handle_input(command):
        nonlocal repair_task
        # The menu sends this single fixed token only after SSL and the SOCKS
        # owner were verified. EOF, cancel, or an invalid command always stops.
        if command.startswith(b'repair-dns '):
            name = command[11:].strip().decode('ascii', errors='replace')
            allowed = (len(name) <= 253 and re.fullmatch(r'[a-z0-9.-]+', name)
                       and matched_rule(cfg, name))
            if (allowed and published and not held.is_set() and not stop.is_set()
                    and (repair_task is None or repair_task.done())):
                repair_task = loop.create_task(repair_dns(name))
            else:
                emit('dnsRepairResult', 'unconfirmed')
            return
        if command == b'activate\n' and not activation.is_set():
            activation.set()
        elif published and command == b'hold\n':
            held.set()
        elif published and held.is_set() and command == b'resume\n':
            held.clear()
            emit('ready','Рабочий транспорт восстановлен.',session=str(stage))
        else:
            stop.set()
            activation.set()
    incoming = bytearray()
    def input_ready():
        data = os.read(sys.stdin.fileno(), 4096)
        if not data or len(incoming) + len(data) > 8192:
            cancel()
            return
        incoming.extend(data)
        while b'\n' in incoming:
            line, _, rest = incoming.partition(b'\n')
            incoming[:] = rest
            handle_input(bytes(line) + b'\n')
    def cancel():
        stop.set()
        activation.set()
    try:
        status=await helper.open()
        if not helper_is_idle(status):
            CLEANUP_CONFIRMED=False
            raise RuntimeError('HELPER_SESSION_PENDING')
        if status.get('version')!='0.3.0-alpha.3' or status.get('build') not in ('0.3.10','0.3.11','0.3.20'):raise RuntimeError('HELPER_UPDATE_REQUIRED')
        if not approved(cfg, status):
            raise RuntimeError('HELPER_POLICY_APPROVAL_REQUIRED')
        loop.add_reader(sys.stdin.fileno(),input_ready);reader=True
        for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,cancel)
        await check_system_dns()
        rdp_host = rdp_host_for_profile(cfg, status.get('approvedRDPHost'))
        emit('awaitingTunnel','Сайт проверен. Ожидание корпоративного входа.',gateway=gateway+'@'+gateway_ip,rdpHost=rdp_host)
        await activation.wait()
        if stop.is_set():return
        # A different VPN or an old lease can appear while MFA is on screen.
        await check_system_dns()
        if not helper_is_idle(await helper.call('status')):
            CLEANUP_CONFIRMED=False
            raise RuntimeError('HELPER_SESSION_PENDING')
        if stop.is_set():return
        registry=initialize_map()
        rdp_rule = {'rdpSlot': registry.allocate(rdp_host)} if rdp_host else {}
        stage=Path(tempfile.mkdtemp(prefix='cvr-selective-input-',dir='/private/tmp'))
        (STATE/'last-session.txt').write_text(str(stage))
        inp=dict(mode='stable-map',host=cfg['sites'][0]['domain'],ipv4='198.18.73.2',ipv6='fdc7:7652:9a10::2',
                 policy=cfg,verify_names='tcpRules' in status,rdp_host=rdp_host,gateway=gateway,dns_port=53541,dns_backend_port=53542,socks_port=11090,
                 password=secrets.token_hex(24),map_path=str(STATE/'domain-map.json'),
                 retained_addresses=[registry.address(name,version) for name in registry.names for version in (4,6)])
        (stage/'trial-input.json').write_text(json.dumps(inp))
        service=asyncio.create_task(serve(inp,stage,stop_event=stop,held=held));tasks.append(service)
        for _ in range(60):
            if service.done():await service
            if (stage/'services.pid').exists():break
            await asyncio.sleep(.1)
        else:raise RuntimeError('Локальный мост не готов.')
        if stop.is_set():return
        emit('starting','Запуск рабочих маршрутов через установленный помощник…',session=str(stage))
        # A failed begin can still have created a journal/interface. Always
        # verify cleanup, including partial startup and lost replies.
        prepared=True;CLEANUP_CONFIRMED=False
        await helper.call('begin',domains=[r['domain'] for r in cfg['sites']],ports=[443] if 'tcpRules' in status else cfg['ports'],password=inp['password'],**rdp_rule)
        async def install(addresses):
            await check_system_dns()
            if 'tcpRules' in status:
                current = DomainMap(STATE/'domain-map.json')
                for slot in {int(a) & 255 for a in addresses}:
                    name = current.reverse.get(slot)
                    if name and matched_rule(cfg, name):
                        await helper.call('register', name=name, slot=slot)
            await helper.call('route',addresses=[str(a) for a in addresses])
        dns_ready = asyncio.Event()
        front = asyncio.create_task(serve_front(cfg, stage, stop.is_set, route_installer=install, ready=dns_ready))
        tasks.append(front)
        ready_wait = asyncio.create_task(dns_ready.wait())
        try:
            # Each helper call is bounded. A fixed startup deadline would cut
            # off valid progress on larger durable maps.
            await asyncio.wait((front, ready_wait), return_when=asyncio.FIRST_COMPLETED)
        finally:
            ready_wait.cancel()
            await asyncio.gather(ready_wait, return_exceptions=True)
        if front.done():
            await front
            if not stop.is_set():
                raise RuntimeError('Локальный DNS остановился.')
        if stop.is_set():return
        await check_system_dns()
        if stop.is_set():return
        await helper.call('publish')
        published=True
        (stage/'ready.json').write_text(json.dumps(dict(helper='launchd',started=time.time())))
        emit('ready','Рабочие маршруты готовы. Safari, Яндекс и Chrome используют обычные настройки.',session=str(stage),gateway=gateway+'@'+gateway_ip)
        next_dns_check=loop.time()+10
        while not stop.is_set():
            for task in tasks:
                if task.done():await task;raise RuntimeError('Локальный мост остановился.')
            if loop.time() >= next_dns_check:
                await check_system_dns()
                next_dns_check=loop.time()+10
            if stop.is_set():break
            await helper.call('heartbeat')
            try:await asyncio.wait_for(stop.wait(),2)
            except asyncio.TimeoutError:pass
    except Exception as exc:
        emit('error',str(exc),code=str(exc) if str(exc).replace('_','').isalnum() else type(exc).__name__,cleanupConfirmed=CLEANUP_CONFIRMED)
        raise
    finally:
        cancelled=stop.is_set()
        stop.set()
        if reader:loop.remove_reader(sys.stdin.fileno())
        if repair_task is not None: tasks.append(repair_task)
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if prepared:
            try:
                try:await helper.call('stop')
                except RuntimeError as exc:
                    if str(exc)!='NO_SESSION':raise
                status=await helper.call('status')
                if not helper_is_idle(status):raise RuntimeError('CLEANUP_UNCONFIRMED')
                if stage:(stage/'cleanup.json').write_text(json.dumps(dict(interface_present=False,resolver_present=False,helpers_remaining=[],helper='launchd')))
                CLEANUP_CONFIRMED=True
                emit('stopped','Рабочие маршруты удалены.',cleanupConfirmed=True)
            except Exception as exc:
                # launchd may be replacing a crashed broker. Reconnect only to
                # read status; never recreate routes automatically after loss.
                recovered=False
                for _ in range(12):
                    await helper.close()
                    try:
                        status=await helper.open()
                        if helper_is_idle(status):
                            recovered=True;break
                    except Exception:pass
                    await asyncio.sleep(.5)
                if recovered:
                    if stage:(stage/'cleanup.json').write_text(json.dumps(dict(interface_present=False,resolver_present=False,helpers_remaining=[],helper='launchd',recovered=True)))
                    CLEANUP_CONFIRMED=True
                    emit('stopped','После сбоя рабочие маршруты удалены. Можно подключиться снова.',cleanupConfirmed=True)
                else:emit('error','Помощник проверяет завершение маршрутов: '+str(exc),code='CLEANUP_UNCONFIRMED',cleanupConfirmed=False)
        elif CLEANUP_CONFIRMED and cancelled:
            emit('stopped','Рабочие маршруты не включены.',cleanupConfirmed=True)
        await helper.close()  # daemon independently cleans on XPC EOF/lease expiry
        if stage:(stage/'trial-input.json').unlink(missing_ok=True)


def check_profile(path, first_enrollment=False):
    cfg = validate_selective(json.loads(Path(path).read_text()))
    if first_enrollment and not (DATA/'ssl-site.json').exists():
        # Installing an idle helper grants policy only. start() checks the live
        # selected site against this same policy before opening the helper.
        import trust
        for seed in (trust.approved_receipt(), trust.approved_site_pin()):
            if seed:
                validate_selective(cfg, seed['site'])
    else:
        from routing import verify_gateway
        saved = DATA/'ssl-site.json'
        if saved.exists():
            validate_selective(cfg, json.loads(saved.read_text()).get('site'))
        verify_gateway(cfg)
    return cfg


def save(path, first_enrollment=False):
    cfg = check_profile(path, first_enrollment)
    from routing import put
    # The menu only permits edits with both network session and SSL stopped.
    if (STATE/'last-session.txt').exists():
        session=Path((STATE/'last-session.txt').read_text())
        if (session/'ready.json').exists() and not (session/'cleanup.json').exists():
            raise ValueError('Сначала остановите рабочие маршруты.')
    from sites import approved
    from helper_client import RouteHelper
    async def check():
        client = RouteHelper(RESOURCES)
        try:
            status = await client.open()
            if not helper_is_idle(status) or not approved(cfg, status):
                raise ValueError('Список не применён. Подтвердите правила в помощнике маршрутов.')
        finally:
            await client.close()
    asyncio.run(check())
    if (DATA/'work-sites.json').exists():
        put('previous-work-sites.json', (DATA/'work-sites.json').read_bytes())
    put('work-sites.json',cfg)
    print('Правила сохранены и сверены с помощником. Действуют при следующем подключении.')


if __name__=='__main__':
    os.umask(0o077)
    try:
        if sys.argv[1]=='save':save(sys.argv[2])
        elif sys.argv[1]=='save-enrollment':save(sys.argv[2], first_enrollment=True)
        elif sys.argv[1] in ('check-draft', 'check-enrollment'):
            check_profile(sys.argv[2], first_enrollment=sys.argv[1]=='check-enrollment')
        elif sys.argv[1]=='validate':policy();print('Список поддерживается.')
        elif sys.argv[1]=='start':asyncio.run(start(int(sys.argv[2])))
        else:raise ValueError('Unknown operation')
    except Exception as exc:
        if sys.argv[1]=='start':emit('error',str(exc),code=str(exc) if str(exc).replace('_','').isalnum() else type(exc).__name__,cleanupConfirmed=CLEANUP_CONFIRMED)
        else:print(str(exc))
        sys.exit(1)
