"""Unprivileged application-owned selective session and native authorization."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from domain_map import DomainMap
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


async def start(app_pid):
    global CLEANUP_CONFIRMED
    # Signed official IPC state is checked before listeners or route mutation.
    # An Idle VPN is normal; only explicit service errors are classified as such.
    from trust import official_info
    from helper_client import RouteHelper
    from sparse_dns import serve as serve_front
    gateway,_,_=official_info()
    cfg,_=policy()
    validate_selective(cfg,gateway)
    helper=RouteHelper(RESOURCES)
    stage=None; tasks=[]; stop=asyncio.Event(); prepared=False; reader=False
    loop=asyncio.get_running_loop()
    try:
        status=await helper.open()
        if status.get('version')!='0.3.0-alpha.3':raise RuntimeError('HELPER_UPDATE_REQUIRED')
        if not set(row['domain'] for row in cfg['sites']).issubset(status['approvedDomains']) or not set(cfg['ports']).issubset(status['approvedPorts']):
            raise RuntimeError('HELPER_POLICY_APPROVAL_REQUIRED')
        registry=initialize_map()
        stage=Path(tempfile.mkdtemp(prefix='cvr-selective-input-',dir='/private/tmp'))
        (STATE/'last-session.txt').write_text(str(stage))
        inp=dict(mode='stable-map',host=cfg['sites'][0]['domain'],ipv4='198.18.73.2',ipv6='fdc7:7652:9a10::2',
                 policy=cfg,gateway=gateway,dns_port=53541,dns_backend_port=53542,socks_port=11090,
                 password=secrets.token_hex(24),map_path=str(STATE/'domain-map.json'),
                 retained_addresses=[registry.address(name,version) for name in registry.names for version in (4,6)])
        (stage/'trial-input.json').write_text(json.dumps(inp))
        def input_ready():
            os.read(sys.stdin.fileno(),4096);stop.set()
        loop.add_reader(sys.stdin.fileno(),input_ready);reader=True
        for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,stop.set)
        service=asyncio.create_task(serve(inp,stage));tasks.append(service)
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
        await helper.call('begin',domains=[r['domain'] for r in cfg['sites']],ports=cfg['ports'],password=inp['password'])
        async def install(addresses):
            await helper.call('route',addresses=[str(a) for a in addresses])
        front=asyncio.create_task(serve_front(cfg,stage,stop.is_set,route_installer=install));tasks.append(front)
        for _ in range(150):
            if front.done():await front;raise RuntimeError('Локальный DNS остановился.')
            if (stage/'dns-ready').exists():break
            await asyncio.sleep(.1)
        else:raise RuntimeError('Локальный DNS не готов.')
        if stop.is_set():return
        await helper.call('publish')
        (stage/'ready.json').write_text(json.dumps(dict(helper='launchd',started=time.time())))
        emit('ready','Рабочие маршруты готовы. Safari, Яндекс и Chrome используют обычные настройки.',session=str(stage))
        while not stop.is_set():
            for task in tasks:
                if task.done():await task;raise RuntimeError('Локальный мост остановился.')
            await helper.call('heartbeat')
            try:await asyncio.wait_for(stop.wait(),2)
            except asyncio.TimeoutError:pass
    except Exception as exc:
        emit('error',str(exc),code=str(exc) if str(exc).replace('_','').isalnum() else type(exc).__name__,cleanupConfirmed=CLEANUP_CONFIRMED)
        raise
    finally:
        stop.set()
        if reader:loop.remove_reader(sys.stdin.fileno())
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if prepared:
            try:
                try:await helper.call('stop')
                except RuntimeError as exc:
                    if str(exc)!='NO_SESSION':raise
                    status=await helper.call('status')
                    if status.get('active') or status.get('cleanupPending'):raise
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
                        if not status.get('active') and not status.get('cleanupPending'):
                            recovered=True;break
                    except Exception:pass
                    await asyncio.sleep(.5)
                if recovered:
                    if stage:(stage/'cleanup.json').write_text(json.dumps(dict(interface_present=False,resolver_present=False,helpers_remaining=[],helper='launchd',recovered=True)))
                    CLEANUP_CONFIRMED=True
                    emit('stopped','После сбоя рабочие маршруты удалены. Можно подключиться снова.',cleanupConfirmed=True)
                else:emit('error','Помощник проверяет завершение маршрутов: '+str(exc),code='CLEANUP_UNCONFIRMED',cleanupConfirmed=False)
        elif stage:
            emit('stopped','Изменений сети нет.',cleanupConfirmed=True)
        await helper.close()  # daemon independently cleans on XPC EOF/lease expiry
        if stage:(stage/'trial-input.json').unlink(missing_ok=True)


def save(path):
    cfg=validate_selective(json.loads(Path(path).read_text()))
    from routing import verify_gateway,put
    verify_gateway(cfg)
    # The menu only permits edits with both network session and SSL stopped.
    if (STATE/'last-session.txt').exists():
        session=Path((STATE/'last-session.txt').read_text())
        if (session/'ready.json').exists() and not (session/'cleanup.json').exists():
            raise ValueError('Сначала остановите рабочие маршруты.')
    put('work-sites.json',cfg)
    print('Список сохранён. Новые домены вне разрешённой области потребуют обновления помощника администратором.')


if __name__=='__main__':
    os.umask(0o077)
    try:
        if sys.argv[1]=='save':save(sys.argv[2])
        elif sys.argv[1]=='validate':policy();print('Список поддерживается.')
        elif sys.argv[1]=='start':asyncio.run(start(int(sys.argv[2])))
        else:raise ValueError('Unknown operation')
    except Exception as exc:
        if sys.argv[1]=='start':emit('error',str(exc),code=str(exc) if str(exc).replace('_','').isalnum() else type(exc).__name__,cleanupConfirmed=CLEANUP_CONFIRMED)
        else:print(str(exc))
        sys.exit(1)
