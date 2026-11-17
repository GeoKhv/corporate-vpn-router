"""Native-authorized, bounded root session. No installed daemon or NE.

Only a private copy of the bundled runtime is executed. An independent fork
owns rollback on parent SIGKILL; app/bridge death and an 8-hour ceiling also
end the session. No public DNS, default route, PF or service proxy mutations.
"""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def identity(pid):
    p = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart=', '-o', 'comm='], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ''


def main(source):
    assert os.geteuid() == 0, 'Требуется штатное подтверждение администратора macOS.'
    source = Path(source).resolve()
    os.umask(0o077)
    owned_stage = Path(__file__).resolve().parent.parent
    cfg = json.loads(((owned_stage if '--owned' in sys.argv else source)/'trial-input.json').read_text())
    if '--owned' not in sys.argv:
        # Authorization approves this temporary copy. Refuse symlinks and
        # validate every bundled byte again before executing the root copy.
        stage = Path(tempfile.mkdtemp(prefix='cvr-selective-app-', dir='/private/tmp'))
        stage.chmod(0o711)
        manifest = json.loads((source/'manifest.json').read_text())
        try:
            for relative, expected in manifest.items():
                rel = Path(relative)
                assert not rel.is_absolute() and '..' not in rel.parts
                src, dest = source/rel, stage/rel
                assert src.is_file() and not src.is_symlink()
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dest)
                assert hashlib.sha256(dest.read_bytes()).hexdigest() == expected
                dest.chmod(0o700 if os.access(src, os.X_OK) else 0o600)
            shutil.copyfile(source/'trial-input.json',stage/'trial-input.json')
            os.execv(str(stage/'Runtime/bin/python3.13'), [str(stage/'Runtime/bin/python3.13'), '-I', '-B',
                     str(stage/'Selective/network.py'), str(source), '--owned'])
        except BaseException:
            shutil.rmtree(stage)
            raise
    stage = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(stage/'Selective'))
    from policy import validate_selective
    from pool_config import build
    validate_selective(cfg['policy'], cfg.get('gateway'))
    assert cfg['mode']=='stable-map' and cfg['dns_port']==53541 and cfg['dns_backend_port']==53542 and cfg['socks_port']==11090
    assert source.parent == Path('/private/tmp') and source.name.startswith('cvr-selective-input-')
    assert source.stat().st_uid == cfg['uid'] and source.stat().st_mode & 0o077 == 0
    assert not (source/'stop').exists(), 'Запуск отменён'
    assert cfg['owner_identity'] and identity(cfg['owner_pid']) == cfg['owner_identity']
    assert cfg['app_identity'] and identity(cfg['app_pid']) == cfg['app_identity']
    iface='utun73'
    assert iface not in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split(), 'utun73 уже занят'
    resolver_dir=Path('/etc/resolver')
    assert not resolver_dir.is_symlink()
    contents={}
    for row in cfg['policy']['sites']:
        name=row['domain']; path=resolver_dir/name
        assert not path.exists() and not path.is_symlink(), 'Существующий DNS resolver сохранён: '+name
        contents[path]=(f'# CVR selective session {source.name}\ndomain {name}\nnameserver 127.0.0.1\nport 53541\nsearch_order 1000\ntimeout 1\n').encode()
    # Root copy has no corporate sockets except the loopback authenticated bridge.
    (stage/'config.json').write_text(json.dumps(build(cfg)))
    (stage/'config.json').chmod(0o600)
    log=(stage/'supervisor.jsonl').open('a',buffering=1)
    def record(event,**data):log.write(json.dumps(dict(time=time.time(),event=event,**data))+'\n')
    def run(*args):return subprocess.run(args,capture_output=True,text=True,timeout=8)
    before=run('/sbin/route','-n','get','default').stdout
    made_dir=not resolver_dir.exists()
    lock=stage/'cleanup.lock';lock.touch(mode=0o600)
    parent=os.getpid()
    def owned_helpers():
        # Covers SIGKILL between Popen and PID publication, using the unique
        # root-owned stage path, not a broad process-name match.
        rows=run('/bin/ps','-axo','pid=,args=').stdout.splitlines(); found=[]
        for row in rows:
            parts=row.strip().split(None,1)
            if len(parts)!=2:continue
            pid=int(parts[0]);args=parts[1]
            if args.startswith(str(stage/'sing-box')+' run ') or (
                args.startswith(str(stage/'Runtime/bin/python3.13')+' ') and str(stage/'Selective/sparse_dns.py') in args):
                found.append(pid)
        return found
    def cleanup(reason):
        with lock.open('r+') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX)
            if (stage/'cleaned').exists():return
            record('cleanup_begin',reason=reason)
            # Stop the DNS writer first so routes cannot be added during rollback.
            for sig in (signal.SIGTERM,signal.SIGKILL):
                for pid in owned_helpers():
                    try:os.kill(pid,sig)
                    except ProcessLookupError:pass
                end=time.monotonic()+3
                while owned_helpers() and time.monotonic()<end:time.sleep(.1)
            for path,data in contents.items():
                if path.is_file() and not path.is_symlink() and path.read_bytes()==data:path.unlink()
                elif path.exists():record('resolver_conflict_preserved',path=str(path))
            journal=stage/'host-routes.json'
            for address in json.loads(journal.read_text()) if journal.exists() else []:
                ip=ipaddress.ip_address(address); family='-inet' if ip.version==4 else '-inet6'
                actual=run('/sbin/route','-n','get',family,address).stdout
                if re.search(r'interface:\s*utun73\b',actual):run('/sbin/route','-n','delete',family,'-host',address,'-interface',iface)
            if made_dir:
                try:resolver_dir.rmdir()
                except OSError:pass
            result=dict(reason=reason,default_same=before==run('/sbin/route','-n','get','default').stdout,
                        interface_present=iface in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split(),
                        resolver_present=any(p.exists() for p in contents),helpers_remaining=owned_helpers())
            record('cleanup_done',**result)
            (stage/'cleaned').write_text(json.dumps(result))
            # Readable only inside the user's 0700 session directory.
            dest=source/'cleanup.json'
            with dest.open('x') as f:json.dump(result,f)
            dest.chmod(0o644)
            for name in ('supervisor.jsonl','dns-front.jsonl','adapter.log','dns-process.log','host-routes.json'):
                if (stage/name).exists():
                    target=source/('root-'+name)
                    with target.open('xb') as f:
                        f.write((stage/name).read_bytes());os.fchown(f.fileno(),cfg['uid'],cfg['gid']);os.fchmod(f.fileno(),0o600)
            for name in ('config.json','trial-input.json'):(stage/name).unlink(missing_ok=True)
            # Root-owned executable staging can be removed once helpers are gone.
            if not result['helpers_remaining']:
                for name in ('Runtime','Selective'):shutil.rmtree(stage/name,ignore_errors=True)
                (stage/'sing-box').unlink(missing_ok=True)
    read_fd,write_fd=os.pipe()
    watchdog=os.fork()
    if watchdog==0:
        os.close(write_fd)
        select.select([read_fd],[],[],8*3600+30)
        cleanup('supervisor EOF or 8-hour safety deadline')
        os._exit(0)
    os.close(read_fd)
    stopping=False
    def stop(sig,frame):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        if made_dir:
            resolver_dir.mkdir(mode=0o755)
            resolver_dir.chmod(0o755)  # explicit: root session umask is 077
        adapter_log=(stage/'adapter.log').open('w')
        adapter=subprocess.Popen([str(stage/'sing-box'),'run','-c',str(stage/'config.json')],stdout=adapter_log,stderr=subprocess.STDOUT)
        adapter_log.close()
        end=time.monotonic()+10
        while iface not in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split():
            assert adapter.poll() is None and time.monotonic()<end,'Не удалось создать utun73'
            time.sleep(.1)
        dns_log=(stage/'dns-process.log').open('w')
        dns=subprocess.Popen([str(stage/'Runtime/bin/python3.13'),'-I','-B',str(stage/'Selective/sparse_dns.py'),str(stage)],stdout=dns_log,stderr=subprocess.STDOUT)
        dns_log.close()
        end=time.monotonic()+15
        while not (stage/'dns-ready').exists():
            assert dns.poll() is None and time.monotonic()<end,'Локальный DNS не готов'
            time.sleep(.1)
        assert before==run('/sbin/route','-n','get','default').stdout,'Default route изменился во время старта'
        assert not (source/'stop').exists() and identity(cfg['owner_pid'])==cfg['owner_identity'], 'Запуск отменён'
        for path,data in contents.items():
            with path.open('xb') as f:f.write(data)
            path.chmod(0o644)
        result=dict(stage=str(stage),supervisor=parent,watchdog=watchdog,adapter=adapter.pid,dns=dns.pid,started=time.time())
        with (source/'ready.json').open('x') as f:json.dump(result,f)
        (source/'ready.json').chmod(0o644)
        record('ready',**result)
        end=time.monotonic()+8*3600
        while not stopping and time.monotonic()<end and not (source/'stop').exists():
            # Private acceptance hook: kills only this session's supervisor.
            # Its independently forked watchdog must perform the rollback.
            if (source/'crash-supervisor').exists():os.kill(parent,signal.SIGKILL)
            if adapter.poll() is not None or dns.poll() is not None:break
            if identity(cfg['owner_pid'])!=cfg['owner_identity'] or identity(cfg['app_pid'])!=cfg['app_identity']:break
            if not (source/'heartbeat').exists() or time.time()-(source/'heartbeat').stat().st_mtime>15:break
            time.sleep(.3)
    finally:
        cleanup('app/bridge exit, stop, helper failure or session limit')
        os.close(write_fd);os.waitpid(watchdog,0)


if __name__=='__main__':main(sys.argv[1])
