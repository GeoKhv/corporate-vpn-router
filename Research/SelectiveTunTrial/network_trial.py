"""Root-only bounded laboratory supervisor with an independent crash watchdog.

Run only through native macOS administrator authorization. Never install as a
service. Owns one resolver file, two synthetic host routes and one utun. It
refuses an existing resolver/interface. No default route, PF, network service,
browser preference, VPN provider, certificate or production app is changed.
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

SOURCE = Path(sys.argv[1]).resolve()
IFACE = 'utun73'
assert os.geteuid() == 0, 'Native administrator authorization required'
CFG = json.loads((SOURCE / 'trial-input.json').read_text())
POOL = CFG.get('mode') in ('domain-pool','stable-map')
HOST = CFG['host']
assert re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', HOST) and len(HOST) < 254
assert CFG['ipv4'] == '198.18.73.2' and CFG['ipv6'] == 'fdc7:7652:9a10::2'
assert CFG['dns_port'] == 53541 and CFG['socks_port'] == 11090
assert IFACE not in subprocess.check_output(['/sbin/ifconfig', '-l'], text=True).split()
RESOLVER_DIR = Path('/etc/resolver')
domains = [HOST]
if POOL:
    domains = [r['domain'] for r in CFG['policy']['sites']] + ['work.cvr-probe.invalid']
    for row in CFG['policy']['sites']:
        assert row['scope'] in ('exact','tree')
    assert all(isinstance(p,int) and 1 <= p <= 65535 for p in CFG['policy']['ports'])
RESOLVERS = {}
for domain in domains:
    assert re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',domain) and len(domain)<254
    target=RESOLVER_DIR/domain
    assert not target.exists() and not target.is_symlink(), 'Existing resolver must not be replaced'
    RESOLVERS[target] = ('# CVR bounded selective TUN trial\n' + f'domain {domain}\nnameserver 127.0.0.1\n'
                        'port 53541\nsearch_order 1000\ntimeout 1\n').encode()
STAGE = Path(tempfile.mkdtemp(prefix='cvr-selective-', dir='/private/tmp'))
STAGE.chmod(0o711)
LOG = (STAGE / 'supervisor.jsonl').open('a', buffering=1)
os.chmod(STAGE / 'supervisor.jsonl', 0o644)
def log(event, **extra): LOG.write(json.dumps(dict(time=time.time(), event=event, **extra))+'\n')
def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    log('command', args=args, code=p.returncode, stdout=p.stdout, stderr=p.stderr)
    return p

binary_source = SOURCE / 'upstream/sing-box-1.14.4-darwin-arm64/sing-box'
expected = json.loads((SOURCE / 'binary-sha256.json').read_text())['sha256']
shutil.copyfile(binary_source, STAGE / 'sing-box')
assert hashlib.sha256((STAGE / 'sing-box').read_bytes()).hexdigest() == expected
os.chmod(STAGE / 'sing-box', 0o755)
shutil.copyfile(SOURCE / 'sing-box.json', STAGE / 'config.json')
os.chmod(STAGE / 'config.json', 0o600)
config = json.loads((STAGE / 'config.json').read_text())
if POOL:
    from pool_config import build
    assert config == build(CFG)
    shutil.copyfile(SOURCE/'sparse_dns.py',STAGE/'sparse_dns.py')
    (STAGE/'trial-input.json').write_text(json.dumps(CFG));os.chmod(STAGE/'trial-input.json',0o600)
else:
    assert config['inbounds'] == [{'type': 'tun', 'tag': 'one-name', 'interface_name': IFACE,
        'address': ['198.18.73.1/32','fdc7:7652:9a10::1/128'], 'mtu': 1500,
        'auto_route': False, 'dns_mode': 'disabled', 'stack': 'gvisor'}]
    assert len(config['outbounds']) == 1 and config['outbounds'][0]['type'] == 'socks'
    assert config['outbounds'][0]['server'] == '127.0.0.1' and config['outbounds'][0]['server_port'] == 11090
    assert config['route']['rules'] == [
        {'inbound':['one-name'], 'ip_cidr':[CFG['ipv4']+'/32',CFG['ipv6']+'/128'],
         'network':'tcp','port':[443],'action':'route','override_address':HOST,'outbound':'verified-work'},
        {'action':'reject','no_drop':True}]
made_dir = not RESOLVER_DIR.exists()
if made_dir: RESOLVER_DIR.mkdir(mode=0o755)
before_default = run('/sbin/route','-n','get','default').stdout
adapter_log = (STAGE/'adapter.log').open('w')
adapter = subprocess.Popen([str(STAGE/'sing-box'),'run','-c',str(STAGE/'config.json')],
                           stdout=adapter_log,stderr=subprocess.STDOUT,close_fds=True)
adapter_log.close()
log('adapter_started',pid=adapter.pid)
capture = None
if CFG.get('capture_dns'):
    dns_log = (STAGE/'dns-packets.txt').open('w')
    capture = subprocess.Popen(['/usr/sbin/tcpdump','-i','any','-n','-l','-vv','-s','512',
                                'port 53 or port 53541'],stdout=dns_log,stderr=subprocess.STDOUT)
    dns_log.close()
lock = STAGE/'cleanup.lock'
lock.touch(mode=0o600)
def cleanup(reason):
    with lock.open('r+') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        if (STAGE/'cleaned').exists(): return
        log('cleanup_begin',reason=reason)
        for resolver,contents in RESOLVERS.items():
            if resolver.is_file() and not resolver.is_symlink() and resolver.read_bytes()==contents:
                resolver.unlink(); log('resolver_removed',path=str(resolver))
            elif resolver.exists(): log('resolver_conflict_preserved',path=str(resolver))
        # Delete only routes currently naming our interface.
        addresses=[CFG['ipv4'],CFG['ipv6']]
        if POOL:
            addresses=json.loads((STAGE/'host-routes.json').read_text()) if (STAGE/'host-routes.json').exists() else []
        for addr in addresses:
            ip=ipaddress.ip_address(addr);family='inet' if ip.version==4 else 'inet6'
            route=run('/sbin/route','-n','get','-'+family,addr)
            if re.search(r'interface:\s*'+IFACE+r'\b',route.stdout):
                run('/sbin/route','-n','delete','-'+family,'-host',addr,'-interface',IFACE)
        children=[(adapter.pid,str(STAGE/'sing-box'),'comm=')]
        if (STAGE/'dns.pid').exists():
            dns_pid=int((STAGE/'dns.pid').read_text())
            children.append((dns_pid,str(STAGE/'sparse_dns.py'),'args='))
        if capture is not None:
            children.append((capture.pid,'/usr/sbin/tcpdump','comm='))
        def owned(pid,expected,field):
            identity=subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','stat=','-o',field],capture_output=True,text=True)
            fields=identity.stdout.strip().split(None,1)
            return len(fields)==2 and not fields[0].startswith('Z') and (fields[1]==expected if field=='comm=' else expected in fields[1].split())
        # Wait for every helper, not just interface disappearance. A DNS helper
        # can otherwise retain its port after the TUN has already vanished.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            for pid,expected,field in children:
                if owned(pid,expected,field):
                    try:os.kill(pid,sig);log('helper_signal',pid=pid,signal=int(sig))
                    except ProcessLookupError:pass
            end=time.monotonic()+3
            while any(owned(*child) for child in children) and time.monotonic()<end:time.sleep(.1)
        remaining=[pid for pid,expected,field in children if owned(pid,expected,field)]
        log('helpers_checked',remaining=remaining)
        if made_dir:
            try:RESOLVER_DIR.rmdir()
            except OSError:pass
        after=run('/sbin/route','-n','get','default').stdout
        log('cleanup_done',default_same=before_default==after,
            interface_present=IFACE in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split(),
            resolver_present=any(p.exists() for p in RESOLVERS),helpers_remaining=remaining)
        (STAGE/'cleaned').write_text(reason)

# EOF arrives on supervisor death, including SIGKILL. The watchdog has its own
# process and a hard deadline; it is not an exit handler in the test process.
rfd,wfd=os.pipe()
watchdog=os.fork()
if watchdog==0:
    os.close(wfd)
    select.select([rfd],[],[],900)
    cleanup('supervisor EOF or 15-minute deadline')
    os._exit(0)
os.close(rfd)
stopping=False
def stop(signum,frame):
    global stopping
    stopping=True
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)
try:
    deadline=time.monotonic()+8
    while IFACE not in subprocess.check_output(['/sbin/ifconfig','-l'],text=True).split():
        if time.monotonic()>deadline or adapter.poll() is not None:raise RuntimeError('adapter did not create utun')
        time.sleep(.1)
    dns_process=None
    if POOL:
        dns_log=(STAGE/'dns-process.log').open('w')
        # Keep the same runtime as the supervisor. A later private application
        # must use its bundled Python, without requiring Command Line Tools.
        dns_process=subprocess.Popen([sys.executable,'-B',str(STAGE/'sparse_dns.py'),str(STAGE)],stdout=dns_log,stderr=subprocess.STDOUT)
        dns_log.close();(STAGE/'dns.pid').write_text(str(dns_process.pid))
        end=time.monotonic()+5
        while not (STAGE/'dns-ready').exists():
            assert time.monotonic()<end and dns_process.poll() is None,'DNS frontend failed'
            time.sleep(.1)
    else:
        for family,addr in [('inet',CFG['ipv4']),('inet6',CFG['ipv6'])]:
            run('/sbin/route','-n','add','-'+family,'-host',addr,'-interface',IFACE)
            actual=run('/sbin/route','-n','get','-'+family,addr)
            assert re.search(r'interface:\s*'+IFACE+r'\b',actual.stdout), 'host route not installed'
    assert run('/sbin/route','-n','get','default').stdout==before_default,'default route changed'
    for resolver,contents in RESOLVERS.items():
        with resolver.open('xb') as f:f.write(contents)
        resolver.chmod(0o644)
    info=dict(stage=str(STAGE),supervisor=os.getpid(),watchdog=watchdog,adapter=adapter.pid)
    # Existing directory is private to the current user; only write a new file.
    with (SOURCE/'active-run.json').open('x') as f:json.dump(info,f)
    os.chmod(SOURCE/'active-run.json',0o644)
    log('ready',**info)
    end=time.monotonic()+840
    while not stopping and time.monotonic()<end and not (SOURCE/'stop').exists():
        if (SOURCE/'crash-supervisor').exists():os.kill(os.getpid(),signal.SIGKILL)
        if (SOURCE/'crash-adapter').exists():os.kill(adapter.pid,signal.SIGKILL);break
        if adapter.poll() is not None:break
        if dns_process is not None and dns_process.poll() is not None:break
        if not (SOURCE/'services.pid').exists():break
        try:os.kill(int((SOURCE/'services.pid').read_text()),0)
        except (ProcessLookupError,ValueError):break
        time.sleep(.2)
finally:
    cleanup('normal exit, stop, missing services or adapter death')
    os.close(wfd)
    os.waitpid(watchdog,0)
    try:adapter.wait(timeout=5)
    except subprocess.TimeoutExpired:pass
    print(STAGE,flush=True)
