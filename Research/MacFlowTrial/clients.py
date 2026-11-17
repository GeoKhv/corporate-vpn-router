"""HTTPS acceptance experiment; no installed service, preference, or profile is edited.
Run with an absolute path to a compiled WebKitProbe. See the research report.
"""
import asyncio
import ipaddress
import json
import os
import signal
import time
import urllib.request
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'Backend'))
import http_router as h

data = Path.home() / 'Library/Application Support/Corporate VPN Router'
public = 'example.com'

def yandex(port, needle, debugger):
    with tempfile.TemporaryDirectory(prefix='cvr-ya-', dir='/private/tmp') as profile:
        args = ['/Applications/Yandex.app/Contents/MacOS/Yandex','--user-data-dir='+profile,
                '--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--headless',
                '--no-first-run','--disable-background-networking','--disable-extensions','--disable-quic',
                '--proxy-server=http://127.0.0.1:'+port,'about:blank']
        browser = subprocess.Popen(args, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            portfile = Path(profile)/'DevToolsActivePort'
            for _ in range(80):
                if portfile.is_file(): break
                time.sleep(.1)
            portnum = int(portfile.read_text().splitlines()[0])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open('http://127.0.0.1:'+str(portnum)+'/json/list',timeout=3) as resp:
                tabs = json.load(resp)
            tab = next(t for t in tabs if t.get('type') == 'page' and t.get('url') == 'about:blank')
            return subprocess.run([debugger,tab['webSocketDebuggerUrl'],needle],
                                  input=input()+'\n',text=True,timeout=18).returncode
        finally:
            try: os.killpg(browser.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            browser.wait(timeout=4)

async def run(exe, engines):
    # One private listener, two allowed destinations, Work only via existing verified worker.
    # No production HTTP control socket, no policy updates, no browser challenge or logs.
    policy = data / 'work-sites.json'
    work = json.loads((data / 'certificate-endpoints.json').read_bytes())['hosts'][1]
    h.SOCKS_CONTROL = str(data / 'socks-worker.sock')
    original = h.via_socks
    counts = {'work': 0, 'life': 0}
    failed = False
    class TinyRouter(h.Router):
        async def direct(self, host, port):
            if (host != public and not ('egress' in engines and host == 'www.cloudflare.com')) or port != 443:
                raise OSError('outside lab')
            counts['life'] += 1
            return await super().direct(host, port)
    router = TinyRouter(policy)
    router.refresh()
    assert h.is_work(router.config, work) and not h.is_work(router.config, public)
    async def socks(host, port):
        if host != work or port != 443:
            raise OSError('outside lab')
        counts['work'] += 1
        if failed:
            raise OSError('isolated Work failure')
        return await original(host, port)
    h.via_socks = socks
    server = await asyncio.start_server(router.handle, '127.0.0.1', 0)
    port = str(server.sockets[0].getsockname()[1])
    all_pass = True
    async with server:
        for engine in engines:
            if engine == 'egress':
                async def sample(proxy):
                    proc = await asyncio.create_subprocess_exec('/usr/bin/curl','-q','-fsS','--max-time','12',
                        '--noproxy','','--proxy',proxy,'https://www.cloudflare.com/cdn-cgi/trace?t='+uuid.uuid4().hex,
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                    buf,_ = await proc.communicate()
                    if proc.returncode: return None
                    for line in buf.splitlines():
                        if line.startswith(b'ip='): return ipaddress.ip_address(line[3:].decode('ascii'))
                    return None
                baseline = await sample('')
                for phase in ('up','down','restored'):
                    failed = phase == 'down'
                    before = counts['life']
                    ip = await sample('http://127.0.0.1:'+port)
                    passed = baseline is not None and baseline == ip and counts['life'] > before
                    print(json.dumps(dict(engine=engine, phase=phase, sameObservedIP=bool(ip and ip==baseline),
                                          witnessed=counts['life'] > before, passed=passed)),flush=True)
                    all_pass &= passed
                continue
            for phase, side in [('up','life'),('up','work'),('down','work'),('down','life'),('restored','work')]:
                failed = phase == 'down'
                needle = 'user-agent:' if side == 'work' else 'example domain'
                url = ('https://' + work + '/robots.txt' if side == 'work' else 'https://' + public + '/') + '?trial=' + uuid.uuid4().hex
                cmd = [exe,port,needle] if engine == 'webkit' else [sys.executable,'-B',__file__,'--yandex',port,needle,str(Path(exe).with_name('debug-tab'))]
                before = counts[side]
                if engine == 'curl':
                    cmd = ['/usr/bin/curl','-q','-sSf','--noproxy','','-x','http://127.0.0.1:'+port,'--max-time','16','-K','-']
                proc = await asyncio.create_subprocess_exec(*cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = b'', b''
                try:
                    content = ('url = "' + url + '"' if engine == 'curl' else url) + '\n'
                    out, err = await asyncio.wait_for(proc.communicate(content.encode()),35)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                code = proc.returncode
                if engine == 'curl' and code == 0 and needle.encode() not in out.lower():
                    code = 4
                detail = ''
                if engine != 'curl' and code != 0:
                    # Print structured categories only; never page text, errors with URLs or hostnames.
                    if b'Traceback' in err: detail = 'client exception: '+err.splitlines()[-1].split(b':')[0].decode(errors='replace')
                    elif engine == 'webkit': detail = out.decode(errors='replace').strip()[:70]
                    else: detail = 'browser navigation failed'

                wanted = int(failed and side == 'work')
                passed = (code in (22,56) and b'502' in err if engine == 'curl' and wanted else code == wanted and not detail.startswith('client exception')) and counts[side] > before
                print(json.dumps(dict(engine=engine,phase=phase,side=side,clientCode=code,detail=detail,
                                      witnessed=counts[side]>before,passed=passed)),flush=True)
                all_pass &= passed
                # Do not send internal names to a client whose public proxy path failed.
                if side == 'life' and phase == 'up' and not passed:
                    break
    return 0 if all_pass else 1

if __name__ == '__main__':
    if sys.argv[1] == '--yandex':
        sys.exit(yandex(*sys.argv[2:]))
    engines = sys.argv[2:] or ['curl', 'webkit', 'yandex']
    assert set(engines) <= {'curl', 'webkit', 'yandex', 'egress'}
    sys.exit(asyncio.run(run(str(Path(sys.argv[1]).resolve()), engines)))
