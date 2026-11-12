"""Read-only Check Point / Router comparison; no elevation or VPN login.

Reports stay local. Raw registry/configuration, authentication logs, credentials
and packet content are never collected. OS error logs are filtered/redacted.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

CP=Path('/Library/Application Support/Checkpoint/Endpoint Connect')
LABEL='com.checkpoint.epc.service'


def run(argv, timeout=12):
    try:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout)
        return dict(code=p.returncode,output=(p.stdout+'\n'+p.stderr).strip()[:80000])
    except (OSError,subprocess.TimeoutExpired) as exc:
        return dict(code=None,output=type(exc).__name__)


def classify(info):
    text=info['output'].lower()
    if any(marker in text for marker in ('service is not started','vpn service is down',
            'connectivity with the check point endpoint security service is lost')):
        return 'service_unavailable_reported_by_official_cli'
    if info['code'] is None:return 'probe_unavailable_or_timeout'
    if info['code']!=0:return 'official_command_failed_service_state_unknown'
    states=re.findall(r'^\s*status:\s*(.+)$',info['output'],re.M)
    if states:return 'service_responding_vpn_'+','.join(s.strip().lower() for s in states)
    return 'service_state_unknown_no_site_status'


def redact(text):
    # Do not retain whole authentication-related lines, even if error-level.
    text='\n'.join(line for line in text.splitlines() if not re.search(
        r'password|passwd|token|cookie|authorization|challenge|saml|assertion|secret|username|user_name|login_name|fingerprint',line,re.I))
    text=re.sub(r'https?://\S+','<url>',text)
    text=re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','<ip>',text)
    text=re.sub(r'(?<!\w)(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}(?!\w)','<domain-or-id>',text)
    text=re.sub(r'/Users/[^/\s]+','/Users/<user>',text)
    return text


def snapshot():
    launch=run(['/bin/launchctl','print','system/'+LABEL])
    disabled=run(['/bin/launchctl','print-disabled','system'])
    disabled['output']='\n'.join(line for line in disabled['output'].splitlines() if 'checkpoint' in line.lower())
    # Same vendor signature/ownership verification as the normal trust path.
    try:
        from trust import owned
        owned(CP/'trac')
        signed=run(['/usr/bin/codesign','--verify','--strict','-R=anchor apple generic and certificate leaf[subject.OU] = "TZ3UEPFYKD" and identifier "trac"',str(CP/'trac')])
        info=run([str(CP/'trac'),'info']) if signed['code']==0 else dict(code=None,output='signature verification failed')
    except Exception as exc:
        signed=dict(code=None,output=type(exc).__name__);info=signed
    proc=run(['/bin/ps','-axo','uid=,pid=,ppid=,comm='])
    proc['output']='\n'.join(line for line in proc['output'].splitlines() if any(s in line.lower() for s in ('tracsrvwrapper','endpoint_security','endpoint security','corporatevpnrouter','sing-box','routehelper','sota connect','adguard vpn')))
    routes={family:run(['/usr/sbin/netstat','-rn','-f',family]) for family in ('inet','inet6')}
    for value in routes.values():value['output']='\n'.join(line for line in value['output'].splitlines() if re.search(r'^default\s|utun73|198\.18\.7[35]|fdc7:7652:9a10',line))
    resolvers={}
    root=Path('/etc/resolver')
    if root.exists():
        for p in root.iterdir():
            if p.is_file() and not p.is_symlink():
                try:
                    data=p.read_bytes()
                    if data.startswith(b'# CVR '):resolvers[hashlib.sha256(p.name.encode()).hexdigest()[:12]]=dict(sha256=hashlib.sha256(data).hexdigest(),owner=p.stat().st_uid)
                except OSError:pass
    logs=run(['/usr/bin/log','show','--last','20m','--style','compact','--predicate',
        '(process == "TracSrvWrapper" OR process == "Endpoint Security") AND (messageType == error OR messageType == fault)'],timeout=20)
    logs['output']=redact('\n'.join(logs['output'].splitlines()[-120:]))
    packages=run(['/usr/sbin/pkgutil','--pkgs'])
    versions={}
    for name in packages['output'].splitlines():
        if re.search(r'checkpoint|endpoint.*connect',name,re.I):
            versions[name]=run(['/usr/sbin/pkgutil','--pkg-info',name])
    for app in (Path('/Applications/Endpoint Security VPN.app'),Path('/Applications/Endpoint Security.app')):
        try:
            meta=plistlib.loads((app/'Contents/Info.plist').read_bytes())
            versions[app.name]={k:meta.get(k) for k in ('CFBundleShortVersionString','CFBundleVersion')}
        except OSError:pass
    status=classify(info)
    info['output']=redact(info['output'])
    for value in (launch,proc,*routes.values()):value['output']=redact(value['output'])
    return dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        macOS=run(['/usr/bin/sw_vers']),boot=run(['/usr/sbin/sysctl','-n','kern.boottime']),
        architecture=run(['/usr/bin/uname','-m']),versions=versions,classification=status,
        launchd=launch,disabled=disabled,signature=signed,official_info=info,processes=proc,
        routes=routes,owned_resolvers=resolvers,error_logs=logs)


def main():
    os.umask(0o077)
    folder=Path(tempfile.mkdtemp(prefix='CVR-CheckPoint-',dir=str(Path.home()/'Desktop')))
    print('Проверка только читает состояние. Пароль администратора и подключение VPN не нужны.')
    print('Завершите Router через его меню. В Check Point оставьте VPN отключённым.')
    if '--snapshot' not in sys.argv:input('Нажмите Enter для исходного снимка: ')
    before=snapshot();(folder/'01-before.json').write_text(json.dumps(before,ensure_ascii=False,indent=2))
    print('Исходное состояние:',before['classification'])
    if '--snapshot' in sys.argv or not before['classification'].startswith('service_responding_vpn_'):
        print('Состояние службы не подтверждено. Маршруты Router не включайте для этой проверки.')
        print('Если это первый сбой после долгого перерыва: сохраните отчёт, перезагрузите Mac штатно и повторите ту же проверку до запуска Router.')
    else:
        print('Служба отвечает. Теперь запустите Router и включите только рабочие маршруты, без авторизации VPN.')
        answer=input('Enter — снимок с маршрутами; q — закончить: ')
        if answer.strip().lower()!='q':
            after=snapshot();(folder/'02-routes-on.json').write_text(json.dumps(after,ensure_ascii=False,indent=2))
            input('Завершите Router через его меню, подождите 25 секунд и нажмите Enter: ')
            final=snapshot();(folder/'03-routes-off.json').write_text(json.dumps(final,ensure_ascii=False,indent=2))
            comparison=dict(before=before['classification'],during=after['classification'],after=final['classification'],
                before_had_routes=bool(before['owned_resolvers']),during_had_routes=bool(after['owned_resolvers']),after_had_routes=bool(final['owned_resolvers']))
            (folder/'comparison.json').write_text(json.dumps(comparison,ensure_ascii=False,indent=2));print(comparison)
    print('Локальный отчёт:',folder)
    print('Просмотрите файлы перед передачей. Автоматической отправки нет; отсутствие журнала может означать ограничения чтения.')

if __name__=='__main__':main()
