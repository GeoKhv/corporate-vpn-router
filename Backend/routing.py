"""Validate private rules and retire only a byte-for-byte owned beta.5 policy."""
import socket, re, hashlib, json, os, plistlib, subprocess, sys, tempfile, fcntl, getpass, uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from sites import validate
from policy_control import synchronize, HTTP_CONTROL, SOCKS_CONTROL
DATA=Path.home()/'Library/Application Support/Corporate VPN Router'
CHROME='com.google.Chrome'
KEYS={'ProxySettings','ProxyMode','ProxyPacUrl','ProxyServer','ProxyBypassList','ProxyPacMandatory','ProxyOverrideRules','ProxyPolicy'}
R='router-profile-receipt.json'
WORK='work-sites.json'
FIXED={'ProxyMode':'fixed_servers','ProxyServer':'http://127.0.0.1:1091'}
PROFILE='Chrome Local Router.mobileconfig'
BACKUP='beta5-routing-backup.json'
FILE='Chrome Work Sites.mobileconfig'
class Conflict(Exception): pass

def put(name, data):
    if not isinstance(data,bytes): data=json.dumps(data,ensure_ascii=False).encode()
    with tempfile.NamedTemporaryFile(dir=DATA,delete=False) as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(f.name,DATA/name)

def read(name, default=None):
    p=DATA/name
    return json.loads(p.read_text()) if p.exists() else default

def profiles():
    data=subprocess.check_output(['/usr/bin/profiles','show','-type','configuration','-output','stdout-xml'],timeout=12)
    root=plistlib.loads(data)
    return [p for group in root.values() if isinstance(group,list) for p in group if isinstance(p,dict)]

def checked():
    rec=read(R,{})
    listing=profiles()
    owned=None
    for p in listing:
        if rec and p.get('ProfileIdentifier')==rec['id']:
            if p.get('ProfileUUID','').upper()!=rec['uuid']: raise Conflict('Идентификатор занят чужим профилем.')
            if owned or p.get('ProfileIsManaged') or p.get('ProfileRemovalDisallowed'):
                raise Conflict('Управляемый или неоднозначный профиль: обратитесь в ИТ.')
            owned=p
        elif any(k in str(p.get('ProfileItems')) for k in KEYS) and CHROME in str(p.get('ProfileItems')):
            raise Conflict('Прокси Chrome задан другим профилем. Обратитесь в ИТ.')
    # Reject standalone local/managed Chrome proxy settings, even when no profile lists them.
    for path in preference_dirs():
        f=path/(CHROME+'.plist')
        if f.exists():
            settings=plistlib.loads(f.read_bytes())
            keys=set(settings)&KEYS
            if keys and not (owned and keys=={'ProxySettings'} and settings['ProxySettings'] in rec['issued'] and 'Managed Preferences' in str(path)):
                raise Conflict('Существующая настройка прокси Chrome не принадлежит Router.')
    return rec,owned

def preference_dirs():
    return (Path.home()/'Library/Preferences',Path('/Library/Preferences'),Path('/Library/Managed Preferences'),Path('/Library/Managed Preferences')/getpass.getuser())

def owned_proxy(owned):
    if owned is None:return None
    items=owned.get('ProfileItems',[])
    rec=read(R,{})
    if len(items)==1 and items[0].get('PayloadType')=='com.apple.ManagedClient.preferences' and items[0].get('PayloadIdentifier')==rec.get('id','')+'.settings' and items[0].get('PayloadUUID','').upper()==rec.get('payload'):
        c=items[0].get('PayloadContent',{})
        if set(c)=={'PayloadContentManagedPreferences'}: c=c['PayloadContentManagedPreferences']
        try:
            value=c[CHROME]['Forced'][0]['mcx_preference_settings']['ProxySettings']
            if c=={CHROME:{'Forced':[{'mcx_preference_settings':{'ProxySettings':value}}]}}:return value
        except (KeyError,TypeError,IndexError):pass
    raise Conflict('Содержимое установленного профиля изменилось; автоматическая замена запрещена.')

def migration_check():
    rec, installed = checked()
    if installed and owned_proxy(installed) not in rec.get('issued', []):
        raise Conflict('Содержимое профиля beta.5 отличается от сохранённого.')
    return rec, installed


def verify_gateway(cfg):
    site = read('ssl-site.json', {}).get('site')
    if not site:
        from trust import official_info
        site = official_info()[0]
    if any(site == r['domain'] or (r['scope'] == 'tree' and site.endswith('.'+r['domain']))
           for r in cfg['sites']) and site not in cfg['beforeLogin']:
        raise Conflict('Добавьте точное имя шлюза в список доступа до входа.')


def retire_profile():
    rec, installed = migration_check()
    if installed:
        subprocess.run(['/usr/bin/profiles','remove','-type','configuration','-identifier',rec['id'],'-forced'],
                       check=True, timeout=30)
        if migration_check()[1]:
            raise Conflict('macOS ещё не сняла профиль beta.5.')
    # Keep the original receipt and mobileconfig for an explicit beta.5 rollback.


def payload(rec, proxy):
    settings = {'Forced':[{'mcx_preference_settings':{'ProxySettings':proxy}}]}
    item = dict(PayloadType='com.apple.ManagedClient.preferences', PayloadVersion=1,
                PayloadIdentifier=rec['id']+'.settings', PayloadUUID=rec['payload'],
                PayloadContent={CHROME:settings})
    return dict(PayloadType='Configuration', PayloadScope='User', PayloadVersion=1,
                PayloadIdentifier=rec['id'], PayloadUUID=rec['uuid'],
                PayloadDisplayName='Corporate VPN Router · beta.6 · Локальный прокси Chrome',
                PayloadDescription='Google Chrome использует локальный прокси Corporate VPN Router.',
                PayloadContent=[item])


def prepare():
    cfg = validate(read(WORK))
    verify_gateway(cfg)
    rec, installed = migration_check()
    current = owned_proxy(installed)
    if current == FIXED:
        return 'active'
    if installed:
        if current.get('ProxyMode') != 'pac_script' or current != read('active-proxy.json'):
            raise Conflict('Не удалось подтвердить исходную политику beta.5.')
        old = plistlib.loads((DATA/FILE).read_bytes())
        if old.get('PayloadIdentifier') != rec['id'] or old.get('PayloadUUID') != rec['uuid']:
            raise Conflict('Не совпадает копия профиля для отката.')
        expected = payload(rec,current)['PayloadContent'][0]
        items = old.get('PayloadContent',[])
        if len(items)!=1 or any(items[0].get(k)!=v for k,v in expected.items()):
            raise Conflict('Локальный профиль для отката отличается от установленного.')
        if (DATA/'pending-sites.json').exists():
            raise Conflict('Осталось неподтверждённое изменение beta.5.')
        put(BACKUP, dict(profileSHA=hashlib.sha256((DATA/FILE).read_bytes()).hexdigest(), policy=current, sites=cfg, receipt={**rec,'issued':[v for v in rec['issued'] if v!=FIXED]}))
    elif not rec:
        rec = dict(id='com.geokhv.corporate-vpn-router.chrome.'+str(uuid.uuid4()),
                   uuid=str(uuid.uuid4()).upper(),payload=str(uuid.uuid4()).upper(),issued=[])
    if FIXED not in rec['issued']:
        rec['issued'].append(FIXED)
        put(R,rec)
    put(PROFILE, plistlib.dumps(payload(rec,FIXED)))
    return str(DATA/PROFILE)


def rollback():
    rec, installed = migration_check()
    backup = read(BACKUP)
    if not backup or backup['receipt']['id']!=rec.get('id'):
        raise Conflict('Копия исходного профиля beta.5 отсутствует.')
    actual = owned_proxy(installed)
    if hashlib.sha256((DATA/FILE).read_bytes()).hexdigest()!=backup.get('profileSHA'):
        raise Conflict('Исходный файл профиля beta.5 изменился.')
    if actual is None or actual == FIXED:
        return 'confirm'
    if actual != backup['policy']:
        raise Conflict('Исходная политика beta.5 ещё не восстановлена.')
    put(WORK, validate(backup['sites']))
    os.chdir(DATA)
    synchronize(SOCKS_CONTROL)
    synchronize(HTTP_CONTROL)
    put(R,backup['receipt'])
    put('active-proxy.json',actual)
    return 'ready'


def save(cfg):
    cfg = validate(cfg)
    verify_gateway(cfg)
    rec, installed = migration_check()
    active = owned_proxy(installed)
    if installed and active != FIXED and cfg != read(WORK):
        raise Conflict('Сначала подтвердите постоянный прокси Chrome. Пока действует проверенная beta.5.')
    os.chdir(DATA)
    with open('policy-save.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        put(WORK, cfg)
        synchronize(SOCKS_CONTROL)
        synchronize(HTTP_CONTROL, required=active == FIXED)
    return 'Список сохранён. Новые правила применены.'


def main():
    os.umask(0o077)
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    op=sys.argv[1]
    if op=='save':
        return save(json.loads(Path(sys.argv[2]).read_bytes()))
    if op in ('challenge','observed'):
        os.chdir(DATA)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect(HTTP_CONTROL)
            sock.sendall(b'N' if op=='challenge' else b'V')
            with sock.makefile('rb') as incoming:
                answer=incoming.read(64).decode()
        if op=='observed' and answer=='1':
            return 'observed'
        if op=='challenge' and re.fullmatch(r'[0-9a-f]{40}',answer):
            return 'http://router-check.invalid/'+answer
        raise Conflict('Запрос основного Chrome пока не наблюдался.')
    if op=='ready':
        os.chdir(DATA)
        synchronize(HTTP_CONTROL, required=True)
        return 'Готово'
    if op=='prepare':
        return prepare()
    if op=='rollback-profile':
        return rollback()
    if op=='uninstall-owned':
        retire_profile()
        return 'Готово'
    if op=='status':
        _, installed = migration_check()
        proxy = owned_proxy(installed)
        if proxy == FIXED:
            return 'Chrome · локальный прокси'
        return 'Профиль beta.5' if installed else 'Профиль Chrome не установлен'
    raise ValueError()


if __name__=='__main__':
    try:
        print(main())
    except Conflict as e:
        print(str(e)); sys.exit(1)
    except Exception:
        print('Действие не подтверждено. Проверьте состояние профиля, маршрутизатора и формат списка.'); sys.exit(1)
