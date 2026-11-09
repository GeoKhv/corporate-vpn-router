"""Validate private rules and retire only a byte-for-byte owned beta.5 policy."""
import json, os, plistlib, subprocess, sys, tempfile, fcntl, getpass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from sites import validate
from policy_control import synchronize, HTTP_CONTROL, SOCKS_CONTROL
DATA=Path.home()/'Library/Application Support/Corporate VPN Router'
CHROME='com.google.Chrome'
KEYS={'ProxySettings','ProxyMode','ProxyPacUrl','ProxyServer','ProxyBypassList','ProxyPacMandatory','ProxyOverrideRules','ProxyPolicy'}
R='router-profile-receipt.json'
WORK='work-sites.json'
PENDING='pending-sites.json'
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


def extension_conflict():
    # A disabled extension retains its files, Sync settings and private profile.
    root = Path.home()/'Library/Application Support/Google/Chrome'
    for folder in [root/'Default', *root.glob('Profile *')]:
        for name in ('Secure Preferences', 'Preferences'):
            p = folder/name
            if not p.exists():
                continue
            settings = json.loads(p.read_bytes()).get('extensions', {}).get('settings', {})
            for ext in settings.values():
                manifest = ext.get('manifest', {})
                if not manifest and ext.get('location') == 4 and ext.get('path'):
                    source = Path(ext['path'])/'manifest.json'
                    if source.is_file():
                        manifest = json.loads(source.read_bytes())
                if ('proxy' in manifest.get('permissions', []) and not ext.get('disable_reasons')
                        and ext.get('state', 1) == 1):
                    raise Conflict('В Chrome включено расширение с разрешением proxy. Выключите его в списке расширений, сохранив данные.')


def save(cfg):
    cfg = validate(cfg)
    verify_gateway(cfg)
    rec, installed = migration_check()
    if installed and cfg != read(WORK):
        raise Conflict('Сначала включите системный режим. Пока действует проверенная beta.5.')
    os.chdir(DATA)
    with open('policy-save.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        put(WORK, cfg)
        synchronize(SOCKS_CONTROL)
        synchronize(HTTP_CONTROL, required=(DATA/'system-proxy.plist').exists())
    return 'Список сохранён. Новые правила применены.'


def main():
    os.umask(0o077)
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    op=sys.argv[1]
    if op=='save':
        return save(json.loads(Path(sys.argv[2]).read_bytes()))
    if op=='ready':
        os.chdir(DATA)
        synchronize(HTTP_CONTROL, required=True)
        return 'Готово'
    if op=='preflight':
        migration_check()
        cfg = validate(read(WORK))
        verify_gateway(cfg)
        extension_conflict()
        return 'Готово'
    if op=='uninstall-owned':
        retire_profile()
        return 'Готово'
    if op=='rollback-profile':
        rec, installed = migration_check()
        if installed is None:
            rollback = read('beta5-sites.json')
            if not rec or not rollback or not (DATA/FILE).is_file():
                raise Conflict('Локальная копия профиля beta.5 отсутствует.')
            return 'confirm'
        # Only restore a list whose old PAC was verified during migration.
        original = read('beta5-sites.json')
        if original:
            put(WORK, original)
            os.chdir(DATA)
            synchronize(SOCKS_CONTROL)
            synchronize(HTTP_CONTROL)
        return 'ready'
    if op=='retire':
        extension_conflict()
        _, installed = migration_check()
        if installed:
            cfg=validate(read(WORK))
            if read('active-proxy.json') != owned_proxy(installed):
                raise Conflict('Не удалось сверить архивную политику beta.5.')
            put('beta5-sites.json',cfg)
        retire_profile()
        put('routing-mode.json','system')
        return 'Системный прокси'
    if op=='status':
        if migration_check()[1]:
            return 'Установлен профиль beta.5'
        extension_conflict()
        return 'Системный прокси' if read('routing-mode.json') == 'system' else 'Режим выключен'
    raise ValueError()


if __name__=='__main__':
    try:
        print(main())
    except Conflict as e:
        print(str(e)); sys.exit(1)
    except Exception:
        print('Действие не подтверждено. Проверьте состояние профиля, маршрутизатора и формат списка.'); sys.exit(1)
