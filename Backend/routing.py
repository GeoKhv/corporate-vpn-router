"""Manage one user-scoped macOS configuration profile. Never edit Chrome's profile DB."""
import json, os, plistlib, subprocess, sys, tempfile, uuid, getpass
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from sites import proxy, validate, hostname
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

def payload(rec,cfg):
    inner={'PayloadType':'com.apple.ManagedClient.preferences','PayloadVersion':1,'PayloadIdentifier':rec['id']+'.settings',
           'PayloadDisplayName':'Google Chrome · рабочие сайты','PayloadUUID':rec['payload'],
           'PayloadContent':{CHROME:{'Forced':[{'mcx_preference_settings':{'ProxySettings':proxy(cfg)}}]}}}
    return dict(PayloadIdentifier=rec['id'],PayloadUUID=rec['uuid'],PayloadDisplayName='Corporate VPN Router · Chrome',
                PayloadDescription='Обязательные правила прокси только в Google Chrome для текущего пользователя.',
                PayloadOrganization='Corporate VPN Router',PayloadType='Configuration',PayloadScope='User',PayloadVersion=1,PayloadContent=[inner])

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

def confirm():
    rec,owned=checked()
    actual=owned_proxy(owned)
    if actual and actual not in rec['issued']:raise Conflict('Политика изменена извне.')
    candidate=read(PENDING)
    if candidate and proxy(candidate)==actual:
        put(WORK,candidate); (DATA/PENDING).unlink()
    cfg=read(WORK)
    if actual and cfg and proxy(cfg)==actual and (DATA/PENDING).exists():return 'Ожидается замена профиля; пока действует прежний список'
    if actual and cfg and proxy(cfg)==actual:
        if read('active-proxy.json')!=actual:put('active-proxy.json',actual)
        return 'Приложение · профиль установлен'
    if actual:raise Conflict('Политика Chrome отличается от рабочих сайтов. Не начинайте сеанс.')
    if rec:return 'Ожидается установка профиля в настройках macOS'
    return 'Расширение' if read('routing-mode.json')=='extension' else 'Режим не выбран'

def prepare(cfg):
    cfg=validate(cfg)
    # A saved exact gateway exception never includes its siblings. Numeric gateways
    # and the loopback callback cannot match a work domain.
    site=read('ssl-site.json',{}).get('site')
    if not site:
        try:
            from trust import official_info
            site=official_info()[0]
        except Exception as e:
            raise Conflict('Не удалось определить шлюз. Проверьте сохранённый сайт в Check Point.') from e
    if site and any(site==r['domain'] or (r['scope']=='tree' and site.endswith('.'+r['domain'])) for r in cfg['sites']) and site not in cfg['beforeLogin']:
        raise Conflict('Добавьте имя сохранённого шлюза в «До входа».')
    rec,owned=checked()
    if not rec:
        # System proxies remain unchanged, but DIRECT could bypass one in Chrome.
        system=subprocess.check_output(['/usr/sbin/scutil','--proxy'],text=True)
        if any(k+' : 1' in system for k in ('HTTPEnable','HTTPSEnable','ProxyAutoConfigEnable','ProxyAutoDiscoveryEnable','SOCKSEnable')):
            raise Conflict('В macOS включён другой прокси. Используйте расширение или обратитесь в ИТ.')
        rec=dict(id='com.geokhv.corporate-vpn-router.chrome.'+str(uuid.uuid4()),uuid=str(uuid.uuid4()).upper(),payload=str(uuid.uuid4()).upper(),issued=[])
        put('routing-before.json',{'system':system,'priorMode':read('routing-mode.json'),'chromeProfile':'untouched','priorRouterProfile':None})
    elif owned and owned_proxy(owned) not in rec['issued']: raise Conflict('Существующий профиль изменён.')
    new=proxy(cfg)
    if new not in rec['issued']:rec['issued'].append(new)
    put(R,rec);put(PENDING,cfg);put(FILE,plistlib.dumps(payload(rec,cfg)))
    return str(DATA/FILE)

def release():
    rec,owned=checked()
    if owned:
        if owned_proxy(owned) not in rec['issued']:raise Conflict('Существующий профиль изменён.')
        subprocess.run(['/usr/bin/profiles','remove','-type','configuration','-identifier',rec['id'],'-forced'],check=True,timeout=20)
        if checked()[1]:raise Conflict('macOS ещё не удалила профиль Router.')
    for name in (PENDING,FILE,R,'active-proxy.json'):
        (DATA/name).unlink(missing_ok=True)
    put('routing-mode.json','extension')
    return 'Расширение · прежние настройки Chrome сохранены'

def main():
    os.umask(0o077); DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    op=sys.argv[1]
    if op=='prepare':return prepare(json.loads(Path(sys.argv[2]).read_text()))
    if op=='status':return confirm()
    if op=='extension':return release()
    if op=='save':
        cfg=validate(json.loads(Path(sys.argv[2]).read_text()))
        if read(R):raise Conflict('Сначала примените профиль через macOS.')
        put(WORK,cfg);return 'Сохранено'
    raise ValueError()
if __name__=='__main__':
    try:print(main())
    except Conflict as e:print(str(e));sys.exit(1)
    except Exception:print('Не удалось проверить профиль или выполнить действие. Проверьте права macOS и формат списка.');sys.exit(1)
