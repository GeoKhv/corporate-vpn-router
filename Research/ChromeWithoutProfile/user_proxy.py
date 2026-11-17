"""Offline proxy edit prototype restricted to explicitly marked disposable profiles.
This is not a supported Chrome API and cannot be used on the user's profile.
"""
import hashlib,json,os,tempfile
from pathlib import Path
MARKER='CVR disposable Chrome laboratory v1\n'
PROXY={'mode':'fixed_servers','server':'http://127.0.0.1:1091','bypass_list':''}
def create_profile(path):
    path=Path(path);path.mkdir()
    (path/'.cvr-laboratory').write_text(MARKER)
    (path/'Default').mkdir()
    (path/'Default/Preferences').write_text('{}')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def load(profile):
    profile=Path(profile)
    if profile.is_symlink() or (profile/'.cvr-laboratory').read_text()!=MARKER:raise ValueError('Not a disposable laboratory profile')
    lock=profile/'SingletonLock'
    if lock.exists() or lock.is_symlink():raise ValueError('Chrome must be fully closed')
    path=profile/'Default/Preferences'
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('Symlink refused')
    raw=path.read_bytes();value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('Invalid Preferences')
    return path,raw,value
def replace(path,old,new):
    if path.read_bytes()!=old:raise ValueError('Preferences changed concurrently')
    fd,name=tempfile.mkstemp(prefix='.cvr-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(new);out.flush();os.fsync(out.fileno())
        if path.read_bytes()!=old:raise ValueError('Preferences changed concurrently')
        os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)
def apply(profile,proxy):
    path,raw,value=load(profile)
    receipt=dict(original=raw.decode(),originalHash=digest(raw),hadProxy='proxy' in value,previous=value.get('proxy'),installed=proxy.copy())
    value['proxy']=proxy.copy();new=json.dumps(value,separators=(',',':')).encode()
    replace(path,raw,new);receipt['patchedHash']=digest(new)
    return receipt
def restore(profile,receipt):
    path,raw,value=load(profile)
    if digest(receipt['original'].encode())!=receipt['originalHash']:raise ValueError('Invalid receipt')
    if value.get('proxy')!=receipt['installed']:raise ValueError('Proxy changed outside experiment')
    if digest(raw)==receipt['patchedHash']:
        replace(path,raw,receipt['original'].encode());return 'exact bytes'
    if receipt['hadProxy']:value['proxy']=receipt['previous']
    else:value.pop('proxy',None)
    replace(path,raw,json.dumps(value,separators=(',',':')).encode());return 'proxy key only; newer browser changes retained'
