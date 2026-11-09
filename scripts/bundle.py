"""Build the restricted packet proxy and bundle a pinned, relocatable CPython."""
import hashlib,json,os,re,shutil,subprocess,sys,tarfile,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
TP=ROOT/'ThirdParty'
CACHE=ROOT/'.build/deps'
RUNTIME_URL='https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.13.18%2B20261026-aarch64-apple-darwin-install_only.tar.gz'
SHA='e5af2fde6a937a0e0c795a0c595c4efb70578d57463a2657c819992b9b9acbac'
def check(path,expected):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected: raise RuntimeError('Hash mismatch: '+path.name)
def run(*cmd,cwd=None):
    subprocess.run(cmd,cwd=cwd,check=True,stdout=subprocess.DEVNULL)
def native(dest):
    files=[('ocproxy.tar.gz','a617cb9f47e36cb2d68b81f7edf5148646ee6e3374f985763afc5945101fe88c'),('libevent-2.1.12-stable.tar.gz','92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb')]
    key=hashlib.sha256((TP/'ocproxy-policy.patch').read_bytes()+Path(__file__).read_bytes()).hexdigest()
    for name,digest in files: check(TP/name,digest)
    cache=CACHE/('ocproxy-'+key)
    if not cache.exists():
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            for name,digest in files:
                run('/usr/bin/tar','-xzf',str(TP/name),'-C',tmp)
            oc=next(Path(tmp).glob('*ocproxy*'));lib=next(Path(tmp).glob('libevent-*'))
            run('/usr/bin/patch','-p1','-i',str(TP/'ocproxy-policy.patch'),cwd=oc)
            run('/bin/sh','./configure','--disable-shared','--enable-static','--disable-openssl','--disable-samples','--disable-libevent-regress','--disable-dependency-tracking',cwd=lib)
            run('/usr/bin/make','-j4','include/event2/event-config.h','libevent.la',cwd=lib)
            s=(oc/'Makefile.am').read_text().split('LWIP_SOURCES',1)[1].split('APP_SOURCES',1)[0]
            inputs=re.findall(r'(?m)^\s*([a-zA-Z0-9_/.]+\.c)\s*\\?\s*$',s)+['src/ocproxy.c']
            includes=['src','lwip/src','lwip/src/include','lwip/src/include/ipv4','lwip/src/include/ipv6','contrib/ports/unix/include']
            run('/usr/bin/cc','-std=gnu99','-O2','-Dunix','-DIPv4',*['-I'+str(oc/i) for i in includes],'-I'+str(lib/'include'),*[str(oc/i) for i in inputs],str(lib/'.libs/libevent.a'),'-lpthread','-o',str(cache))
    shutil.copy2(cache,dest)
def main():
    resources=Path(sys.argv[1]); engine=resources/'Engine'
    CACHE.mkdir(parents=True,exist_ok=True)
    shutil.copytree(ROOT/'Backend',engine,ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(TP/'cpyvpn',engine/'cpyvpn',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(TP/'licenses',resources/'Licenses')
    native(engine/'ocproxy')
    arch=CACHE/'runtime.tar.gz'
    if not arch.exists(): urllib.request.urlretrieve(RUNTIME_URL,arch)
    check(arch,SHA)
    with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
        run('/usr/bin/tar','-xzf',str(arch),'-C',tmp)
        src=Path(tmp)/'python';dst=resources/'Runtime'
        (dst/'bin').mkdir(parents=True);shutil.copy2(src/'bin/python3.13',dst/'bin/python3.13')
        std=src/'lib/python3.13'
        for p in std.rglob('*.py'):
            rel=p.relative_to(std)
            if any(k in rel.parts for k in ('test','tests','ensurepip','idlelib','site-packages','tkinter','turtledemo','__pycache__','_pyrepl')):continue
            target=dst/'lib/python3.13'/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
        (dst/'lib/python3.13/lib-dynload').mkdir(exist_ok=True)
    for p in [engine/'ocproxy',dst/'bin/python3.13']:
        run('/usr/bin/codesign','--force','-s','-','--timestamp=none',str(p))
if __name__=='__main__': main()
