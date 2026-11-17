#!/usr/bin/env python3
"""Developer-side audit and receiver-side expected-code manifest (no app launch)."""
import argparse, hashlib, json, os, plistlib, re, stat, subprocess
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('app', type=Path)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--evidence', type=Path, required=True)
p.add_argument('--recipient-os', default='26.6.2')
a = p.parse_args()
app = a.app.resolve()
def run(*args):
    r = subprocess.run(list(map(str, args)), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {'exit': r.returncode, 'output': r.stdout}
def version(s): return tuple((list(map(int, s.split('.'))) + [0, 0, 0])[:3])
magic = {bytes.fromhex(x) for x in ('cffaedfe','cefaedfe','feedfacf','feedface','cafebabe','bebafeca','cafebabf','bfbafeca')}
info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
result = {'version': info['CFBundleShortVersionString'], 'build': info['CFBundleVersion'],
          'declared_minimum': info['LSMinimumSystemVersion'], 'recipient_os': a.recipient_os,
          'bundle_signature': run('codesign','--verify','--deep','--strict','--all-architectures',app), 'files': {}}
assert result['bundle_signature']['exit'] == 0, result['bundle_signature']
assert version(info['LSMinimumSystemVersion']) <= version(a.recipient_os)
for path in sorted(app.rglob('*')):
    if path.is_symlink():
        assert path.exists() and app in path.resolve().parents, f'Broken/external link: {path}'
        continue
    if not path.is_file(): continue
    with path.open('rb') as f: header = f.read(4)
    if header not in magic: continue
    name = path.relative_to(app).as_posix()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o755, (name, oct(mode))
    arches = run('lipo','-archs',path)
    assert arches['exit'] == 0 and 'arm64' in arches['output'].split() and 'arm64e' not in arches['output'].split(), arches
    commands = run('otool','-l',path)
    minima = re.findall(r'^\s*minos (\d+(?:\.\d+){1,2})\s*$', commands['output'], re.M)
    minima += re.findall(r'cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version (\d+(?:\.\d+){1,2})', commands['output'])
    assert minima and all(version(x) <= version(a.recipient_os) for x in minima), (name,minima)
    assert all(version(x) <= version(info['LSMinimumSystemVersion']) for x in minima), (name,minima)
    assert 'LC_DYLD_ENVIRONMENT' not in commands['output'], name
    loads = run('otool','-L',path)
    dependencies = [line.strip().split(' (')[0] for line in loads['output'].splitlines() if line.startswith('\t')]
    for dep in dependencies:
        if dep.startswith(('/System/Library/', '/usr/lib/')): continue
        if dep.startswith('@rpath/'):
            assert (app/'Contents/Frameworks'/dep[7:]).exists(), (name,dep)
        elif dep.startswith(('@loader_path/', '@executable_path/')):
            assert (path.parent/dep.split('/',1)[1]).exists(), (name,dep)
        else: raise AssertionError((name,dep))
    signature = run('codesign','--verify','--strict','--all-architectures',path)
    assert signature['exit'] == 0, (name,signature)
    result['files'][name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': oct(mode),
        'architectures': arches['output'].strip().split(), 'minimum_macos': minima, 'dependencies': dependencies,
        'signature': signature, 'identity': run('codesign','-d','--verbose=4','--entitlements',':-',path)}
assert len(result['files']) == 12, len(result['files'])
proxy = app/'Contents/Resources/Engine/ocproxy'
assert '_pipe2' not in run('nm','-u',proxy)['output']
listing = run('ls','-leR',app)
result['acl_entries'] = [line for line in listing['output'].splitlines() if re.match(r'^\s*\d+:', line)]
assert not result['acl_entries'], result['acl_entries']
manifest = {'schema': 1, 'version': info['CFBundleShortVersionString'], 'build': info['CFBundleVersion'],
            'files': {name: {k: v for k,v in row.items() if k in ('sha256','architectures','minimum_macos')} for name,row in result['files'].items()}}
a.manifest.write_text(json.dumps(manifest, indent=2)+'\n')
a.evidence.write_text(json.dumps(result, indent=2)+'\n')
print('PASS: 12 Mach-O files; arm64; minimum OS <= declared minimum <= recipient; 0755; signatures; contained dependencies; no ACL; no pipe2')
