#!/usr/bin/env python3
"""Set distributable Mach-O permissions on a staging bundle, never an install.

Run before signing and packaging. No bytes, xattrs or security policy change.
"""
import argparse
import stat
from pathlib import Path

MAGIC = {bytes.fromhex(v) for v in (
    'cffaedfe', 'cefaedfe', 'feedfacf', 'feedface',
    'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}

def normalize(app, check=False):
    if not (app / 'Contents/Info.plist').is_file():
        raise ValueError('Expected an application staging bundle')
    count = 0
    for path in app.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as stream:
            macho = stream.read(4) in MAGIC
        if macho:
            if check:
                if stat.S_IMODE(path.stat().st_mode) != 0o755:
                    raise ValueError(f'Mach-O must have mode 0755: {path}')
            else:
                path.chmod(0o755)
            count += 1
    if not count:
        raise ValueError('No Mach-O code found')
    print(f'{"Verified" if check else "Normalized"} {count} Mach-O files at 0755')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('staging_app', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    normalize(args.staging_app, args.check)
