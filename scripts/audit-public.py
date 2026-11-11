#!/usr/bin/env python3
"""Audit explicit public inputs and ZIP payloads. Private deny patterns never leave this Mac."""
import argparse
import re
import io
import tarfile
import subprocess
import sys
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--deny-file', type=Path, help='Private newline-separated forbidden literals; do not commit this file')
parser.add_argument('--zip', type=Path)
parser.add_argument('--directory', type=Path, help='Audit a mounted distribution (read-only)')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
denied = [s.strip().lower().encode() for s in args.deny_file.read_text().splitlines() if s.strip()] if args.deny_file else []
patterns = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n'),
    re.compile(rb'gh[oapsr]_[A-Za-z0-9]{25,}'),
    re.compile(rb'(?:AKIA|ASIA)[A-Z0-9]{16}'),
    re.compile(rb'/Users/[A-Za-z0-9_.-]+/'),
]
failures = []

def check(name, data):
    if any(s in data.lower() for s in denied) or any(p.search(data) for p in patterns):
        failures.append(name)
    if name.endswith(('.tar.gz', '.tgz')):
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as nested:
            for member in nested:
                if member.isfile(): check(name + ':' + member.name, nested.extractfile(member).read())

if args.zip and args.directory:
    parser.error('Choose --zip or --directory')
if args.directory:
    for path in args.directory.rglob('*'):
        name = str(path.relative_to(args.directory))
        if any(part in name.split('/') for part in ['.private', '.build', '__MACOSX', '.git']):
            failures.append(name)
        if path.is_symlink():
            target = path.readlink()
            try:
                path.resolve().relative_to(args.directory.resolve())
                outside = False
            except ValueError:
                outside = True
            if target.is_absolute() or outside:
                failures.append(name)
        elif path.is_file():
            check(name, path.read_bytes())
elif args.zip:
    with zipfile.ZipFile(args.zip) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if any(s in info.filename for s in ['.private/', '.build/', '__MACOSX/', '.git/']):
                failures.append(info.filename)
            check(info.filename, archive.read(info))
else:
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).split(b'\0')
    for name in filter(None, files):
        path = root / name.decode()
        if path.is_symlink() or any(p in path.relative_to(root).parts for p in ['.private', '.build', 'dist']):
            failures.append(name.decode())
        else:
            check(name.decode(), path.read_bytes())
    if not any(files):
        raise SystemExit('No tracked files: stage the explicit public file set first.')
if failures:
    print('FAIL: forbidden content or paths in: ' + ', '.join(sorted(set(failures))))
    sys.exit(1)
print('PASS: audited public payload; no matched private literals, private keys, tokens or personal home paths.')
