#!/usr/bin/env python3
"""Content, mode and symlink inventory; no timestamps or owner-specific paths."""
import hashlib, json, stat, sys
from pathlib import Path
root = Path(sys.argv[1])
result = {}
for path in sorted(root.rglob('*')):
    mode = path.lstat().st_mode
    key = str(path.relative_to(root))
    if stat.S_ISLNK(mode):
        result[key] = ['link', str(path.readlink())]
    elif stat.S_ISREG(mode):
        result[key] = ['file', stat.S_IMODE(mode), hashlib.sha256(path.read_bytes()).hexdigest()]
    elif stat.S_ISDIR(mode):
        result[key] = ['dir', stat.S_IMODE(mode)]
    else:
        raise SystemExit('Unexpected payload type: ' + key)
print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
