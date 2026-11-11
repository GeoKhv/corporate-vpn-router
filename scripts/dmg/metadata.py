"""Load hash-pinned, pure-Python build-only wheels without installing packages."""
import hashlib
import sys
from pathlib import Path

WHEELS = {
    'ds_store-1.3.1-py3-none-any.whl': 'fbacbb0bd5193ab3e66e5a47fff63619f15e374ffbec8ae29744251a6c8f05b5',
    'mac_alias-2.2.2-py3-none-any.whl': '504ab8ac546f35bbd75ad014d6ad977c426660aa721f2cd3acf3dc2f664141bd',
}
for name, expected in WHEELS.items():
    path = Path(__file__).resolve().parent/'vendor'/name
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Build dependency checksum mismatch: ' + name)
    sys.path.insert(0, str(path))

from ds_store import DSStore
from mac_alias import Alias, Bookmark
