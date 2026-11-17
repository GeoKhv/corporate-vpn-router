import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"Backend/Selective"))
"""Durability, immutable ownership and fail-closed capacity, without networking."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

from domain_map import DomainMap
from services import dns_answer


def main():
    with tempfile.TemporaryDirectory(prefix='cvr-domain-durable-') as temp:
        directory=Path(temp);path=directory/'map.json'
        child='from domain_map import DomainMap; import os,sys; m=DomainMap(sys.argv[1]); m.allocate("alpha.work.invalid"); m.allocate("beta.work.invalid"); os._exit(0)'
        subprocess.run([sys.executable,'-B','-c',child,str(path)],check=True,cwd=Path(__file__).resolve().parents[2]/"Backend/Selective")
        m=DomainMap(path)
        assert m.address('beta.work.invalid',4)=='198.18.75.3'
        assert m.address('alpha.work.invalid',4)=='198.18.75.2'
        assert m.name_for_ip('198.18.75.2')=='alpha.work.invalid'
        assert m.name_for_ip('fdc7:7652:9a10:75::3')=='beta.work.invalid'
        for address in ['198.18.75.4','198.18.74.2','127.0.0.1','::1']:
            try:m.name_for_ip(address)
            except ValueError:pass
            else:raise AssertionError('unowned address accepted')
        for i in range(251):m.allocate(f'n{i}.work.invalid')
        before=path.read_bytes()
        try:m.allocate('overflow.work.invalid')
        except ValueError:pass
        else:raise AssertionError('exhaustion must not recycle')
        assert path.read_bytes()==before
        assert DomainMap(path).name_for_ip('198.18.75.2')=='alpha.work.invalid'
        broken=directory/'broken.json';broken.write_text('{');broken.chmod(0o600)
        try:DomainMap(broken)
        except ValueError:pass
        else:raise AssertionError('corrupt map silently reset')
        symlink=directory/'link.json';symlink.symlink_to(path)
        try:DomainMap(symlink)
        except OSError:pass
        else:raise AssertionError('symlink followed')
        failed=DomainMap(directory/'failed.json')
        with patch('domain_map.os.fsync',side_effect=OSError('disk error')):
            try:failed.allocate('first.work.invalid')
            except OSError:pass
            else:raise AssertionError('persistence error hidden')
        try:failed.allocate('second.work.invalid')
        except ValueError:pass
        else:raise AssertionError('failed persistence continued')
    print('PASS durable identities after abrupt process exit; IPv4+IPv6; no address recycling; capacity, corruption, symlink and fsync failure rejected')


if __name__=='__main__':main()
