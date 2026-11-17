"""Durable synthetic-address ownership. Never recycle an address.

Commit and fsync before DNS can return an address. Corruption, exhaustion or
foreign ownership fail closed. No DNS lookup or network socket is used here.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

V4=ipaddress.ip_network('198.18.75.0/24')
V6=ipaddress.ip_network('fdc7:7652:9a10:75::/120')
SCHEMA='cvr-stable-domain-map-v1'


class DomainMap:
    def __init__(self,path):
        self.path=Path(path)
        self.failed=False
        parent=self.path.parent.stat()
        if parent.st_uid!=os.getuid() or parent.st_mode&0o022:
            raise ValueError('domain map directory must be privately owned')
        self.names={}
        if self.path.exists() or self.path.is_symlink():
            fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'r') as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
                    raise ValueError('domain map must be an owned private regular file')
                value=json.load(f)
            if value.get('schema')!=SCHEMA:raise ValueError('domain map schema mismatch')
            self.names=value['names']
            if not isinstance(self.names,dict):raise ValueError('invalid domain map')
            slots=set()
            for name,slot in self.names.items():
                self.validate_name(name)
                if type(slot)!=int or not 2<=slot<=254 or slot in slots:
                    raise ValueError('invalid or reused synthetic address')
                slots.add(slot)
        self.reverse={slot:name for name,slot in self.names.items()}

    @staticmethod
    def validate_name(name):
        if not isinstance(name,str) or len(name)>253 or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',name):
            raise ValueError('invalid canonical domain')
        if any(len(label)>63 or label.startswith('-') or label.endswith('-') for label in name.split('.')):
            raise ValueError('invalid domain label')

    def allocate(self,name):
        if self.failed:raise ValueError('domain map persistence failed; restart required')
        self.validate_name(name)
        if name in self.names:return self.names[name]
        slot=max(self.reverse,default=1)+1
        if slot>254:raise ValueError('synthetic name capacity exhausted; addresses are never reused')
        updated=dict(self.names);updated[name]=slot
        fd,temp=tempfile.mkstemp(prefix='.domain-map-',dir=str(self.path.parent))
        try:
            with os.fdopen(fd,'w') as f:
                json.dump({'schema':SCHEMA,'names':updated},f,sort_keys=True)
                f.flush();os.fsync(f.fileno())
            os.replace(temp,self.path)
            dfd=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        except BaseException:
            self.failed=True
            raise
        finally:
            try:os.unlink(temp)
            except FileNotFoundError:pass
        self.names=updated;self.reverse[slot]=name
        return slot

    def address(self,name,version):
        slot=self.allocate(name)
        return str((V4 if version==4 else V6).network_address+slot)

    def name_for_ip(self,address):
        if self.failed:raise ValueError('domain map persistence failed; restart required')
        ip=ipaddress.ip_address(address);pool=V4 if ip.version==4 else V6
        if ip not in pool:raise ValueError('address outside synthetic map')
        slot=int(ip)-int(pool.network_address)
        if slot not in self.reverse:raise ValueError('unallocated synthetic address')
        return self.reverse[slot]
