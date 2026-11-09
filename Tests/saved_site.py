"""Exercise the first-use binding with public, ephemeral fixture identity data."""
import json, ssl, subprocess, sys, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import trust
with tempfile.TemporaryDirectory() as d:
    root=Path(d); ca=root/'ca';leaf=root/'leaf';csr=root/'csr';key=root/'key'
    def openssl(*args):
        subprocess.run(['/usr/bin/openssl',*map(str,args)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=Fixture CA','-keyout',root/'cak','-out',ca,'-days','1')
    openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=fixture.invalid','-keyout',key,'-out',csr)
    (root/'ext').write_text('subjectAltName=IP:127.0.0.1\n')
    openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',root/'cak','-CAcreateserial','-extfile',root/'ext','-out',leaf,'-days','1')
    pem=leaf.read_bytes()+ca.read_bytes()
    class Discovery:
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def wrap_socket(self,*a,**kw):return self
        def getpeercert(self,binary_form):return ssl.PEM_cert_to_DER_cert(leaf.read_text())
    ctx=Discovery()
    def never(*_):raise AssertionError('unexpected confirmation of changed binding')
    data=root/'data';data.mkdir()
    with patch.object(trust,'DATA',data),patch.object(trust,'site',return_value=('fixture.invalid','127.0.0.1')),patch.object(trust.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout=pem)),patch.object(trust,'accepted'),patch.object(trust,'pinned_context',return_value=ctx),patch.object(trust.socket,'create_connection',return_value=ctx):
        calls=[];trust.anchor(calls.append);assert len(calls)==1
        trust.anchor(never)
        for field in ('site','ip','cn','ca_sha256'):
            (data/'ssl-site.json').write_text(json.dumps({**calls[0],field:'changed'}))
            try:trust.anchor(never)
            except trust.Refused as e:assert str(e)=='SAVED_SITE_OR_PIN_CHANGED'
            else:raise AssertionError(field)
        print('Initial consent once; repeat needs no new consent; changed site, IP, name and CA pin all blocked.')
