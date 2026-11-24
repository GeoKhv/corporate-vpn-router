"""Alternate site's connected gateway identity and a private-only TLS SAN."""
from contextlib import ExitStack
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(engine), str(Path(__file__).resolve().parents[1])]
import trust
import tls_policy
from beta_tls import Fixture, openssl

host, ip, obj = 'alt.example.invalid', '192.0.2.4', 'Office-02'


def native(state='Connected', name=obj):
    return (f'Conn seed.example.invalid:\n  gw: 192.0.2.1\n  status: Idle\n'
            f'  gateway list:\n   (Idle) {obj}\n'
            f'Conn {host}:\n  gw: {ip}\n  status: {state}\n  gateway list:\n'
            f'   ({state}) {name}\n   (Idle) Other\n')


def refuses(code, action):
    try:
        action()
    except trust.Refused as exc:
        assert str(exc) == code, (code, str(exc))
    else:
        raise AssertionError(code)


with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
    root = Path(tmp)
    (root/'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n'
        '[dn]\nCN=Offline Test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n')
    openssl(root,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-config','ca.cnf','-keyout','ca.key','-out','ca.pem')
    (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:172.16.0.9\n')
    services = []
    for n in (0,1):
        # Same CA, name and SAN, different target keys and leaf certificates.
        openssl(root,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+obj+' VPN Certificate',
                '-keyout','leaf.key','-out','leaf.csr')
        openssl(root,'x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key',
                '-CAcreateserial','-days','1','-extfile','ext','-out','leaf%d.pem'%n)
        services.append(Fixture(root,'leaf%d.pem'%n))
        stack.callback(services[-1].close)
    ca_der = ssl.PEM_cert_to_DER_cert((root/'ca.pem').read_text())
    ca_hash = hashlib.sha256(ca_der).hexdigest()
    seed = dict(site='seed.example.invalid',ip='192.0.2.1',cn='Seed',ca_sha256=ca_hash)
    (root/'seed.json').write_text(json.dumps(dict(schema=1,automaticFirstUse=True,receipt=seed,
                provenance='OWNER_APPROVED_EXISTING_OFFICIAL_CLIENT_PIN_AND_STRICT_LIVE_TLS')))
    (root/'registry').mkdir()
    (root/'registry/HKLM_registry.data').write_text(': (accepted_cn\n: ("'+obj+' VPN Certificate" :--Fingerprint-- ("'+trust.fingerprint(ca_der)+'"))\n)')
    stack.enter_context(patch.object(trust,'CP',root))
    stack.enter_context(patch.object(trust,'owned'))
    stack.enter_context(patch.object(trust,'DATA',root))
    stack.enter_context(patch.object(trust,'APPROVED_GATEWAY',root/'seed.json'))
    official=stack.enter_context(patch.object(trust,'official_output',return_value=native()))
    real_dial=socket.create_connection
    node=0
    def dial(address, *args, **kwargs):
        assert address==(ip,443)
        return real_dial(('127.0.0.1',services[node].port),*args,**kwargs)
    stack.enter_context(patch.object(socket,'create_connection',side_effect=dial))
    real_dns=socket.getaddrinfo
    def dns(name,*args):
        return [(0,0,0,'',(ip,443))] if name==host else real_dns(name,*args)
    stack.enter_context(patch.object(socket,'getaddrinfo',side_effect=dns))
    def inventory(command, **kwargs):
        assert command[3]==ip+':443' and command[5]==host and command[1]=='s_client'
        return subprocess.CompletedProcess(command,0,(root/'leaf0.pem').read_bytes()+(root/'ca.pem').read_bytes())
    stack.enter_context(patch.object(trust.subprocess,'run',side_effect=inventory))
    approvals=[]
    first=lambda:trust.anchor(approvals.append,require_idle=False)
    for invalid in (native(name='Other'),native().replace('(Connected) '+obj,'(Idle) '+obj),
                    native().replace('(Idle) Other','(Connected) Other')):
        official.return_value=invalid
        refuses('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED',first)
    assert not (root/'ssl-site.json').exists()
    official.return_value=native()
    official.return_value=native().replace('Conn '+host+':', 'Conn Corporate VPN:').replace('gw: '+ip, 'gw: '+host)
    address,ctx=first()
    assert address==ip and len(approvals)==1
    receipt=json.loads((root/'ssl-site.json').read_text())
    assert receipt['gateway_object']==obj and 'ip' not in receipt
    ip='192.0.2.5'
    official.return_value=native('Idle')
    address,ctx=trust.anchor(approvals.append)
    assert address==ip and (root/'ssl-site.json').exists() and len(approvals)==1
    assert ctx.check_hostname and ctx.verify_mode==ssl.CERT_REQUIRED and ctx.gateway_http_host==host
    for node in (0,1):
        for resilient in (False,True):
            hooks,utils=SimpleNamespace(),SimpleNamespace()
            tls_policy.install(hooks,utils,ip,ctx,resilient)
            with patch('connection_resilience.connect',side_effect=dial):
                try:
                    utils.do_https_request('https://'+ip+'/clients/',data='test')
                    assert node==0
                except ssl.SSLCertVerificationError:
                    assert node==1
                finally:
                    tls_policy.close_control()
        async def stream():
            reader,writer=await asyncio.open_connection('127.0.0.1',services[node].port,
                        ssl=ctx,server_hostname=tls_policy.tls_name(ctx,ip))
            try:
                assert node==0
            finally:
                writer.close()
                await writer.wait_closed()
        try:
            asyncio.run(stream())
        except ssl.SSLCertVerificationError:
            assert node==1
    assert len(services[0].application_data)==2
    assert all(b'Host: alt.example.invalid' in request for request in services[0].application_data)
    assert not services[1].application_data

    # Fleet provisioned site: reuse only hashes from a completed object enrollment.
    node=0
    pin=dict(schema=1,site=host,leaf_sha256=receipt['leaf_sha256'],ca_sha256=receipt['ca_sha256'])
    provisioning=root/'Provisioning'
    provisioning.mkdir()
    manifest=provisioning/'ApprovedSitePin.json'
    manifest.write_text(json.dumps(pin))
    # An upgrade keeps the existing user's proof and does not need a second handoff.
    old_proof=(root/'official-alternate-binding.json').read_bytes()
    address,ctx=trust.anchor(approvals.append)
    assert address==ip and (root/'official-alternate-binding.json').read_bytes()==old_proof
    for filename in ('ssl-site.json','official-alternate-binding.json'):
        (root/filename).unlink()
    idle=native('Idle').replace('status: Idle','status: Idle\n  active site: false',1)
    idle=idle.replace(f'gw: {ip}\n  status: Idle',f'gw: {ip}\n  status: Idle\n  active site: true')
    official.return_value=idle.replace('active site: false','active site: true')
    refuses('OFFICIAL_SITE_AMBIGUOUS',first)
    official.return_value=idle
    for key in ('ca_sha256','leaf_sha256'):
        manifest.write_text(json.dumps(dict(pin,**{key:'f'*64})))
        refuses('APPROVED_GATEWAY_MISMATCH',first)
        assert not (root/'ssl-site.json').exists()
    manifest.write_text(json.dumps(pin))
    # A deliberate site choice works with the real native shape: Connected
    # site status can coexist with an all-Idle gateway list. Fleet enrollment
    # checks the reviewed leaf and CA instead of requiring a Connected object.
    # Reproduce an IPv4-only inactive entry before the selected alternate.
    # The native list reports no connected object; the provisioned leaf and
    # CA must still be checked on a real loopback TLS handshake.
    stale='Conn 192.0.2.99:\n gw: 192.0.2.99\n status: Idle\n active site: false\n gateway list:\n (Idle) Old\n'
    current=f'Conn {host}:\n gw: {ip}\n status: Connected\n active site: true\n gateway list:\n (Idle) {obj}\n'
    official.return_value=stale+current
    with patch.object(trust,'gateway_ipv4',side_effect=lambda name,deadline: {ip if name==host else '192.0.2.1'}):
        address,ctx=first()
        assert address==ip and ctx.gateway_leaf_der==ssl.PEM_cert_to_DER_cert((root/'leaf0.pem').read_text())
        official.return_value=stale+current.replace('status: Connected','status: Idle')
        assert trust.anchor(approvals.append)[0]==ip
    (root/'ssl-site.json').unlink()
    preference=root/'preferred-site.json'
    official.return_value=native('Idle')
    preference.write_text(json.dumps({'site':'foreign.example.invalid'}))
    refuses('INVALID_SITE_SELECTION',first)
    preference.write_text(json.dumps({'site':host}))
    official.return_value=native('Idle').replace('status: Idle','status: Connected',1)
    refuses('OFFICIAL_OTHER_SITE_ACTIVE',first)
    official.return_value=native('Idle')
    address,ctx=trust.anchor(approvals.append)
    assert address==ip and len(approvals)==1
    enrolled=json.loads((root/'ssl-site.json').read_text())
    assert enrolled['leaf_sha256']==pin['leaf_sha256'] and 'ip' not in enrolled
    assert not (root/'official-alternate-binding.json').exists()
    preference.unlink()
    ip='192.0.2.77'
    official.return_value=native('Idle')
    address,ctx=trust.anchor(approvals.append)
    assert address==ip and ctx.gateway_leaf_der==ssl.PEM_cert_to_DER_cert((root/'leaf0.pem').read_text())
    node=1
    try:
        trust.anchor(approvals.append)
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError('preconfigured site accepted a substitute certificate')
    assert not services[1].application_data
print('PASS preconfigured pin: fresh idle client, two sites, prior object enrollment, rotation, CA/leaf mismatch')
print('PASS native site/object, ambiguous and foreign objects, persisted leaf, rotated dial IP, strict sync and async TLS')
