"""A DNS-bound gateway can rotate its dial address without changing its TLS identity."""
from contextlib import ExitStack
import asyncio
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
import browser_auth
import tls_policy
import trust
from beta_tls import Fixture, openssl

site = 'vpn.fixture.invalid'
first, second = '192.0.2.15', '192.0.2.16'
real_socket = socket.create_connection


def refuses(code, action):
    try:
        action()
    except trust.Refused as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError('expected ' + code)


with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp, ExitStack() as config:
    root = Path(tmp)
    (root/'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n'
        '[dn]\nCN=Offline Root\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
    openssl(root, 'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-config','ca.cnf','-keyout','ca.key','-out','ca.pem')
    openssl(root, 'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+site,
            '-keyout','leaf.key','-out','leaf.csr')
    config.enter_context(patch.object(trust, 'DATA', root))
    config.enter_context(patch.object(trust, 'APPROVED_GATEWAY', root/'absent'))
    config.enter_context(patch.object(trust, 'accepted'))  # covered separately with fixture registry
    approvals = []
    saved = root / 'ssl-site.json'

    def exercise(san, scenario):
        (root/'ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName='+san+'\n')
        openssl(root,'x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key',
                '-CAcreateserial','-days','1','-extfile','ext','-out','leaf.pem')
        chain = (root/'leaf.pem').read_bytes() + (root/'ca.pem').read_bytes()
        with ExitStack() as fixture:
            service = Fixture(root, 'leaf.pem')
            fixture.callback(service.close)
            seen_sni = []
            service.context.set_servername_callback(lambda _sock,name,_ctx: seen_sni.append(name))
            def dial(endpoint, *args, **kwargs):
                assert endpoint == (ip,443), endpoint
                return real_socket(('127.0.0.1',service.port),*args,**kwargs)
            def discovery(args, **kwargs):
                assert args[:2]==['/usr/bin/openssl','s_client'] and args[3]==ip+':443' and args[5]==site
                return subprocess.CompletedProcess(args,0,chain)
            fixture.enter_context(patch.object(trust.subprocess,'run',side_effect=discovery))
            fixture.enter_context(patch.object(socket,'create_connection',side_effect=dial))
            for ip in (first,second):
                with patch.object(trust,'site',return_value=(site,ip)):
                    if scenario=='mismatch':
                        refuses('SITE_SAN_MISMATCH', lambda:trust.anchor(approvals.append))
                        assert not service.application_data and not seen_sni
                        return
                    if scenario=='downgrade':
                        refuses('SAVED_SITE_OR_PIN_CHANGED', lambda:trust.anchor(approvals.append))
                        assert not service.application_data
                        return
                    address,ctx=trust.anchor(approvals.append)
                assert address==ip and tls_policy.tls_name(ctx,ip)==site
                assert ctx.check_hostname and ctx.verify_mode==ssl.CERT_REQUIRED and not ctx.hostname_checks_common_name
                for resilient in (False,True):
                    hooks,utils=SimpleNamespace(),SimpleNamespace()
                    tls_policy.install(hooks,utils,ip,ctx,resilient=resilient)
                    try:
                        hooks.check_ssl_mode(ip,443,False)
                        utils.do_https_request('https://'+ip+'/clients/',data='fixture')
                    finally:
                        tls_policy.close_control()
                browser_auth.single_tab_url('https://'+site+'/saml-vpn/ServiceProviderTabs?q=fixture',ip,ctx)
                async def async_handshake():
                    loop = asyncio.get_running_loop()
                    transport, _ = await loop.create_connection(asyncio.Protocol, host='127.0.0.1',
                        port=service.port, ssl=tls_policy.require_strict(ctx), server_hostname=tls_policy.tls_name(ctx,ip))
                    transport.close()
                asyncio.run(async_handshake())
                assert len(approvals)==1
                record=json.loads(saved.read_text())
                assert record['dns_name']==record['site']==site and 'ip' not in record
                assert all(name==site for name in seen_sni)
            assert len(service.application_data)==6 and len(seen_sni)>=10

    exercise('DNS:*.fixture.invalid','valid')
    unchanged=saved.read_bytes()
    dns_record=json.loads(unchanged)
    legacy={key:value for key,value in dns_record.items() if key!='dns_name'}
    legacy['ip']=first
    assert trust.binding_matches(legacy,dns_record)
    assert not trust.binding_matches(legacy,dict(dns_record,ca_sha256='0'*64))
    assert not trust.binding_matches(legacy,dict(dns_record,cn='Another gateway'))
    assert not trust.binding_matches(legacy,dict(legacy,ip=second))
    exercise('IP:'+first,'downgrade')
    exercise('IP:172.16.0.1','mismatch')
    exercise('DNS:wrong.fixture.invalid','mismatch')
    assert saved.read_bytes()==unchanged and len(approvals)==1

print('PASS DNS SAN and wildcard, two IPs, SNI on control/browser/data TLS, wrong names, no IP fallback after DNS enrollment')
