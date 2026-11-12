#!/usr/bin/env python3
"""Exercise production TLS entry points against ephemeral loopback certificates.

No real credentials, gateway requests, Keychain edits, or persistent test keys.
"""
import asyncio
import hashlib
import http.client
import json
import logging
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(engine))
from tls_policy import install, pinned_context, require_strict
import trust

ROOT = Path(__file__).resolve().parent


def openssl(base, *args):
    subprocess.run(['/usr/bin/openssl', *args], cwd=base, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Fixture:
    def __init__(self, base, leaf, response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.accepts = 0
        self.application_data = []
        self.running = True
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(base / leaf), str(base / 'leaf.key'))
        self.response = response
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while self.running:
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepts += 1
            raw.settimeout(2)
            try:
                with self.context.wrap_socket(raw, server_side=True) as tls:
                    data = tls.recv(4096)
                    if data:
                        # Headers and POST body may arrive in separate TLS records.
                        # Drain the complete request before closing to avoid a TCP RST.
                        while b'\r\n\r\n' not in data:
                            part = tls.recv(4096)
                            if not part:
                                raise OSError('incomplete fixture headers')
                            data += part
                        headers, body = data.split(b'\r\n\r\n', 1)
                        size = next((int(h.split(b':', 1)[1]) for h in headers.split(b'\r\n')
                                     if h.lower().startswith(b'content-length:')), 0)
                        while len(body) < size:
                            part = tls.recv(4096)
                            if not part:
                                raise OSError('incomplete fixture request')
                            body += part
                        self.application_data.append(headers + b'\r\n\r\n' + body)
                        tls.sendall(self.response)
            except (ssl.SSLError, OSError):
                raw.close()

    def close(self):
        self.running = False
        self.listener.close()
        self.thread.join(timeout=3)


def main(resilient=False):
    from cpyvpn import auth, ssl_ctx, utils
    logging.disable(logging.CRITICAL)
    results = []
    with tempfile.TemporaryDirectory(prefix='checkpoint-strict-tls-', dir='/private/tmp') as temp:
        base = Path(temp)
        (base / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Ephemeral Test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        openssl(base, 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-config', 'ca.cnf', '-keyout', 'ca.key', '-out', 'ca.pem')
        openssl(base, 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Loopback Fixture',
                '-keyout', 'leaf.key', '-out', 'leaf.csr')
        for label, san, days in [('valid', 'IP:127.0.0.1', '1'),
                                  ('wrong-name', 'DNS:wrong.invalid', '1'),
                                  ('expired', 'IP:127.0.0.1', '-1')]:
            (base / 'leaf.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=' + san + '\n')
            if label == 'expired':
                (base / 'index').touch()
                (base / 'serial').write_text('1000\n')
                (base / 'sign.cnf').write_text('[ca]\ndefault_ca=sign\n[sign]\ndatabase=index\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\nserial=serial\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n')
                openssl(base, 'ca', '-batch', '-config', 'sign.cnf', '-in', 'leaf.csr',
                        '-startdate', '20200101000000Z', '-enddate', '20200102000000Z',
                        '-extfile', 'leaf.cnf', '-out', 'expired.pem')
            else:
                openssl(base, 'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                        '-CAcreateserial', '-days', days, '-extfile', 'leaf.cnf', '-out', label + '.pem')
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert((base / 'ca.pem').read_text())).hexdigest()
        context = pinned_context(base / 'ca.pem', digest)
        real_create = socket.create_connection
        for label in ('valid', 'wrong-name', 'expired', 'untrusted'):
            fixture = Fixture(base, ('valid' if label == 'untrusted' else label) + '.pem')
            test_context = ssl.create_default_context() if label == 'untrusted' else context
            test_context.minimum_version = ssl.TLSVersion.TLSv1_2
            install(ssl_ctx, utils, '127.0.0.1', test_context, resilient=resilient)
            def redirect_socket(address, *args, **kwargs):
                assert address == ('127.0.0.1', 443)
                return real_create(('127.0.0.1', fixture.port), *args, **kwargs)
            # Exercise the exact preflight check and exact control-request path.
            errors = []
            try:
                with patch('socket.create_connection', redirect_socket):
                    for action in (lambda: ssl_ctx.check_ssl_mode('127.0.0.1', 443, False),
                                   lambda: utils.do_https_request('https://127.0.0.1/clients/', data='NO_SECRET')):
                        try:
                            action()
                            errors.append(None)
                        except ssl.SSLCertVerificationError as error:
                            errors.append(error.verify_code)
                # Async dataplane uses the same strict context and hostname.
                async def async_handshake():
                    transport, _ = await asyncio.get_running_loop().create_connection(asyncio.Protocol,
                        host='127.0.0.1', port=fixture.port, ssl=require_strict(test_context),
                        server_hostname='127.0.0.1')
                    transport.abort()
                try:
                    asyncio.run(async_handshake())
                    errors.append(None)
                except ssl.SSLCertVerificationError as error:
                    errors.append(error.verify_code)
            finally:
                fixture.close()
            assert fixture.accepts == (2 if resilient else 3), (label, fixture.accepts)
            if label == 'valid':
                assert errors == [None] * 3 and len(fixture.application_data) == 1
            else:
                assert all(e is not None for e in (errors[1:] if resilient else errors)) and not fixture.application_data
                if resilient:assert errors[0] is None # mode validation adds no network probe
            assert test_context.check_hostname and test_context.verify_mode == ssl.CERT_REQUIRED
            results.append({'case': label, 'verify_codes': errors,
                'connections': fixture.accepts, 'application_requests': len(fixture.application_data)})
        install(ssl_ctx, utils, '127.0.0.1', context, resilient=resilient)
        # All these refusals must happen before any network connection.
        blocked = [lambda: pinned_context(base / 'ca.pem', '0' * 64),
                   lambda: ssl_ctx.set_ssl_strict_mode(False),
                   lambda: ssl_ctx.check_ssl_mode('127.0.0.1', 443, True),
                   lambda: ssl_ctx.check_ssl_mode('wrong.invalid', 443, False)]
        blocked += [lambda url=url: utils.do_https_request(url, data='NO_SECRET') for url in (
            'http://127.0.0.1/clients/', 'https://wrong.invalid/clients/',
            'https://127.0.0.1:444/clients/', 'https://127.0.0.1/other',
            'https://127.0.0.1/clients/?query=1', 'https://127.0.0.1/clients/#fragment',
            'https://user@127.0.0.1/clients/')]
        with patch('socket.create_connection', side_effect=AssertionError('NETWORK_FORBIDDEN')):
            for action in blocked:
                try:
                    action()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError('POLICY_BYPASSED')
            with patch.object(trust,'owned'), patch.object(trust,'CP',base):
                (base/'registry').mkdir()
                (base/'registry/HKLM_registry.data').write_text(': (accepted_cn\n: ("gateway.invalid" :--Fingerprint-- ("WRONG WORDS"))\n)')
                try: trust.accepted('gateway.invalid','EXPECTED WORDS')
                except trust.Refused as e: assert str(e)=='OFFICIAL_PIN_MISMATCH'
                else: raise AssertionError('SAVED_PIN_BYPASSED')
        fixture = Fixture(base, 'valid.pem', b'HTTP/1.1 302 Found\r\nLocation: https://wrong.invalid/\r\nContent-Length: 0\r\n\r\n')
        try:
            with patch('socket.create_connection', lambda address, *a, **kw: real_create(('127.0.0.1', fixture.port), *a, **kw)):
                try:
                    utils.do_https_request('https://127.0.0.1/clients/', data='NO_SECRET')
                except RuntimeError as error:
                    assert str(error) == 'CONTROL_HTTP_302'
                else:
                    raise AssertionError('REDIRECT_ACCEPTED')
        finally:
            fixture.close()
        assert fixture.accepts == 1
        results.append({'case': 'policy-pin-and-redirect-refusals', 'pre_network_refusals': len(blocked) + 1,
                        'redirect_connections': fixture.accepts})
    print(json.dumps({'passed': True, 'results': results}, indent=2))


if __name__ == '__main__':
    main()
