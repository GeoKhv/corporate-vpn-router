"""Read-only diagnostic, including a TLS conversation against a loopback fixture."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import ssl
import sys
import tempfile
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / 'scripts'), str(root / 'Tests'), str(engine)]
import check_connected_gateway as probe
import export_gateway_pins as exporter
from beta_tls import Fixture, openssl
import trust

connected = '''Conn one.example:
    gw: 192.0.2.1
    status: Idle
    gateway list:
     (Idle) other-gw
Conn two.example:
    gw: 192.0.2.2
    status: Connected
    gateway list:
     (Connected) second-gw
     (Idle) spare-gw
'''
site, ip, entries = snapshot = probe.connected_gateway(connected, trust)
assert (site, ip) == ('two.example', '192.0.2.2')
assert entries == (('Connected', 'second-gw'), ('Idle', 'spare-gw'))
assert probe.connected_gateway(connected.replace('(Idle) spare-gw', '(Idle) ??'), trust)[2] == ()
for text, error in [(connected.replace('status: Connected', 'status: Idle'), 'NO_CONNECTED_SITE'),
                    (connected.replace('status: Idle', 'status: Connected'), 'NO_UNIQUE_CONNECTED_SITE')]:
    try:
        probe.connected_gateway(text, trust)
    except probe.ProbeError as exc:
        assert str(exc) == error
    else:
        raise AssertionError(error)

with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
    base = Path(directory)
    (base / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n'
                                 '[dn]\nCN=Fixture CA\n[ca]\nbasicConstraints=critical,CA:TRUE\n')
    openssl(base, 'req', '-new', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
            '-config', 'ca.cnf', '-keyout', 'ca.key', '-out', 'ca.pem')
    openssl(base, 'req', '-new', '-nodes', '-newkey', 'rsa:2048', '-subj',
            '/CN=second-gw VPN Certificate', '-keyout', 'leaf.key', '-out', 'leaf.csr')
    (base / 'leaf.cnf').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n'
                                   'subjectAltName=IP:10.0.0.1\n')
    openssl(base, 'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
            '-CAcreateserial', '-extfile', 'leaf.cnf', '-days', '1', '-out', 'leaf.pem')
    chain = [(base / name).read_bytes() for name in ('leaf.pem', 'ca.pem')]
    (base / 'chain.pem').write_bytes(b'\n'.join(chain))
    registry = base / 'registry'
    registry.mkdir()
    words = trust.fingerprint(ssl.PEM_cert_to_DER_cert(chain[-1].decode()))
    entry = ': (accepted_cn\n: ("second-gw VPN Certificate" :--Fingerprint-- ("' + words + '"))\n)'
    (registry / 'HKLM_registry.data').write_text(entry)
    stack.enter_context(patch.object(trust, 'CP', base))
    stack.enter_context(patch.object(trust, 'owned'))
    assert probe.compare(site, ip, (('Idle', 'second-gw'),), chain, trust) == (
        'tls_name=neither active_object=unavailable site_list=match official_ca=match chain=valid')
    assert 'active_object=different site_list=different' in probe.compare(site, ip, (('Connected', 'other-gw'),), chain, trust)
    (registry / 'HKLM_registry.data').write_text(entry.replace(words, 'WRONG WORDS'))
    assert 'official_ca=different' in probe.compare(site, ip, entries, chain, trust)
    (registry / 'HKLM_registry.data').write_text(entry)
    server = Fixture(base, 'chain.pem')
    stack.callback(server.close)
    real_run = probe.run
    def loopback_run(args, timeout=10):
        if args[1] == 's_client':
            assert args[2:] == ['-connect', ip + ':443', '-servername', site, '-showcerts']
            args = [*args[:3], '127.0.0.1:' + str(server.port), *args[4:]]
        return real_run(args, timeout)
    stack.enter_context(patch.object(probe, 'run', side_effect=loopback_run))
    stack.enter_context(patch.object(probe.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', (ip, 443))]))
    with patch.object(probe, 'official', return_value=snapshot):
        assert probe.probe(trust) == 'tls_name=neither active_object=match site_list=match official_ca=match chain=valid'
    with patch.object(probe, 'official', side_effect=[snapshot, (site, ip, ())]):
        try:
            probe.probe(trust)
        except probe.ProbeError as exc:
            assert str(exc) == 'CONNECTION_CHANGED'
        else:
            raise AssertionError('stale session accepted')

    if hasattr(trust, 'private_gateway_binding'):
        hashes = [hashlib.sha256(ssl.PEM_cert_to_DER_cert(p.decode())).hexdigest() for p in chain]
        primary = dict(site='one.example', ip='192.0.2.1', cn='primary', ca_sha256=hashes[1])
        expected = dict(site=site, leaf_sha256=hashes[0], ca_sha256=hashes[1])
        stack.enter_context(patch.object(trust, 'approved_receipt', return_value=primary))
        stack.enter_context(patch.object(trust, 'DATA', base))
        native = stack.enter_context(patch.object(trust, 'official_output', return_value=connected))
        def dial(endpoint, **kwargs):
            assert endpoint == (ip, 443)
            sock = probe.socket.socket()
            sock.settimeout(kwargs['timeout'])
            sock.connect(('127.0.0.1', server.port))
            return sock
        stack.enter_context(patch.object(trust.socket, 'create_connection', side_effect=dial))
        process_run = trust.subprocess.run
        def dial_inventory(args, **kwargs):
            assert args == ['/usr/bin/openssl','s_client','-connect',ip+':443','-servername',site,'-showcerts']
            return process_run([*args[:3], '127.0.0.1:'+str(server.port), *args[4:]], **kwargs)
        stack.enter_context(patch.object(trust.subprocess, 'run', side_effect=dial_inventory))
        assert exporter.export(trust) == ('connected', expected)
        assert trust.DATA == base and not (base/'ssl-site.json').exists()
        proof = base/'official-alternate-binding.json'
        assert not proof.exists()
        with patch.object(trust, 'approved_receipt', return_value=dict(primary, ca_sha256='0'*64)):
            assert exporter.main(engine) == 'GW-RESULT ALTERNATE_CA_NOT_CONFIRMED'
        native.return_value = connected.replace('(Connected) second-gw', '(Idle) second-gw')
        assert exporter.main(engine) == 'GW-RESULT OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED'
        native.return_value = connected.replace('status: Connected', 'status: Idle')
        assert exporter.main(engine) == 'GW-RESULT CONNECT_ASSIGNED_SITE'
        proof.write_text(json.dumps(dict(primary=primary, alternate=expected)))
        with patch.object(trust, 'official_output', side_effect=AssertionError('unneeded network')):
            assert exporter.export(trust) == ('saved', expected)
        print('PASS: export from saved proof and fresh live TLS, wrong CA, ambiguous object, no enrollment writes')
    assert not server.application_data
print('PASS: native site selection, registry, real TLS metadata, redaction, changed session')
