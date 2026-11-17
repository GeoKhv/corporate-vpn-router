#!/usr/bin/env python3
"""Four serial public/strict TLS connections, no login or trust writes.

Run with the installed Python runtime and an explicit app/output directory.
Order A/B then (15s idle) B/A. A=existing openssl discovery, B=pinned Python.
This small matrix is observational; one pair cannot establish causation.
"""
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time

os.umask(0o077)
app, output = map(Path, sys.argv[1:])
sys.path.insert(0, str(app/'Contents/Resources/Engine'))
import connection_trace as trace
import trust
logging.disable(logging.CRITICAL)
trace.install(output, role='serial_AB_BA_no_auth')
res = app/'Contents/Resources'
helper = subprocess.run([str(res/'RouteHelper/RouteClient')], input='{"op":"status"}\n',
                        text=True, capture_output=True, timeout=8)
h = json.loads(helper.stdout)
if h.get('ok') is not True or h.get('active') is not False or h.get('cleanupPending') is not False:
    raise SystemExit('HELPER_NOT_CLEAN')
host, ip, state = trust.official_info()
if state != 'Idle':
    raise SystemExit('OFFICIAL_NOT_IDLE')
receipt = json.loads((trust.DATA/'ssl-site.json').read_text())
if receipt['site'] != host or receipt['ip'] != ip:
    raise SystemExit('SAVED_SITE_OR_PIN_CHANGED')
ip = str(ipaddress.IPv4Address(ip))

def discovery():
    p = subprocess.run(['/usr/bin/openssl', 's_client', '-connect', ip+':443', '-servername', host, '-showcerts'],
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
    chain = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', p.stdout, re.S)
    if not 2 <= len(chain) <= 8:
        raise trust.Refused('GATEWAY_CHAIN_INCOMPLETE')
    return chain

with tempfile.TemporaryDirectory(prefix='cvr-sequence-') as tmp:
    trace.set_phase('sequence_A1_discovery')
    with trace.step('public_chain'):
        chain = discovery()
    leaf = Path(tmp)/'leaf'; leaf.write_bytes(chain[0])
    decoded = ssl._ssl._test_decode_cert(str(leaf))
    names = [v for group in decoded['subject'] for k, v in group if k == 'commonName']
    if names != [receipt['cn']] or ('IP Address', ip) not in decoded['subjectAltName']:
        raise SystemExit('SITE_SAN_MISMATCH')
    der = ssl.PEM_cert_to_DER_cert(chain[-1].decode())
    if hashlib.sha256(der).hexdigest() != receipt['ca_sha256']:
        raise SystemExit('CA_SHA256_PIN_MISMATCH')
    trust.accepted(receipt['cn'], trust.fingerprint(der))
    ca = Path(tmp)/'ca'; ca.write_bytes(chain[-1])
    context = trust.pinned_context(ca, receipt['ca_sha256'])
    for phase in ('sequence_B1_strict', 'sequence_B2_strict', 'sequence_A2_discovery'):
        if phase == 'sequence_B2_strict':
            time.sleep(15)  # No retry; separates the two explicitly ordered pairs.
        trace.set_phase(phase)
        try:
            with trace.step('connection'):
                if phase == 'sequence_A2_discovery':
                    if discovery() != chain:
                        raise trust.Refused('GATEWAY_CHANGED')
                else:
                    with socket.create_connection((ip, 443), timeout=10) as raw:
                        with context.wrap_socket(raw, server_hostname=ip) as tls:
                            if tls.getpeercert(binary_form=True) != ssl.PEM_cert_to_DER_cert(chain[0].decode()):
                                raise trust.Refused('GATEWAY_CHANGED')
        except (TimeoutError, ConnectionRefusedError):
            pass  # Retain a transport outcome and execute the other planned cell.
print('Four planned cells finished. Metadata only:', output)
