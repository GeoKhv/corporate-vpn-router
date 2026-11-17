"""Report an enrolled alternate gateway or verify it with the connected native client."""
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile


class Unavailable(Exception):
    pass


def public_fields(receipt):
    from sites import hostname
    if not isinstance(receipt, dict) or not hostname(receipt.get('site')):
        raise Unavailable('INVALID_BINDING')
    pins = {}
    for k in ('leaf_sha256', 'ca_sha256'):
        value = receipt.get(k)
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
            raise Unavailable('MISSING_CERTIFICATE_HASH')
        pins[k] = value
    return dict(site=receipt['site'], **pins)


def connected_site(trust):
    output = trust.official_output()
    active = [row for row in trust.parse_sites(output).values() if row[2] != 'Idle']
    if not active:
        raise Unavailable('CONNECT_ASSIGNED_SITE')
    if len(active) != 1 or active[0][2] != 'Connected':
        raise Unavailable('NO_UNIQUE_CONNECTED_SITE')
    return active[0], output


def export(trust):
    primary = trust.approved_receipt()
    if not primary:
        raise Unavailable('STARTER_REQUIRED')
    path = trust.DATA / 'official-alternate-binding.json'
    if path.is_file():
        proof = json.loads(path.read_bytes())
        if not isinstance(proof, dict) or proof.get('primary') != primary:
            raise Unavailable('INVALID_BINDING')
        pins = public_fields(proof.get('alternate'))
        if pins['site'] == primary['site']:
            raise Unavailable('INVALID_BINDING')
        return 'saved', pins

    if not hasattr(trust, 'connected_object'):
        raise Unavailable('ROUTER_0_3_8_REQUIRED')
    initial, _ = connected_site(trust)
    host, ip, _ = initial
    if host == primary['site']:
        raise Unavailable('CONNECT_ASSIGNED_SITE')

    class VerifiedForReview(Exception):
        pass

    def stop_before_enrollment(receipt):
        # anchor offers this callback only after validating the registered CA
        # and completing its pinned TLS handshake; stop before it saves consent.
        raise VerifiedForReview(receipt)

    original = trust.DATA
    with tempfile.TemporaryDirectory() as temp:
        trust.DATA = Path(temp)
        try:
            try:
                trust.anchor(stop_before_enrollment, require_idle=False)
            except VerifiedForReview as review:
                receipt = review.args[0]
            else:
                raise Unavailable('NO_NEW_NATIVE_PROOF')
            current, output = connected_site(trust)
            if current != initial or (receipt.get('site'), receipt.get('ip')) != (host, ip):
                raise Unavailable('CONNECTION_CHANGED')
            if receipt.get('ca_sha256') != primary['ca_sha256']:
                raise Unavailable('ALTERNATE_CA_NOT_CONFIRMED')
            if trust.connected_object(output, host) != receipt.get('gateway_object'):
                raise Unavailable('OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED')
            return 'connected', public_fields(receipt)
        finally:
            trust.DATA = original


def deadline(_signum, _frame):
    raise Unavailable('TIMED_OUT')


def main(engine):
    sys.path.insert(0, str(engine))
    try:
        import trust
    except ImportError:
        return 'GW-RESULT ROUTER_0_3_8_REQUIRED'
    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(65)
        source, pins = export(trust)
        return '\n'.join(['GW-RESULT OK ' + source, *(k + '=' + v for k, v in pins.items())])
    except (Unavailable, trust.Refused) as exc:
        code = str(exc)
        return 'GW-RESULT ' + (code if re.fullmatch('[A-Z0-9_]{1,70}', code) else 'CHECK_FAILED')
    except (subprocess.TimeoutExpired, TimeoutError):
        return 'GW-RESULT TIMED_OUT'
    except ssl.SSLError:
        return 'GW-RESULT TLS_VERIFICATION_FAILED'
    except socket.gaierror:
        return 'GW-RESULT DNS_UNAVAILABLE'
    except (OSError, ValueError, TypeError, KeyError):
        return 'GW-RESULT DATA_UNAVAILABLE'
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    os.umask(0o077)
    print(main(Path(sys.argv[1])))
