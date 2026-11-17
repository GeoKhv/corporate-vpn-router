"""Compare one connected native site with a TLS certificate. Diagnostic only."""
import ipaddress
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile


class ProbeError(Exception):
    pass


def run(args, timeout=10):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout)


def connected_gateway(output, trust):
    rows = trust.parse_sites(output)
    active = [row for row in rows.values() if row[2] != 'Idle']
    if not active:
        raise ProbeError('NO_CONNECTED_SITE')
    if len(active) != 1 or active[0][2] != 'Connected':
        raise ProbeError('NO_UNIQUE_CONNECTED_SITE')
    site, ip, _ = active[0]
    header = re.search(r'(?im)^[ \t]*Conn[ \t]+' + re.escape(site) + r':[ \t]*$', output)
    if not header:
        raise ProbeError('UNKNOWN_SITE_FORMAT')
    block = re.split(r'(?im)^[ \t]*Conn[ \t]+', output[header.end():], maxsplit=1)[0]
    lists = re.split(r'(?im)^[ \t]*gateway list:[ \t]*\n', block)
    entries = []
    if len(lists) == 2:
        for line in lists[1].splitlines():
            if not line.lstrip().startswith('('):
                break
            entry = re.fullmatch(r'[ \t]*\(([A-Za-z ]+)\)[ \t]+([A-Za-z0-9_.-]{1,253})[ \t]*', line)
            if not entry:
                entries = []
                break
            entries.append(entry.groups())
    return site, ip, tuple(sorted(entries))


def official(trust):
    trac = trust.CP / 'trac'
    trust.owned(trac)
    vendor = 'anchor apple generic and certificate leaf[subject.OU] = "TZ3UEPFYKD" and identifier "trac"'
    if run(['/usr/bin/codesign', '--verify', '--strict', '-R=' + vendor, str(trac)], 12).returncode:
        raise ProbeError('OFFICIAL_SIGNATURE_UNCONFIRMED')
    result = run([str(trac), 'info'])
    if result.returncode:
        raise ProbeError('OFFICIAL_INFO_UNAVAILABLE')
    return connected_gateway(result.stdout.decode(errors='replace').replace('\r\n', '\n'), trust)


def matching_name(name, cn):
    return cn.casefold() in (name.casefold(), name.casefold() + ' vpn certificate')


def compare(site, ip, entries, chain, trust):
    with tempfile.TemporaryDirectory() as directory:
        leaf = Path(directory) / 'leaf.pem'
        leaf.write_bytes(chain[0])
        cert = ssl._ssl._test_decode_cert(str(leaf))
        names = [value for group in cert['subject'] for key, value in group if key == 'commonName']
        if len(names) != 1:
            raise ProbeError('UNRECOGNIZED_CERTIFICATE_NAME')
        cn = names[0]
        san = cert.get('subjectAltName', ())
        dns_names = [value.lower() for kind, value in san if kind == 'DNS']
        if site in dns_names or '*.' + site.partition('.')[2] in dns_names:
            reference = 'domain'
        elif ('IP Address', ip) in san:
            reference = 'gateway_ip'
        else:
            reference = 'neither'
        active = [name for status, name in entries if status == 'Connected']
        object_match = 'unavailable'
        if len(active) == 1:
            object_match = 'match' if matching_name(active[0], cn) else 'different'
        in_list = 'unavailable'
        if entries:
            in_list = 'match' if any(matching_name(name, cn) for _, name in entries) else 'different'

        ca_pin = 'unavailable'
        chain_status = 'unavailable'
        if len(chain) >= 2:
            anchor = Path(directory) / 'ca.pem'
            anchor.write_bytes(chain[-1])
            try:
                trust.accepted(cn, trust.fingerprint(ssl.PEM_cert_to_DER_cert(chain[-1].decode())))
                ca_pin = 'match'
            except trust.Refused as exc:
                ca_pin = 'different' if str(exc) == 'OFFICIAL_PIN_MISMATCH' else 'unavailable'
            except OSError:
                pass  # The native registry can be absent or inaccessible.
            # A separate, offline chain check. Only the reported pin comparison
            # associates this CA with a native registry entry.
            command = ['/usr/bin/openssl', 'verify', '-purpose', 'sslserver',
                       '-CAfile', str(anchor), '-CApath', directory]
            if len(chain) > 2:
                intermediates = Path(directory) / 'intermediates.pem'
                intermediates.write_bytes(b'\n'.join(chain[1:-1]))
                command.extend(['-untrusted', str(intermediates)])
            chain_status = 'valid' if run([*command, str(leaf)]).returncode == 0 else 'invalid'
    return (f'tls_name={reference} active_object={object_match} site_list={in_list} '
            f'official_ca={ca_pin} chain={chain_status}')


def probe(trust):
    snapshot = official(trust)
    site, ip, entries = snapshot
    # Reach only the site's endpoint already reported by the native client.
    if ip not in {row[4][0] for row in socket.getaddrinfo(site, 443, socket.AF_INET, socket.SOCK_STREAM)}:
        raise ProbeError('SITE_DNS_DIFFERS')
    endpoint = str(ipaddress.IPv4Address(ip)) + ':443'
    result = run(['/usr/bin/openssl', 's_client', '-connect', endpoint, '-servername', site, '-showcerts'], 12)
    chain = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', result.stdout, re.S)
    if not 1 <= len(chain) <= 8:
        raise ProbeError('TLS_CHAIN_UNAVAILABLE')
    report = compare(site, ip, entries, chain, trust)
    if official(trust) != snapshot:
        raise ProbeError('CONNECTION_CHANGED')
    return report


def main(engine):
    sys.path.insert(0, str(engine))
    import trust
    print('Проверка подключённого сайта Check Point. VPN и настройки сети остаются под управлением macOS.', flush=True)
    try:
        if not hasattr(trust, 'parse_sites'):
            raise ProbeError('ROUTER_0_3_7_REQUIRED')
        report = probe(trust)
    except ProbeError as exc:
        report = str(exc)
    except trust.Refused:
        report = 'OFFICIAL_DATA_UNAVAILABLE'
    except subprocess.TimeoutExpired:
        report = 'TIMED_OUT'
    except socket.gaierror:
        report = 'DNS_UNAVAILABLE'
    except (OSError, ValueError):
        report = 'PROBE_UNAVAILABLE'
    print('GW-CHECK ' + report)
    if report == 'NO_CONNECTED_SITE':
        print('Подключитесь к своему рабочему сайту в штатном Check Point и повторите проверку.')
    elif report == 'ROUTER_0_3_7_REQUIRED':
        print('Для проверки нужна установленная версия Router 0.3.7 или новее.')


if __name__ == '__main__':
    main(Path(sys.argv[1]))
