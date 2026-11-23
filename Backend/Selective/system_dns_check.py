"""Compare a work site's Router DNS answer with the address visible to macOS."""
import ipaddress
import socket
import subprocess
import sys
import time


def router_addresses(host):
    addresses = set()
    for kind in ('A', 'AAAA'):
        result = subprocess.run(
            ['/usr/bin/dig', '@127.0.0.1', '-p', '53541', host + '.', kind,
             '+short', '+time=1', '+tries=1'], capture_output=True, text=True,
            check=True, timeout=3, env={'LC_ALL': 'C'})
        addresses.update(ipaddress.ip_address(line) for line in result.stdout.splitlines())
    return addresses


def system_addresses(host):
    return {ipaddress.ip_address(info[4][0]) for info in
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}


def check(host, router=router_addresses, system=system_addresses):
    expected = router(host)
    if not expected:
        return 'router_unavailable'
    try:
        actual = system(host)
    except socket.gaierror as error:
        if error.errno not in (socket.EAI_NONAME, socket.EAI_NODATA):
            return 'inconclusive'
        actual = set()
    if not actual:
        return 'missing'
    return 'ok' if actual <= expected else 'different'


def confirmed(host, probe=check, pause=time.sleep):
    first = probe(host)
    if first in ('missing', 'different'):
        pause(1)
        second = probe(host)
        return second if second == first or second == 'ok' else 'inconclusive'
    return first


def site_status(host):
    status = confirmed(host)
    if status != 'ok':
        return status
    # Pin the connection to an address that both resolvers currently agree on.
    # Keep the hostname for certificate verification and never follow a redirect.
    expected = router_addresses(host)
    actual = system_addresses(host)
    if not actual or not actual <= expected:
        return 'inconclusive'
    address = min(actual, key=lambda ip: (ip.version, int(ip)))
    literal = f'[{address}]' if address.version == 6 else str(address)
    result = subprocess.run(
        ['/usr/bin/curl', '-q', '--noproxy', '*', '--resolve', f'{host}:443:{literal}',
         '--head', '--silent', '--output', '/dev/null', '--write-out', '%{http_code}',
         '--connect-timeout', '4', '--max-time', '7', f'https://{host}/'],
        capture_output=True, text=True, timeout=8)
    if result.returncode == 0 and result.stdout.isdigit():
        return 'http:' + result.stdout
    return 'tls_error' if result.returncode in (35, 51, 60) else 'https_error'


if __name__ == '__main__':
    try:
        print(site_status(sys.argv[1]) if sys.argv[2:] == ['--https'] else confirmed(sys.argv[1]))
    except (OSError, ValueError, subprocess.SubprocessError):
        print('inconclusive')
