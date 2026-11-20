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


if __name__ == '__main__':
    try:
        print(confirmed(sys.argv[1]))
    except (OSError, ValueError, subprocess.SubprocessError):
        print('inconclusive')
