"""Generate a one-name private sing-box config, without starting it."""
import json
from pathlib import Path
import secrets
import sys

directory = Path(sys.argv[1]).resolve()
cfg = json.loads((directory / 'trial-input.json').read_text())
cfg.setdefault('password', secrets.token_hex(24))
(directory / 'trial-input.json').write_text(json.dumps(cfg, indent=2))
(directory / 'trial-input.json').chmod(0o600)
config = {
    'log': {'level': 'debug', 'timestamp': True},
    'inbounds': [{'type': 'tun', 'tag': 'one-name', 'interface_name': 'utun73',
                  'address': ['198.18.73.1/32', 'fdc7:7652:9a10::1/128'],
                  'mtu': 1500, 'auto_route': False, 'dns_mode': 'disabled', 'stack': 'gvisor'}],
    'outbounds': [{'type': 'socks', 'tag': 'verified-work', 'server': '127.0.0.1',
                   'server_port': cfg['socks_port'], 'version': '5',
                   'username': 'trial', 'password': cfg['password']}],
    'route': {'rules': [
        {'inbound': ['one-name'], 'ip_cidr': [cfg['ipv4']+'/32', cfg['ipv6']+'/128'],
         'network': 'tcp', 'port': [443], 'action': 'route',
         'override_address': cfg['host'], 'outbound': 'verified-work'},
        {'action': 'reject', 'no_drop': True}
    ]}
}
(directory / 'sing-box.json').write_text(json.dumps(config, indent=2))
(directory / 'sing-box.json').chmod(0o600)
print('Generated one-name TUN configuration: no automatic routes, native DNS or direct outbound')
