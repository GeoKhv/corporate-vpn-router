"""Verify the shipped RED defaults against an approved RED, and WHITE isolation."""
import json
import plistlib
import sys
from pathlib import Path

from_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(from_root / 'Backend'))
from sites import allowed_tcp, matched_rule, validate


def resource(app, name):
    return app / 'Contents' / 'Resources' / name


def read(app, name):
    return json.loads(resource(app, name).read_bytes())


def main(red, white, approved_red):
    red_info, white_info = [plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                            for app in (red, white)]
    assert red_info['CVRDeploymentEdition'] == 'RED' and white_info['CVRDeploymentEdition'] == 'WHITE'
    for key in ('CFBundleVersion', 'CFBundleShortVersionString', 'SUPublicEDKey'):
        assert red_info[key] == white_info[key], key
    for info, channel in [(red_info, 'update-channel'), (white_info, 'update-channel-white')]:
        assert info['SUFeedURL'].endswith('/' + channel + '/appcast.xml')
    for name in ('DefaultDesktop.json', 'DefaultWorkSites.json', 'StarterHTTPSAliases.json', 'BundledTCPRule.json'):
        assert resource(red, name).is_file() and not resource(white, name).exists(), name

    desktop = read(approved_red, 'DefaultDesktop.json')['desktop']
    assert read(red, 'DefaultDesktop.json')['desktop'] == desktop
    profile = validate(read(red, 'DefaultWorkSites.json'))
    assert allowed_tcp(profile, desktop, 3389, desktop)
    aliases = read(red, 'StarterHTTPSAliases.json')
    reference = read(approved_red, 'StarterHTTPSAliases.json')
    for key, short_name in [('httpEntryHost', 'superset'), ('additionalHTTPEntryHost', 'ametrica')]:
        host = aliases[key]
        assert host == reference[key] and host in aliases['hosts'] and host.split('.')[0] == short_name, key
    assert aliases['retiredTreeHost'] == reference['retiredTreeHost']
    assert matched_rule(profile, aliases['retiredTreeHost']) is None
    print('PASS RED deployment desktop, VDI system route, both HTTP aliases, WHITE isolation and channel identity')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit('usage: test_release_profiles.py RED.app WHITE.app approved-RED.app')
    main(*(Path(arg) for arg in sys.argv[1:]))
