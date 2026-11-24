"""Select the named native profile when a separate inactive entry is IPv4-only."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(engine), str(engine/'Selective')]
import controller
import official_handoff
import trust

host, address, old_ip = 'work.example.invalid', '192.0.2.40', '192.0.2.10'
def block(label, ip, state, active):
    return f'Conn {label}:\r\n gw: {ip}\r\n status: {state}\r\n active site: {active}\r\n gateway list:\r\n (Idle) Object\r\n'

inactive = block(old_ip, old_ip, 'Idle', 'false')
working = block(host, address, 'Connected', 'true')
idle = block(host, address, 'Idle', 'true')

with tempfile.TemporaryDirectory() as folder, \
        patch.object(trust, 'DATA', Path(folder)), \
        patch.object(trust, 'approved_receipt', return_value={'site': host}), \
        patch.object(trust, 'approved_site_pin', return_value=None), \
        patch.object(trust, 'gateway_ipv4', return_value={address}):
    for raw in [inactive+working, working+inactive]:
        with patch.object(trust,'official_output',return_value=raw):
            assert asyncio.run(controller.connection_site()) == (host,address,'Connected')
            assert trust.site(require_idle=False) == (host,address)
            assert len(trust.parse_sites(raw)) == 2
            try: trust.connected_object(raw,host)
            except trust.Refused as e: assert str(e)=='OFFICIAL_GATEWAY_OBJECT_UNCONFIRMED'
            else: raise AssertionError('invented a connected gateway object')
    changed = [inactive+working]
    def confirm(kind, *args, **kwargs):
        return {'check_official_gui':'available','switch_official':'accept','close_official_gui':'closed'}[kind]
    def disconnect(args, **kwargs):
        assert args == [str(trust.CP/'trac'),'disconnect']
        changed[0]=inactive+idle
        return type('Reply',(),{'returncode':0})()
    with patch.object(trust,'official_output',side_effect=lambda:changed[0]), \
            patch.object(official_handoff.subprocess,'run',side_effect=disconnect) as action, \
            patch.dict(os.environ,CVR_ATTEMPT_GATEWAY=host+'@'+address):
        official_handoff.prepare(confirm,browser=False)
        action.assert_called_once()
        assert trust.site() == (host,address)
    for raw in (inactive, inactive.replace('Idle','Connected')+working,
                inactive.replace('false','true')+working, inactive+working.replace('true','false'),
                inactive.replace('(Idle) Object','(Connected) Object')+working,
                inactive.replace('status: Idle','status: Idle\n status: Connected')+working,
                inactive+block('other.example.invalid','192.0.2.42','Connected','true')+working):
        with patch.object(trust,'official_output', return_value=raw):
            try: trust.official_info()
            except trust.Refused: pass
            else: raise AssertionError('accepted inconsistent or unbound native profile')
    (Path(folder)/'ssl-site.json').write_text(json.dumps({'site':'different.example.invalid','ip':address}))
    with patch.object(trust,'official_output',return_value=inactive+working):
        try: trust.official_info()
        except trust.Refused as e: assert str(e)=='SAVED_SITE_OR_PIN_CHANGED'
        else: raise AssertionError('overrode saved binding')
print('PASS numeric idle and named selected site, both orders, handoff and recheck; conflicting identities refused')
