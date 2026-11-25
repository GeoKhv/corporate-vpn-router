"""Clean-Mac enrollment and signed native site record compatibility."""
import asyncio
import json
import socket
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

engine = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(engine), str(engine/'Selective')]
import controller
import official_handoff
import trust

primary, other = 'first.example.invalid', 'second.example.invalid'
ip, ip2 = '192.0.2.4', '192.0.2.5'
addresses = {primary: {ip}, other: {ip2}}
def native(label, gateway, status='Connected'):
    field = '' if gateway is None else f' gw: {gateway}\r\n'
    return f'Conn {label}:\r\n{field} status: {status}\r\n gateway list:\r\n  ({status}) Object\r\n'

def refused(raw, reason):
    try:
        trust.parse_sites(raw)
    except trust.Refused as error:
        assert str(error) == reason, (error, reason)
    else:
        raise AssertionError(reason)

with tempfile.TemporaryDirectory() as temp, patch.object(trust, 'approved_receipt', return_value={'site':primary}), \
        patch.object(trust, 'approved_site_pin', return_value={'site':other}), \
        patch.object(trust, 'gateway_ipv4', side_effect=lambda name, deadline: addresses[name]), \
        patch.object(trust,'DATA',Path(temp)), patch.object(controller,'DATA',Path(temp)):
    for label, gw in [('Work VPN', ip), (ip,ip), ('Work VPN', primary), (primary+'.',ip),
                      (primary,'::ffff:'+ip), (primary,primary), (primary,ip+':443'),
                      ('Work VPN',primary+':443'), (primary,'[::ffff:'+ip+']:443'),
                      ('Work VPN',primary+' ('+ip+')')]:
        raw = native(label, gw)
        with patch.object(trust, 'official_output', return_value=raw):
            assert trust.official_info() == (primary,ip,'Connected')
            assert asyncio.run(controller.connection_site()) == (primary,ip,'Connected')
            def decline(kind, *args, **kwargs):
                return 'available' if kind == 'check_official_gui' else 'cancel'
            with patch.object(official_handoff.subprocess, 'run') as vendor_action:
                try: official_handoff.prepare(decline, browser=False)
                except trust.Refused as error: assert str(error) == 'INPUT_CANCELLED'
                else: raise AssertionError('active official client handed off without consent')
                vendor_action.assert_not_called()
        assert trust.connected_object(raw, primary) == 'Object'
    assert list(trust.parse_sites(native(primary,None,'Idle')).values()) == [(primary,ip,'Idle')]
    refused(native(primary,None),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    assert trust.parse_sites(native(primary,ip).replace(primary+':',primary))[primary][1]==ip
    refused(native(primary,ip+':444'),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    refused(native(primary,primary+' ('+ip2+')'),'SITE_ADDRESS_MISMATCH')
    refused(native('foreign.example.invalid',None,'Idle'),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    refused(native('Work VPN','192.0.2.99'),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    refused(native(ip2,ip),'SITE_ADDRESS_MISMATCH')
    refused(native(primary,ip) + native('Work VPN',ip),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    refused(native(primary,ip).replace(' status:',f' gw: {ip2}\n status:'),'OFFICIAL_SITE_FORMAT_UNSUPPORTED')
    with patch.dict(addresses,{other:{ip}}):
        refused(native('Work VPN',ip),'OFFICIAL_SITE_AMBIGUOUS')
    raw = native('first label',ip,'Idle').replace(' gateway list:', ' active site: false\n gateway list:') + native('second label',ip2,'Idle').replace(' gateway list:', ' active site: true\n gateway list:')
    assert trust.choose_site(trust.parse_sites(raw),raw) == (other,ip2,'Idle')
    # An idle DNS endpoint is irrelevant to the authenticated selection, whichever row comes first.
    active = native(primary, primary+' ('+ip+')')
    idle = native(other, other, 'Idle')
    def active_dns(name, deadline):
        assert name == primary, 'looked up the unused endpoint'
        return {ip}
    with patch.object(trust, 'gateway_ipv4', side_effect=active_dns):
        for raw in (active+idle, idle+active):
            with patch.object(trust, 'official_output', return_value=raw):
                assert asyncio.run(controller.connection_site()) == (primary,ip,'Connected')
                assert trust.connected_object(raw, primary) == 'Object'
        saved = Path(temp)/'ssl-site.json'
        saved.write_text(json.dumps({'site':primary, 'ip':ip}))
        with patch.object(trust,'official_output',return_value=native(primary,primary,'Idle') + idle):
            assert trust.official_info() == (primary,ip,'Idle')
        saved.unlink()
    for gw in (primary, primary+':443', primary+' ('+ip+')'):
        raw = native(primary,gw,'Idle')
        again = socket.gaierror(socket.EAI_AGAIN, 'temporary')
        with patch.object(trust, 'GATEWAY_DNS_RETRY_DELAY', 0), \
                patch.object(trust,'gateway_ipv4',side_effect=[again,{ip},{ip}]) as lookup, \
                patch.object(trust,'official_output',return_value=raw) as read:
            assert trust.official_info() == (primary,ip,'Idle')
            assert lookup.call_count == 3 and read.call_count == 2
        with patch.object(trust, 'GATEWAY_DNS_RETRY_DELAY', 0), \
                patch.object(trust,'gateway_ipv4',side_effect=[again,{ip}]), \
                patch.object(trust,'official_output',side_effect=[raw,native(primary,ip2,'Idle')]):
            try: trust.official_info()
            except trust.Refused as error: assert str(error)=='OFFICIAL_SELECTION_CHANGED'
            else: raise AssertionError('native site changed during DNS retry')
    f = Path(temp)/'candidate'
    rule = {'version':1,'sites':[{'domain':'work.example.invalid','scope':'tree'}],'beforeLogin':[],'ports':[443]}
    f.write_text(json.dumps(rule))
    with patch.object(trust,'official_output',side_effect=AssertionError('enrollment read live VPN')):
        assert controller.check_profile(f,first_enrollment=True) == rule
        rule['sites'][0]['domain'] = primary
        f.write_text(json.dumps(rule))
        try: controller.check_profile(f, first_enrollment=True)
        except ValueError as err: assert 'Шлюз' in str(err)
        else: raise AssertionError('captured approved gateway')
print('PASS offline enrollment; canonical, labeled, DNS, mapped and idle gateways; reject ambiguous/conflicting native identity')
