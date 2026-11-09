"""Synthetic CCC and loopback callback tests. No browser profile data."""
import http.client
import threading
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
import browser_auth as flow
from trust import Refused


def refused(action, code):
    try: action()
    except Refused as error: assert str(error) == code
    else: raise AssertionError(code)


def check_listener(proof):
    server = flow.Callback(('127.0.0.1', 0), flow.ReturnHandler)
    server.proof, server.origin = None, 'https://gateway.invalid'
    server.report = lambda stage: None
    server.browser = None
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        port = server.server_port
        for method, path, host, origin, status in [
            ('GET','/sample','foreign.invalid','https://gateway.invalid',403),
            ('GET','/sample','127.0.0.1:7779','https://foreign.invalid',403),
            ('GET','/a/b','127.0.0.1:7779',server.origin,400),
            ('OPTIONS','/sample','127.0.0.1:7779',server.origin,204),
            ('GET','/'+proof,'127.0.0.1:7779',server.origin,204)]:
            conn = http.client.HTTPConnection('127.0.0.1',port)
            conn.request(method,path,headers={'Host':host,'Origin':origin})
            assert conn.getresponse().status == status
            conn.close()
            assert server.proof == (proof if method == 'GET' and status == 204 else None)
        for signed in [False, True]:
            server.proof = None
            with patch.object(flow, 'signed_chrome_peer', return_value=signed):
                conn = http.client.HTTPConnection('127.0.0.1', port)
                conn.request('GET', '/fixture', headers={'Host':'localhost:7779'})
                assert conn.getresponse().status == (204 if signed else 403)
                conn.close()
                assert server.proof == ('fixture' if signed else None)
    finally:
        server.shutdown(); worker.join(); server.server_close()


if __name__ == '__main__':
    url = 'https://gateway.invalid/saml-vpn/spPortal/ServiceProvider?session=fixture'
    assert flow.browser_origin(url, 'gateway.invalid', '127.0.0.1') == 'https://gateway.invalid'
    for bad in [url.replace('https:', 'http:'),url.replace('gateway.invalid','foreign.invalid'),
                url.replace('gateway.invalid','user@gateway.invalid'),url.replace('spPortal', '..') + '#foreign']:
        refused(lambda:flow.browser_origin(bad,'gateway.invalid','127.0.0.1'), 'UNEXPECTED_BROWSER_CHALLENGE')
    check_listener('fixture-proof')

    # Exercise the actual handshake, including its pending transaction ID.
    from cpyvpn import auth
    from cpyvpn.cfg import CPRR
    from unittest.mock import MagicMock
    gateway = MagicMock()
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.wait.return_value = 'fixture-proof'
    session = SimpleNamespace()
    requests = []
    success = True
    def ccc(_, data):
        req = CPRR(data).find('RequestData')
        if 'auth_session_id' in req:
            assert req['auth_session_id'] == 'pending' and auth.dec(req['user_input']) == 'fixture-proof'
            assert CPRR(data).find('RequestHeader')['session_id'] == 'pending'
            reply = {'username':'test-user','authn_status':'done','is_authenticated':'true' if success else 'false',
                     'active_key':auth.enc('fixture-key'), 'session_id':'authenticated'}
        else:
            assert req['selectedLoginOption'] == 'browser' and not req['username'] and not req['password']
            reply = {'authn_status':'continue','session_id':'pending','prompt':auth.enc(url)}
        requests.append(req)
        gateway.find.return_value = reply
        return gateway
    with patch.object(flow,'Callback',return_value=listener),patch.object(flow.utils,'do_ccc_request',ccc):
        run = lambda:flow.authenticate(session,{'id':'browser'},'gateway.invalid','127.0.0.1',None,
                                        lambda opened:None, lambda stage:None)
        assert run() == 'test-user'; assert session.cookie == 'fixture-key' and session.auth_obj.sid == 'authenticated'
        success = False
        refused(run,'BROWSER_PROOF_REJECTED')
    assert len(requests) == 4
    print('PASS callback host/origin and format, OPTIONS never consumes proof, exact pending session, gateway rejection.')
