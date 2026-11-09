"""Check Point external browser challenge. Keep URLs and proof in memory only."""
import http.client
import http.server
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from cpyvpn import auth, utils
from cpyvpn.cfg import CPRR
from trust import Refused
from chrome_peer import signed_chrome_peer


def browser_origin(url, site, address):
    parts = urlsplit(url)
    if (parts.scheme != 'https' or parts.hostname not in (site, address)
            or parts.port not in (None, 443) or parts.username is not None
            or parts.password is not None or parts.fragment
            or not parts.path.startswith('/saml-vpn/') or not parts.query
            or any(ord(c) < 33 or ord(c) == 127 for c in url)):
        raise Refused('UNEXPECTED_BROWSER_CHALLENGE')
    return 'https://' + parts.netloc


def single_tab_url(url, address, context):
    parts = urlsplit(url)
    if not parts.path.endswith('/ServiceProviderTabs'):
        return url
    # This gateway's launcher repeatedly opens popups. Follow only the exact
    # same-origin continuation explicitly advertised for THIS session. Do not
    # follow redirects, send cookies or accept a different transaction.
    connection = http.client.HTTPSConnection(address, 443, context=context, timeout=10)
    try:
        connection.request('GET', parts.path + '?' + parts.query, headers={'Host':parts.netloc})
        response = connection.getresponse()
        if response.status != 200:
            return url
        body = response.read(128 * 1024).decode('utf8', 'replace')
    finally:
        connection.close()
    target = re.search(r"""var target_location\s*=\s*'ServiceProvider\?'\s*\+\s*["']([^"']+)["']""", body)
    if target and target[1] == parts.query:
        return urljoin(url, 'ServiceProvider?' + parts.query)
    return url


class Callback(http.server.HTTPServer):
    # Rebind after a previous callback in TIME_WAIT; never set SO_REUSEPORT.
    allow_reuse_address = True
    def get_request(self):
        conn, peer = super().get_request()
        conn.settimeout(2)
        return conn, peer

    def handle_error(self, request, client_address):
        pass

    def wait(self):
        self.timeout = 1
        until = time.monotonic() + 180
        while self.proof is None:
            if time.monotonic() >= until:
                raise Refused('BROWSER_TIMEOUT')
            self.handle_request()
        return self.proof


class ReturnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, code, cors=False):
        self.send_response(code)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', '0')
        if cors:
            self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin') or self.server.origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()

    def handle_return(self):
        if self.headers.get('Host') not in ('127.0.0.1:7779', 'localhost:7779'):
            self.server.report('browser_host_refused')
            self.reply(403)
            return
        origin = self.headers.get('Origin')
        ref = urlsplit(self.headers.get('Referer', ''))
        referer_origin = (ref.scheme + '://' + ref.netloc) if ref.netloc else None
        if ((origin not in (None, 'null', self.server.origin))
                or (referer_origin and referer_origin != self.server.origin)):
            self.server.report('browser_origin_refused')
            self.reply(403)
            return
        if origin != self.server.origin and referer_origin != self.server.origin:
            if not signed_chrome_peer(self.client_address[1], self.server.browser):
                self.server.report('browser_peer_refused')
                self.reply(403)
                return
        # A browser process or HTTP header is never authentication. Only the
        # gateway can redeem this proof for the pending CCC auth_session_id.
        if not re.fullmatch(r'/[a-zA-Z0-9_.~%-]{1,2048}', self.path):
            self.server.report('browser_format_refused')
            self.reply(400)
            return
        if self.command == 'OPTIONS':
            self.server.report('browser_preflight')
        self.reply(204, True)
        if self.command == 'GET':
            self.server.proof = self.path[1:]

    do_GET = handle_return
    do_OPTIONS = handle_return


def authenticate(session, realm, site, address, context, launch, status):
    # Reserve the exclusive, vendor-defined return port BEFORE issuing any
    # request. A busy official GUI must never receive our attempt's response.
    try:
        listener = Callback(('127.0.0.1', 7779), ReturnHandler)
    except OSError as exc:
        raise Refused('BROWSER_PORT_UNAVAILABLE') from exc
    helper = auth.AuthHelper(('TRAC', 'Darwin'), realm=realm, url=address)
    session.auth_obj = helper
    session.use_ma = False
    with listener:
        def post(kind, values, sid=''):
            req = {'RequestHeader': {'id': 2, 'type': kind, 'session_id': sid},
                   'RequestData': values}
            return utils.do_ccc_request(address + '/clients/', data=CPRR(
                {'CCCclientRequest': req}).serialize()[:-1]).find('ResponseData')

        values = helper._make_req_data()
        values.update(username='', password='')
        data = post('UserPass', values)
        sid = data.get('session_id', '')
        if data.get('authn_status') != 'continue' or not re.fullmatch(r'[\w.:-]{1,256}', sid):
            raise Refused('NO_BROWSER_CHALLENGE')
        url = auth.dec(data.get('prompt', ''))
        listener.origin = browser_origin(url, site, address)
        listener.proof = None
        listener.report = status
        handler = launch(single_tab_url(url, address, context))
        listener.browser = Path(handler) if handler else None
        proof = listener.wait()
    status('browser_returned')
    data = post('MultiChallange', {'client_type': 'TRAC', 'auth_session_id': sid,
                                    'user_input': auth.enc(proof)}, sid)
    if (data.get('authn_status') != 'done' or data.get('is_authenticated') != 'true'
            or not data.get('active_key') or not data.get('session_id')):
        raise Refused('BROWSER_PROOF_REJECTED')
    helper.sid = data['session_id']
    session.cookie = auth.dec(data['active_key'])
    username = data.get('username')
    if isinstance(username, str) and 0 < len(username) <= 256 and username.isprintable():
        return username
