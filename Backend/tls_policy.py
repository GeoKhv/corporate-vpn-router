"""Process-local pinned CA and strict cpyvpn control TLS. No fallback/CA fetch."""
import hashlib
import http.client
from pathlib import Path
import socket
import ssl
from urllib.parse import urlsplit

_control_channel = None


def close_control():
    if _control_channel is not None:
        _control_channel.close()


def pinned_context(ca_file, expected_sha256):
    der = ssl.PEM_cert_to_DER_cert(Path(ca_file).read_text())
    if hashlib.sha256(der).hexdigest() != expected_sha256:
        raise RuntimeError('CA_SHA256_PIN_MISMATCH')
    # A single fixed verification policy, compatible with installed corporate CAs.
    # No system roots, CERT_NONE, retry, or verification-error exception.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=der)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.has_user_cert = False
    require_strict(context)
    return context


def require_strict(context):
    if (not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED
            or context.minimum_version < ssl.TLSVersion.TLSv1_2):
        raise RuntimeError('TLS_POLICY_CHANGED')
    return context


def install(ssl_ctx, utils, address, context, resilient=False):
    global _control_channel
    close_control()
    _control_channel = None
    def strict_context():
        return require_strict(context)

    if resilient:
        from connection_resilience import ControlChannel
        _control_channel = ControlChannel(address, strict_context)
    channel = _control_channel

    def strict_mode(value):
        if value is not True:
            raise RuntimeError('PERMISSIVE_TLS_FORBIDDEN')

    def strict_check(host, port, nocert):
        if host != address or port != 443 or nocert:
            raise RuntimeError('UNEXPECTED_TLS_DESTINATION')
        if resilient:
            # This upstream hook chooses strict/permissive mode. The caller
            # already anchored the gateway; actual requests still perform
            # strict TLS. A throwaway TCP/TLS probe adds no trust guarantee.
            strict_context()
            return
        with socket.create_connection((address, 443), timeout=12) as raw:
            with strict_context().wrap_socket(raw, server_hostname=address):
                pass

    def strict_request(url, data=None, headers=None, with_cookies=False,
                       rawval=False, filter_data=False):
        parsed = urlsplit(url if url.startswith('https://') else 'https://' + url)
        if (parsed.scheme != 'https' or parsed.hostname != address
                or parsed.port not in (None, 443)
                or parsed.path not in ('/clients', '/clients/')
                or parsed.query or parsed.fragment or parsed.username is not None
                or parsed.password is not None or with_cookies):
            raise RuntimeError('UNEXPECTED_CONTROL_REQUEST')
        if channel is not None:
            return channel.request(parsed.path,data,rawval)
        connection = http.client.HTTPSConnection(address, 443,
            context=strict_context(), timeout=45)
        try:
            connection.request('POST', parsed.path, body=(data or '').encode('ascii'),
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Connection': 'close'})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError('CONTROL_HTTP_%d' % response.status)
            body = response.read(1024 * 1024)
            if len(body) >= 1024 * 1024:
                raise RuntimeError('OVERSIZED_CONTROL_RESPONSE')
            return body if rawval else body.decode('utf_8_sig')
        finally:
            connection.close()

    ssl_ctx.get_ssl_context = strict_context
    ssl_ctx.set_ssl_strict_mode = strict_mode
    ssl_ctx.check_ssl_mode = strict_check
    utils.do_https_request = strict_request
