"""Local-only untrusted TLS fixture. Ephemeral key is created by test.sh, never shipped."""
import socket
import ssl
import sys
from pathlib import Path

base = Path(sys.argv[1])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(str(base / 'server.pem'), str(base / 'leaf.key'))
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    (base / 'port').write_text(str(listener.getsockname()[1]))
    while True:
        client, _ = listener.accept()
        client.settimeout(5)
        try:
            with context.wrap_socket(client, server_side=True) as tls:
                data = tls.recv(4096)
                if data:
                    (base / 'unexpected-application-data').write_bytes(data)
        except (ssl.SSLError, OSError):
            client.close()
