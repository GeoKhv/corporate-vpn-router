"""A successful save is a barrier for both the HTTP router and an active SOCKS worker."""
import os
import socket
from pathlib import Path

HTTP_CONTROL = 'http-router.sock'
SOCKS_CONTROL = 'socks-worker.sock'


def bind_control(name):
    # The service lifetime lock must already be held. Relative addresses fit sun_path
    # even when the user's home path is long.
    Path(name).unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(name)
    os.chmod(name, 0o600)
    listener.listen(4)
    return listener


def synchronize(name, required=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(6)
        try:
            client.connect(name)
        except (ConnectionRefusedError, FileNotFoundError):
            if required:
                raise
            return
        client.sendall(b'S')
        if client.recv(1) != b'1':
            raise OSError('policy reload failed')
