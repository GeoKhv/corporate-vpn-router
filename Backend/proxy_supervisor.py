#!/usr/bin/env python3
"""Terminate the packet-only SOCKS child on parent death, including SIGKILL."""
import os
from pathlib import Path
import select
import signal
import subprocess
import sys


def main():
    lifetime_fd = int(sys.argv[1])
    packet_fd = int(os.environ['VPNFD'])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1090
    if port in (1088, 1089):
        raise RuntimeError('PROTECTED_PORT')
    executable = Path(__file__).resolve().parent / 'ocproxy'
    child = subprocess.Popen([str(executable), '-D', '127.0.0.1:%d' % port],
                             pass_fds=(packet_fd,), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(packet_fd)
    def stop(_signal, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    try:
        while child.poll() is None:
            ready, _, _ = select.select([lifetime_fd], [], [], 0.5)
            if ready and not os.read(lifetime_fd, 1):
                break
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        os.close(lifetime_fd)


if __name__ == '__main__':
    main()
