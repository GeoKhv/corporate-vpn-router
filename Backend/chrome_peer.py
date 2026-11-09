"""Identify the macOS process on the other end of a live loopback callback."""
import ctypes
from pathlib import Path
import subprocess


def signed_chrome_peer(port, expected_browser):
    # Called only for a browser request without a usable HTTPS Origin/Referer.
    # Resolve BOTH ends of the established socket, then verify the client code.
    if not expected_browser or expected_browser.name != 'Google Chrome.app':
        return False
    peer = 'n127.0.0.1:%d->127.0.0.1:7779' % port
    def owner():
        result = subprocess.run(['/usr/sbin/lsof','-nP','-a','-iTCP:7779','-sTCP:ESTABLISHED','-Fpn'],
                                capture_output=True, timeout=4)
        pid = None
        for line in result.stdout.decode().splitlines():
            if line.startswith('p') and line[1:].isdigit():
                pid = int(line[1:])
            if pid and line == peer:
                return pid
        return None
    pid = owner()
    if not pid:
        return False
    buf = ctypes.create_string_buffer(4096)
    if ctypes.CDLL('/usr/lib/libproc.dylib').proc_pidpath(pid, buf, len(buf)) <= 0:
        return False
    path = Path(buf.value.decode()).resolve()
    if not path.is_relative_to(expected_browser.resolve()):
        return False
    requirement = ('anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV" and '
                   '(identifier "com.google.Chrome" or identifier "com.google.Chrome.helper")')
    verified = subprocess.run(['/usr/bin/codesign','--verify','--strict','-R='+requirement,str(path)],
                              capture_output=True,timeout=5)
    return verified.returncode == 0 and owner() == pid
