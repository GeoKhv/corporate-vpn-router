#!/usr/bin/env python3
"""Own the packet-only child and rebuild its pre-DNS gate on a policy change."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from policy_control import bind_control, SOCKS_CONTROL
from sites import gate


def main():
    lifetime_fd = int(sys.argv[1])
    packet_fd = int(os.environ['VPNFD'])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1090
    if port in (1088, 1089):
        raise RuntimeError('PROTECTED_PORT')
    data = Path.home() / 'Library/Application Support/Corporate VPN Router'
    os.chdir(data)
    policy = Path('work-sites.json')
    child = None
    current = None
    verified_pid = None

    def stop_child():
        nonlocal child, verified_pid
        verified_pid = None
        if child is None:
            return
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        child = None

    def reload_policy():
        nonlocal child, current
        try:
            new = gate(json.loads(policy.read_bytes()))
        except (KeyError, ValueError, TypeError, OSError):
            stop_child()
            current = None
            return False
        if new != current:
            stop_child()
            env = dict(os.environ, CVR_DOMAINS=new[0], CVR_PORTS=new[1])
            child = subprocess.Popen([ROOT/'ocproxy', '-D', '127.0.0.1:%d' % port],
                                     pass_fds=(packet_fd,), env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            current = new
        return True

    def owner():
        nonlocal verified_pid
        if child is None or child.poll() is not None:
            return b'0'
        if verified_pid != child.pid:
            proc = subprocess.run(['/usr/sbin/lsof','-nP','-a','-p',str(child.pid),
                                   '-iTCP@127.0.0.1:'+str(port),'-sTCP:LISTEN','-Fp'],
                                  capture_output=True,timeout=3)
            if [line for line in proc.stdout.splitlines() if line.startswith(b'p')] != [b'p'+str(child.pid).encode()]:
                return b'0'
            verified_pid = child.pid
        return str(verified_pid).encode()

    def stop(_signal, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    control = bind_control(SOCKS_CONTROL)
    try:
        while child is None or child.poll() is None:
            reload_policy()
            ready, _, _ = select.select([lifetime_fd, control], [], [], .2)
            if lifetime_fd in ready and not os.read(lifetime_fd, 1):
                break
            if control in ready:
                with control.accept()[0] as client:
                    try:
                        client.settimeout(.5)
                        command = client.recv(1)
                        if command == b'P':
                            client.sendall(owner())
                        elif command == b'S':
                            client.sendall(b'1' if reload_policy() else b'0')
                    except (OSError, subprocess.TimeoutExpired):
                        pass
    finally:
        control.close()
        stop_child()
        os.close(lifetime_fd)
        os.close(packet_fd)


if __name__ == '__main__':
    main()
