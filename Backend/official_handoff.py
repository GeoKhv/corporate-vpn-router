"""One explicit handoff from the signed official client. No service management."""
import socket
import subprocess
import time
from trust import CP, Refused, official_info


def prepare(request, browser=True):
    _, _, state = official_info()
    if request('check_official_gui', '', check_port=browser) != 'available':
        raise Refused('BROWSER_LOCAL_UNAVAILABLE' if browser else 'OFFICIAL_GUI_HANDOFF_FAILED')
    if state != 'Idle':
        if state not in ('Connected', 'Connecting', 'Reconnecting'):
            raise Refused('OFFICIAL_STATE_UNKNOWN')
        if request('switch_official', 'Официальный VPN активен. Отключить его и подключить Router?') != 'accept':
            raise Refused('INPUT_CANCELLED')
        # Revalidate the official executable and status before its disconnect.
        official_info()
        result = subprocess.run([str(CP/'trac'), 'disconnect'], capture_output=True, timeout=12)
        if result.returncode:
            raise Refused('OFFICIAL_DISCONNECT_FAILED')
        deadline = time.monotonic()+15
        while official_info()[2] != 'Idle':
            if time.monotonic() >= deadline:
                raise Refused('OFFICIAL_DISCONNECT_FAILED')
            time.sleep(.25)
    if request('close_official_gui', '', check_port=browser) != 'closed':
        raise Refused('OFFICIAL_GUI_HANDOFF_FAILED')
    # Exclusive bind checks availability. The browser handler binds again before
    # issuing UserPass, refusing any intervening contender.
    if not browser:
        return
    try:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1',7779))
    except OSError as error:
        raise Refused('BROWSER_PORT_UNAVAILABLE') from error
    if official_info()[2] != 'Idle':
        raise Refused('OFFICIAL_VPN_NOT_IDLE')
