"""Run the shipped exporter exactly as the GUI does, including isolated Python."""
import json
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile

app = Path(sys.argv[1]).resolve()
res = app / 'Contents/Resources'
with tempfile.TemporaryDirectory(prefix='cvr-report-cli-', dir='/private/tmp') as folder:
    output = Path(folder) / 'Отчёт Router with spaces.txt'
    command = [str(res/'Runtime/bin/python3.13'), '-I', '-B',
               str(res/'Engine/support_report.py'), str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=folder)
    assert result.returncode == 0, (result.returncode, result.stderr)
    text = output.read_text()
    version = plistlib.loads((app/'Contents/Info.plist').read_bytes())['CFBundleShortVersionString']
    assert text.startswith('# Corporate VPN Router')
    assert '"version": "'+version+'"' in text
    assert '## Попытки подключения' in text and '## Трассировки соединений' in text
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    # The save panel may approve replacing an existing export.
    again = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=folder)
    assert again.returncode == 0, (again.returncode, again.stderr)
    assert output.read_text().startswith('# Corporate VPN Router')
print('PASS packaged exporter: isolated interpreter, report sections, Unicode/spaces, private permissions and replacement')
