"""No production writes: reject an older installer and a different launch source."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile

app = Path(sys.argv[1]).resolve()
exe = app / "Contents/MacOS/CorporateVPNRouter"
with tempfile.TemporaryDirectory(prefix="cvr-launch-source-", dir="/private/tmp") as temporary:
    home = Path(temporary) / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), CFFIXED_USER_HOME=str(home))
    def run(*args, check=True):
        return subprocess.run(list(map(str, args)), env=env, text=True,
                              capture_output=True, check=check, timeout=90)
    assert Path(run(exe, "--installation-home").stdout.strip()).resolve() == home.resolve()
    run(exe, "--install")
    installed = home / "Applications" / app.name
    info = installed / "Contents/Info.plist"
    value = plistlib.loads(info.read_bytes())
    value["CFBundleVersion"] = "999999"
    info.write_bytes(plistlib.dumps(value))
    run("codesign", "--force", "--sign", "-", "--timestamp=none", installed)
    for mode, message in [("--install", "устаревшая копия"), ("--login", "другая копия")]:
        result = run(exe, mode, check=False)
        assert result.returncode and message in result.stderr, result.stderr
        assert plistlib.loads(info.read_bytes())["CFBundleVersion"] == "999999"
print("PASS downgrade refused; different launch source cannot overwrite existing installation")
