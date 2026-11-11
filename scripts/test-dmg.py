#!/usr/bin/env python3
"""Destructive only inside a disposable home. Never invokes real launchd jobs."""
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if os.getuid() == 0:
    raise SystemExit('Run as an ordinary user, never sudo.')
image = Path(sys.argv[1]).resolve()
scripts = Path(__file__).resolve().parent
sys.path.insert(0, str(scripts/'dmg'))
from metadata import DSStore, Alias
name = 'Corporate VPN Router.app'
old_cdhash = '06684ffbb00baba39f611a7d20c9c643791e893d'
cdhash = None

def run(*args, env=None, ok=True):
    result = subprocess.run([str(arg) for arg in args], env=env, capture_output=True, text=True, timeout=90)
    if ok and result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr}')
    return result

def inventory(path):
    return json.loads(run('/usr/bin/python3', scripts/'dmg/bundle-manifest.py', path).stdout)

def signature(path, vpn=False):
    args = ['--verify', '--deep', '--strict']
    if vpn:
        args += ['-R=cdhash H"' + cdhash + '"']
    run('/usr/bin/codesign', *args, path)

def snapshot(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob('*') if p.is_file()}

report = {}
run('/usr/bin/hdiutil', 'verify', image)
report['image_sha256'] = hashlib.sha256(image.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='cvr-dmg-test-', dir='/private/tmp') as temp:
    root = Path(temp)
    mount = root/'volume'; mount.mkdir()
    run('/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, image)
    process = None
    try:
        launcher = mount/'Установить Corporate VPN Router.app'
        target = launcher
        payload = launcher/'Contents/Resources/Payload'/name
        cdhash = run('/usr/bin/codesign', '-dvvv', payload, ok=False).stderr.split('CDHash=')[1].splitlines()[0]
        assert (payload/'Contents/Resources/INSTALLER_REVISION').read_text().strip() == 'installer-fix.1'
        for path in [launcher, payload]:
            signature(path, vpn=path == payload)
        manifest = json.loads((launcher/'Contents/Resources/Payload.manifest.json').read_text())
        assert inventory(payload) == manifest
        assert not (mount/'Applications').exists(), 'System-wide copy shortcut would duplicate beta.6'
        assert (mount/'.DS_Store').stat().st_size > 0
        with DSStore.open(str(mount/'.DS_Store'), 'r') as store:
            assert store['.']['icvp']['iconSize'] == 112.0
            assert store['.']['icvl'] == (b'type', b'icnv')
            alias = Alias.from_bytes(store['.']['icvp']['backgroundImageAlias'])
            assert os.fsdecode(alias.volume.posix_path) == '/Volumes/Corporate VPN Router beta.6'
            assert os.fsdecode(alias.target.posix_path) == '/.background/background.png'
            (root/'bookmark').write_bytes(store['.']['pBBk'].to_bytes())
        cache = scripts.parent/'.build/module-cache'
        cache.mkdir(parents=True, exist_ok=True)
        run('/usr/bin/xcrun', 'swiftc', '-module-cache-path', cache, scripts/'dmg/ResolveBookmark.swift', '-o', root/'resolve')
        resolved = run(root/'resolve', root/'bookmark').stdout.strip()
        assert Path(resolved).resolve() == (mount/'.background/background.png').resolve()
        report['portable_layout'] = 'PASS (native macOS bookmark resolves background after image relocation)'
        installer = target/'Contents/MacOS/DistributionInstaller'
        source_installer = launcher/'Contents/MacOS/DistributionInstaller'
        home = root/'home'; home.mkdir()
        env = {**os.environ, 'HOME': str(home), 'CFFIXED_USER_HOME': str(home)}
        # Fail closed if Foundation stops honoring the test-only home override.
        reported_home = Path(run(installer, '--home', env=env).stdout.strip())
        assert reported_home.resolve() == home.resolve(), 'Foundation home override failed; no installation attempted'
        home = reported_home  # Foundation can abbreviate /private/tmp as /tmp.
        installed = home/'Applications'/name
        data = home/'Library/Application Support/Corporate VPN Router'
        agent = home/'Library/LaunchAgents/com.geokhv.corporate-vpn-router.menu.plist'
        run(installer, '--install-only', env=env)
        assert inventory(installed) == manifest
        signature(installed, vpn=True)
        job = plistlib.loads(agent.read_bytes())
        executable = installed/'Contents/MacOS/CorporateVPNRouter'
        assert job['ProgramArguments'] == [str(executable), '--login']
        assert job['Label'] == 'com.geokhv.corporate-vpn-router.menu'
        assert not list(data.glob('rollback-*.app'))
        report['fresh_install'] = 'PASS (non-root, disposable home, exact fixed payload)'
        report['payload_cdhash'] = cdhash

        # Synthetic user data only; never copy the owner's actual corporate data.
        markers = {
            'work-sites.json': b'{"sites":[{"domain":"work.example.com","scope":"exact"}]}',
            'ssl-logins.json': b'{"synthetic-account":"keep"}',
            'router-profile-receipt.json': b'{"synthetic-receipt":"keep"}',
        }
        for key, value in markers.items():
            (data/key).write_bytes(value)
        before_agent = agent.read_bytes()
        process = subprocess.Popen([str(executable), '--login'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if (data/'ssl-status.json').exists(): break
            if process.poll() is not None: raise AssertionError('Published app did not stay running')
            time.sleep(0.1)
        status = json.loads((data/'ssl-status.json').read_text())
        assert status['connected'] is False and process.poll() is None
        assert run(executable, '--version', env=env).stdout.strip() == '0.2.0-beta.6'
        # Actual --login process holds the same production lock, not a fake lock.
        before = snapshot(home)
        refused = run(installer, '--install-only', env=env, ok=False)
        assert refused.returncode != 0 and 'VPN-сеанс сохранён' in refused.stderr
        assert snapshot(home) == before and process.poll() is None
        duplicate = run(executable, '--login', env=env)
        assert duplicate.returncode == 0 and process.poll() is None
        assert agent.read_bytes() == before_agent
        relocated = run(payload/'Contents/MacOS/CorporateVPNRouter', '--login', env=env)
        assert relocated.returncode == 0 and process.poll() is None
        assert agent.read_bytes() == before_agent
        assert not list(data.glob('rollback-*.app'))
        report['relocated_identity'] = 'PASS (same signed bundle at another path recognized without self-reinstallation)'
        report['launch_and_busy_refusal'] = 'PASS (actual beta.6 GUI startup, second instance exits, zero install writes while running)'
        process.terminate(); process.wait(timeout=10); process = None

        # Exercise the written login arguments through real launchd under a unique test label.
        login_test = plistlib.loads(before_agent)
        login_test['Label'] += '.installation-test.' + root.name
        login_test['EnvironmentVariables'] = {'HOME': str(home), 'CFFIXED_USER_HOME': str(home)}
        login_file = root/'login-test.plist'
        login_file.write_bytes(plistlib.dumps(login_test))
        service = 'gui/' + str(os.getuid()) + '/' + login_test['Label']
        try:
            run('/bin/launchctl', 'bootstrap', 'gui/' + str(os.getuid()), login_file)
            for _ in range(50):
                state = run('/bin/launchctl', 'print', service).stdout
                if 'state = running' in state: break
                time.sleep(0.1)
            assert 'state = running' in state
            refused = run(installer, '--install-only', env=env, ok=False)
            assert refused.returncode != 0 and 'VPN-сеанс сохранён' in refused.stderr
        finally:
            run('/bin/launchctl', 'bootout', service, ok=False)
        report['launchd_login'] = 'PASS (real Aqua launchd, unique disposable label, canonical executable with --login)'

        # Invalid launch-agent ownership must refuse an update without replacing files.
        agent.write_bytes(plistlib.dumps({'Label': 'example.foreign.agent', 'ProgramArguments': ['/usr/bin/false']}))
        before = snapshot(home)
        refused = run(installer, '--install-only', env=env, ok=False)
        assert refused.returncode != 0 and snapshot(home) == before
        agent.write_bytes(before_agent)
        report['foreign_login_agent_refusal'] = 'PASS (no bundle, backup or data changes)'

        # Tamper with only a disposable copy of the launcher/payload.
        damaged = root/'tampered'/name
        damaged.parent.mkdir()
        run('/usr/bin/ditto', launcher, damaged)
        damaged_payload = damaged/'Contents/Resources/Payload'/name
        (damaged_payload/'Contents/Resources/VERSION').write_text('tampered')
        before = snapshot(home)
        refused = run(damaged/'Contents/MacOS/DistributionInstaller', '--install-only', env=env, ok=False)
        assert refused.returncode != 0 and snapshot(home) == before
        report['damaged_payload_refusal'] = 'PASS (signature failure before installation)'

        # Mid-transaction failure: app has already been replaced when agent write fails.
        agent.unlink()
        agent.parent.chmod(0o500)
        before = inventory(installed)
        backups_before = list(data.glob('rollback-*.app'))
        try:
            refused = run(installer, '--install-only', env=env, ok=False)
            assert refused.returncode != 0 and 'автозапуск' in refused.stderr and str(agent) in refused.stderr
            assert 'NSCocoaErrorDomain' in refused.stderr
            assert inventory(installed) == before
            assert list(data.glob('rollback-*.app')) == backups_before
            assert not agent.exists()
        finally:
            agent.parent.chmod(0o700)
            agent.write_bytes(before_agent)
        report['agent_write_failure_rollback'] = 'PASS (actual permission denial after app replacement; exact app restored)'

        # Real published beta.6 is the update source, not another freshly built copy.
        original = Path(sys.argv[2]).resolve()
        signature_original = run('/usr/bin/codesign', '--verify', '--deep', '--strict', '-R=cdhash H"' + old_cdhash + '"', original)
        shutil.rmtree(installed)
        run('/usr/bin/ditto', original, installed)
        # Preserve a disabled/customized login item byte-for-byte.
        spec = plistlib.loads(before_agent)
        spec['RunAtLoad'] = False
        before_agent = plistlib.dumps(spec)
        agent.write_bytes(before_agent)
        previous = inventory(installed)
        run(source_installer, '--install-only', env=env)
        backups = list(data.glob('rollback-*.app'))
        assert len(backups) == 1 and inventory(backups[0]) == previous
        assert inventory(installed) == manifest
        signature(installed, vpn=True)
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', '-R=cdhash H"' + old_cdhash + '"', backups[0])
        assert all((data/k).read_bytes() == v for k, v in markers.items())
        assert agent.read_bytes() == before_agent
        assert len(list((home/'Applications').glob('*.app'))) == 1
        assert len(list((home/'Library/LaunchAgents').glob('*.plist'))) == 1
        report['existing_install_update'] = 'PASS (published beta.6 backup exact, one app, customized login agent and user data preserved)'

        # Exercise the documented same-version rollback, without changing profiles.
        shutil.move(installed, root/'updated.app')
        run('/usr/bin/ditto', backups[0], installed)
        assert inventory(installed) == previous
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', '-R=cdhash H"' + old_cdhash + '"', installed)
        assert agent.read_bytes() == before_agent
        assert all((data/k).read_bytes() == v for k, v in markers.items())
        process = subprocess.Popen([str(executable), '--login'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(1)
        assert process.poll() is None
        process.terminate(); process.wait(timeout=10); process = None
        report['rollback_and_relaunch'] = 'PASS (restored exact backup, original path and settings)'
        assessment = run('/usr/sbin/spctl', '--assess', '--type', 'execute', launcher, ok=False)
        report['gatekeeper_assessment'] = {'exit': assessment.returncode, 'result': assessment.stderr.strip()}
        report['payload_entries'] = len(manifest)
    finally:
        if process is not None and process.poll() is None:
            process.terminate(); process.wait(timeout=10)
        run('/usr/bin/hdiutil', 'detach', mount)
print(json.dumps(report, ensure_ascii=False, indent=2))
