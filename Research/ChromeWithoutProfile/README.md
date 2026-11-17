# Issue #1: isolated Chrome routing prototype

See [research report](../../docs/CHROME-WITHOUT-PROFILE.ru.md) for results and limits.
Nothing in this directory is shipped by `scripts/build.sh`, installed as beta.6,
or an accepted migration of the main Chrome profile.

`browser.py` drives only newly spawned disposable Chrome processes through a
private CDP pipe. It never attaches to the existing browser. `user_proxy.py`
refuses unmarked profiles and a browser lock; it is deliberately lab-only.
Do not remove a managed policy to run these scripts: reinstalling it on current
macOS requires System Settings confirmation.

Use an official Chrome for Testing executable for policy-free tests. Ordinary
stable Chrome inherits beta.6 policy even with `--user-data-dir`; that is a
separate control. No production policy, extension, system proxy, trust, Chrome
bundle, browser data directory or SSL session is edited.

```sh
python3 Research/ChromeWithoutProfile/receipt_checks.py
python3 Research/ChromeWithoutProfile/launch_matrix.py \
  --chrome '/path/to/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' \
  --output /private/tmp/launch-matrix.json
# Requires the existing connected beta.6 and local private site config:
python3 Research/ChromeWithoutProfile/routing_trial.py \
  --chrome '/path/to/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' \
  --output /private/tmp/routing-trial.json
```

The routing trial uses a random loopback port and its own rules/control socket.
It reuses the existing verified SOCKS peer without altering it. Work failure is
injected before SOCKS connection in the private relay, not by killing beta.6.
NetLogs are written beside the output and may contain internal names. Do not
publish them. `analyze_netlog.py` emits only a sanitized DNS task summary.

`LaunchProbe.swift` exercises AppKit LaunchServices without AppleScript,
Automation, Accessibility, or remote-debugging access to the main profile.
Its caller must supply only a disposable user-data-dir. The recorded
LaunchServices trial and baseline preservation scripts are private because they
include machine-specific paths and state.
