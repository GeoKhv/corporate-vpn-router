# Mac Beta 0.2

## Candidate beta.6

An independent user LaunchAgent runs the loopback HTTP proxy. Chrome reads the effective macOS HTTP and HTTPS settings. Naked TCP sockets use the existing system route for personal traffic. Corporate CONNECT targets go to loopback SOCKS with ATYP=DOMAIN. The supervisor verifies the native listener owner, and the router checks the worker generation on both sides of the SOCKS greeting before disclosing a target name. HTTPS bytes stay opaque. A rule change cancels forwarding tasks and replaces the native SOCKS child on the existing packet FD. Saving waits for local acknowledgement from the router and any active supervisor. The SSL transport remains subject to its existing pin and lifetime rules.

The native setup transaction snapshots each eligible service by ID under the SCPreferences lock. Only an effective global manual proxy permits retirement of the exactly identified beta.5 profile. Restoration compares protocol groups against the installed values. The process supervisor restores service after a crash while the endpoint configured by macOS remains fixed. Network Extensions may publish a different global proxy configuration. An unconfigured primary service can make Chrome choose a direct connection before a user-space observer can react. The system-mode migration on the test Mac has not been accepted.

## Earlier versions
Chrome Work → SOCKS5 with remote DNS → loopback-only ocproxy → lwIP → Unix datagram socket pair → cpyvpn SLIM over TLS → gateway. The host sees TCP to the validated gateway, never a TUN device, corporate route, or system DNS configuration change. The system resolver is used for the public gateway only. Corporate names are looked up inside the packet tunnel using the first gateway-provided IPv4 resolver.

The managed worker and supervisor use anonymous pipes for credentials/lifetime. Death of the parent closes the downstream proxy. Allowlisted domain suffixes match on DNS label boundaries, before lookup; ports must be explicitly allowed. Raw IP addressing, UDP and public destinations outside the list are refused. This is unauthenticated local SOCKS: other processes on the same Mac can use an active session within its allowlist. Keep the domain list narrow. A hostile local user/process is outside the trust model.

Chrome Work has one proxy and no DIRECT alternative. The 0.4.1 extension applies a mandatory PAC while it controls the browser. Removing/disabling the extension, another proxy controller or incognito without the extension is a separate failure mode. Application HTTPS is validated by the browser as usual. Existing system certificate settings are neither copied nor altered. Login items never silently re-establish an MFA session.

## External browser authentication

With the IdP method selected, the pinned TRAC ClientHello advertises SAML support. The app requires exactly one visible single-factor identity-provider realm, reserves loopback port 7779 and sends a new UserPass with empty credentials. The pending session ID stays in memory. The gateway supplies the HTTPS challenge for the default browser. For a recognized ServiceProviderTabs launcher, a pinned, cookie-free GET must advertise a same-origin continuation with the identical realm and session query before the app can skip the popup loop.

The listener accepts a bounded GET on the expected Host. A supplied non-opaque Origin or Referer must match the gateway. Without either, the client socket must belong to the signed main Google Chrome installation or its signed helper. OPTIONS completes a preflight without consuming the proof. The proof is redeemed over pinned TLS in a MultiChallange for the pending ID. The gateway must return authenticated status and an active key before SLIM can start. The app never reads profile credentials or cookies. The listener closes on completion, cancellation, process exit or timeout.

OTP has a distinct username request before any secret input. UserPass and MultiChallange fields are typed independently of prompt text. A local username is scoped to the site, CA pin, method and realm. The IdP controls browser account selection. When it explicitly returns a username after authentication, the app can show it locally.

## Official GUI handoff in beta.3

Only a user-initiated browser connection prepares the official GUI. The backend validates the root-owned vendor-signed trac executable and obtains one unambiguous official state. Idle permits normal GUI Quit. Connected/Connecting/Reconnecting requires explicit confirmation in Router before trac disconnect. Cancel leaves the official session untouched. Unknown states fail closed.

The native app rechecks Idle, validates the exact vendor-signed GUI bundle and refuses any port-7779 listener outside that GUI's PID set. It sends NSRunningApplication.terminate and waits for a clean exit. The backend then checks an exclusive loopback bind. The actual callback listener reserves the port again before issuing authentication, closing the race with other processes. Neither path launches the GUI, manages a protection service, force-kills a process or retries browser launch automatically.

The Check Point GUI LaunchAgent is RunAtLoad with KeepAlive SuccessfulExit=false. A normal Quit avoids its abnormal-exit relaunch rule. Its system service remains available for state and trust checks. A retired legacy local router contained a 300-second connectgui loop. Its LaunchAgents are absent from the active user domain. The gateway ServiceProviderTabs page can also reopen browser windows on a timer. Router uses the pinned same-transaction single-tab continuation described above.

The successful connection records only the method identifier in user preferences. Startup restores that choice and the method-scoped local username. The Aqua --login job creates a disconnected status item, without starting handoff, a backend or a browser.

## Capability preflight and secure input in beta.4

Both methods obtain the advertised realms over pinned TLS before an official VPN can be disconnected. An active official connection is permitted only for this read-only discovery and pin validation. Zero advertised IdP realms, multiple matching realms and an unsuccessful capability request are distinct outcomes. Personal Passkey enrollment is unknown until the user visits their provider. No Check Point version threshold is used. An explicit fallback button starts code/password authentication, without an automatic retry loop. Following consent, Idle and the pinned identity are verified again before credentials are sent.

InlineSecureField remains an NSSecureTextField using AppKit's native secure editor. Direct keyboard input can temporarily draw one composed character over its bullet region inside that editor. Native text storage, selection, navigation, scrolling, paste and secure accessibility behavior remain in place. The drawing overlay cannot receive mouse input and has no accessibility label. Paste, deletion, selection changes, focus loss, send, cancel and a one-second timer remove it. The native secure editor continues masking every other character.

## Standalone Chrome controller (beta.5)

A user-installed macOS configuration profile carries Chrome's mandatory ProxySettings with a static data-URL PAC. No PAC server, port, extension, system proxy or VPN interface is needed. The same versioned work-sites document feeds the script and the packet proxy's pre-DNS gate. Only exact bootstrap hosts use DIRECT ahead of the work rules. Non-work DIRECT follows the host route and does not chain an existing HTTP proxy; the installer refuses an enabled competing system proxy. Rules are private; changing them requires macOS to replace the profile. Chrome's mandatory setting is what prevents fallback if the PAC is invalid. Removing a policy externally is outside that guarantee. See the [Chromium policy schema](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/policy/resources/templates/policy_definitions/Miscellaneous/ProxySettings.yaml).
