# Mac Beta 0.2
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
