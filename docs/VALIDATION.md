# Mac Beta 0.2 validation

Tested on Apple Silicon. A previous experiment independently established two authenticated sessions with the official client idle, no corporate interface/routes, and an unchanged external VPN path. In the installed GUI beta, a real user completed the gateway MFA. Three corporate HTTPS endpoints returned 302, 401 and 302 with successful TLS verification; the in-tunnel DNS counter recorded three requests and three replies. External HTTPS continued via the existing system route. A 401 proves reachability and TLS, not application-level authorization.

The application listener rejected a numeric IP, an outside domain and a forbidden TCP port (SOCKS status 2) and UDP ASSOCIATE (status 7). The bundled runtime's ephemeral loopback TLS test verifies a valid positive control plus wrong SAN, expiration, foreign trust anchor, pin mismatch, unexpected endpoint and redirect refusals. Negative certificate cases send no HTTP body; the tests cover preflight, control and asynchronous transport. Legacy 0.1 tests are separate and do not establish new browser, sleep or login behavior.

The bundle extracted from the installer was installed and compared file by file. The actual ordinary Chrome profile used a mandatory PAC: the original rule scopes and Work/Life choices were tested against the active PAC. With the new tunnel off, a fresh corporate tab failed at the proxy and an external site loaded; with fresh MFA the three corporate web applications opened and Chrome owned established loopback connections to the new listener. External HTTPS and the corporate services were checked again after retiring the older helpers.

A real system sleep/wake closed the listener without prompting for or replaying credentials: new corporate browser traffic failed at the proxy while external HTTPS remained available. After an actual macOS logout and login, the Aqua RunAtLoad job started a new instance of the installed menu app automatically. The app was disconnected and port 1090 remained closed until fresh MFA. Cross-device Smart Proxy Route Helper Sync and gateway compatibility outside the tested setup are not certified here.

## Mac Beta 0.2.0-beta.2 · 9 November 2026

On the installed arm64 app, the operator approved an existing corporate Passkey in the ordinary default Chrome profile. The Check Point GUI was quit normally to release port 7779. The official CLI reported Idle. The browser returned a proof, the gateway accepted it for the app's pending CCC session and SLIM provided a new address and DNS. The owned SOCKS5 listener served three corporate TLS-verified HEAD requests (HTTP 302, 401 and 302). Numeric IPs, an outside domain, a forbidden port and UDP produced SOCKS replies 2, 2, 2 and 7. An independent OTP/password session passed the same checks. This result applies to the tested gateway. Check Point documents an IPsec limitation for SAML Remote Access. [Check Point R82 limitations](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_RemoteAccessVPN_AdminGuide/Content/Topics-VPNRG/SAML-Support-for-Remote-Access-VPN.htm).

Cmd+W and the close button hid the main window on the live tunnel. Reopening returned to the same session. Diagnostics closed independently and produced a fresh verified HTTP 302. The secure field showed one typed test character briefly, masked a paste and suppressed the echo with the preference off. Cancel cleared the unfinished prompt. The light/dark AppKit fixture exercised the actual window views. The fixture username and MFA marker were absent from persistent app records.

A new corporate Chrome tab reached Jira with the tunnel up. Killing the verified SSL worker closed port 1090 and the next corporate request failed with ERR_PROXY_CONNECTION_FAILED. An external Chrome page and separate HTTPS requests continued via Sota. The active mandatory PAC passed 140 destination and scope checks with 2 Work and 76 Life rules. The sleep and logout observations above are from beta.1.

## Mac Beta 0.2.0-beta.3 · 9 November 2026

The live Connected handoff was canceled first. Official Connected remained and Router did not start 1090. The operator then explicitly approved switching and confirmed Passkey. The GUI exited normally and Router served corporate HTTPS 302/401/302 with verified TLS while the official CLI reported Idle. The separate Idle test started the real GUI, set Idle through the official CLI, and Router closed it normally before opening its own browser request. Canceling that request removed the callback listener.

A foreign Python listener on 7779 survived the attempted Router connection. Router displayed a handoff/port refusal, opened zero new SAML tabs and left the official state Idle. The last successful method and username were restored after a complete application restart. The real Aqua login job was kickstarted with --login. It showed zero visible app windows, no backend, no 7779/1090 listener and disconnected state. This exercises the actual login entry point. A fresh macOS logout/login was not performed for beta.3.

Tests/handoff.py covers Idle, accepted switch, rejected switch, unknown state and GUI failure. Browser callback, strict TLS/pin and AppKit regressions passed. The packet tunnel implementation is unchanged.

The separate beta.3 OTP/password session served the same TLS-verified 302/401/302, with Sota reachable and SOCKS denials 2/2/2/7. After full exit and reinstall, OTP and the scoped username were restored. Reconnect immediately asked for OTP, without asking for a username. Cancel left the successful-method preference intact. The local rollback to the verified published beta.2 and reinstallation of the exact beta.3 ZIP both passed. A final Passkey session from that ZIP again served the corporate endpoints with official Idle. Chrome's mandatory PAC still passed 140 checks for 2 Work and 76 Life.

## Mac Beta 0.2.0-beta.4 · 9 November 2026

Tests/capabilities.py drives the production session entry point with absent IdP realms, ambiguous realms and a network error. All are rejected before calling the official handoff. The native GUI/port capability check also precedes consent and disconnect. Tests/handoff.py verifies consent, refusal and cancellation. TLS/pin and callback regressions pass.

On the installed secure field, test keyboard input showed a temporary character inside its position among the bullets, followed by complete masking after one second. Insertion in the middle, replacing a selection, deleting and pasting a string containing combining accents and an emoji sequence were inspected visually. Paste stayed fully masked. The secure accessibility role remained intact. The focus-dependent auxiliary menu-tests assertion failed during development and was removed from the final test program. It was unrelated to the installed app's process. Direct committed input for every third-party IME was not certified.

A real code/password session reused the saved login and served corporate TLS-verified 302/401/302 while the official client was Idle. Sota remained reachable. SOCKS restrictions returned 2/2/2/7 and the active mandatory Chrome PAC passed 140 checks for 2 Work and 76 Life. The input and preflight changes preserve the existing packet transport.

The rollback helper restored the verified published beta.3. Reinstalling the exact beta.4 ZIP retained the username and last successful code/password choice. The final installed ZIP then completed a new existing-Passkey request in the ordinary Chrome profile. It provided SOCKS5 1090 with corporate TLS-verified 302/401/302, official Idle and three in-tunnel DNS requests/replies. In-app HTTPS diagnostics independently produced verified HTTP 302. Closing diagnostics kept the tunnel up.

Compatibility of older Check Point installations is determined through their validated CLI/configuration and actual gateway capabilities. This Mac's installed client was used for live validation. A matrix of older client releases and all third-party IMEs was not tested.

## Mac Beta 0.2.0-beta.5 · 9 November 2026

The owner used **beta.4** for a full workday on one Mac: work and personal services operated without noticeable delays, including after breaks. This is user observation, not a performance measurement or certification of other devices.

The beta.5 binary extracted from the distribution matched all 570 files of the signed build. On macOS 27.0.1 arm64 the installed bundle matched the extracted one. Gatekeeper assessments were enabled. No usable signing identity was available; the app is signed ad hoc and was not submitted for Apple notarization.

On installed Google Chrome 156, disposable profiles exercised the real network stack with no extension. A local HTTP origin and fresh URL paths witnessed DIRECT independently of the proxy. An exact pre-login exception reached the origin; a fresh work subdomain did not. An invalid PAC reached the same origin with mandatory=false and failed with mandatory=true. NetLog recorded the tested request error. These fixtures seed a disposable Chrome proxy preference; they do not establish ordinary-profile policy installation. Tests/chrome_failures.py can be run on a test Mac with no active Chrome proxy policy.

Tests/sites_gate.py exercised the packaged native binary with a private packet socket. Exact, nested and mixed-case work matches emitted in-tunnel DNS; an unmatched suffix, child of an exact site, pre-login exception and forbidden port returned reply 2 and emitted no DNS. Local profile lifecycle tests separately cover pending state, replacement and refusing foreign or changed settings. Existing TLS, callback, capability and handoff tests passed; 83 legacy tests passed. The packet transport and trust mechanisms were not replaced.

On the owner's Mac, System Settings installed the per-user profile. The actual profiles output on this macOS wraps the managed payload in PayloadContentManagedPreferences; the installer checks the returned payload and macOS reports ProxySettings forced. Separate fresh instances of the installed stable Chrome with no extensions and no proxy switches inherited that OS policy: a work request did not reach the local direct witness (net error -130); an ordinary request reached it. The owner completed Passkey in the installed beta.5 app. Corporate TLS probes returned 302, 401, 302, with three tunnel DNS requests/replies; forbidden SOCKS commands returned 2/2/2/7. The official VPN was Idle and external HTTPS remained available on the existing utun route. The normal, already-open Chrome process established a connection to 127.0.0.1:1090.

The owner verified ProxySettings on chrome://policy after reloading policies in their ordinary profile, and opened Jira. The existing extension relinquished proxy control; its data was not removed. A fresh browser's inherited configuration is not proof that a running profile has already reloaded it. Verify the active browser **before disabling the previous controller**.

Two different live failures were injected after separate Passkey logins. SIGKILL of the installed menu app ended its SSL child and closed SOCKS. A separate SIGKILL of the verified SSL worker left the menu process alive and closed SOCKS. In both cases the installed user policy stayed in place; a new Chrome test instance using that policy reported ERR_PROXY_CONNECTION_FAILED (-130) for the work host with zero hits on the direct witness, while an ordinary host reached the witness. No automatic login or direct alternative was used. The broken-PAC test above is independent of both process tests. No claim about other browsers, direct IPs, external profile removal, all possible network side channels or all managed Macs is made.

## System proxy candidate · 9 November 2026

The test Mac runs macOS 27.0.1 and Google Chrome 156. The published beta.5 was active during side-by-side tests. Five alternating cold TLS requests per route on a preliminary HTTP relay all completed. Median time to first byte was 103 ms for the existing work route and 114 ms through the relay. For the personal site it was 370 ms direct and 318 ms through the relay. These small transport samples predate the final worker-identity check.

The CONNECT fixture verified a 4 MiB transfer by SHA-256, remote SOCKS domain framing, cancellation of previously open streams after a policy edit, forbidden-port rejection, and personal access while the work peer was unavailable. A separate native ocproxy packet fixture verified worker replacement, revocation of an old stream and in-tunnel DNS for a newly allowed host. The running signed main Chrome also returned a synthetic value to the real callback on 7779, without a gateway authentication exchange. A disposable Aqua launchd job restarted the packaged HTTP router after SIGKILL. A personal CONNECT succeeded and a work CONNECT failed both before and after restart. TLS identity, callback checks, capabilities, official-client handoff and 83 legacy regression checks passed.

The active Sota packet tunnel is the primary IPv4 and IPv6 service. Its live service ID is absent from SCNetworkServiceCopyAll and SCNetworkServiceCopy returns nil. The saved Sota service has a different ID. Neither the live global HTTP nor HTTPS proxy was enabled. On 10 November macOS completed both reversible trials while beta.5 remained active. Across 24 readings over six seconds per trial, configuring six physical services produced a scoped endpoint and zero global HTTP/HTTPS matches. Adding the saved Sota service produced 24/24 matches on its persistent service, but 0/24 on the active VPN service and 0/24 in the global proxy dictionary. All saved service settings matched the original snapshot after restoration. The candidate cannot enforce the requested Chrome route with this Sota configuration. Ordinary Chrome was observed using the existing beta.5 SOCKS. Migration of ordinary Chrome, a fresh external Passkey, actual sleep/wake, login and physical network transitions with beta.6 remain unverified. The candidate has not been released.

## Fixed Chrome proxy candidate · 10 November 2026

The replacement user profile contains one Chrome ProxySettings dictionary, fixed_servers, with a single HTTP proxy and no DIRECT option. It contains no work rules. No macOS network service is modified. An isolated instance of installed Google Chrome was launched without extensions. CDP supplied a fixed proxy to a disposable browser context; this exercises the real network stack but does not verify the main profile or its enrollment.

- A fresh direct control request reached the local HTTP origin. With the fixed proxy, a work request without a tunnel never reached that origin. A public HTTPS page rendered, failed when added to Work and rendered after removal, in the same browser process. A save interrupted a transfer in progress, closed the upstream and blocked a fresh retry. When the proxy was killed, Chrome returned ERR_PROXY_CONNECTION_FAILED with no direct origin hit. After restart the public page rendered. The one-time enrollment challenge also reached the router and rendered.
- A disposable Aqua launchd job started the signed router from the candidate bundle. During SIGKILL/relaunch a competing bind to its port failed; launchd kept the listening descriptor. Life worked and Work without a tunnel remained blocked before and after restart. The native tests verified remote DNS, port restrictions, stream revocation on change, and SHA-256 for a 4 MiB CONNECT transfer. All 83 legacy regression checks passed.
- While the installed beta.5 remained active, a local trial pinned both sides of the SOCKS greeting to its original verified native worker. It was not a new beta.6-authenticated session. Isolated stable Chrome on the active Sota route rendered the same corporate robots.txt and public HTTPS page through the old path and trial. Five fresh contexts per page and route, interleaved: median time to rendered content for Work was 167/256 ms (old/trial), and for Life 903/932 ms. The Work trial incurs a separate old-process owner lookup; these are small samples, not production latency guarantees. A binary HTTPS resource (3076 bytes) matched in length and SHA-256 on both browser paths.
- With a fixed proxy and no test tunnel, signed Chrome delivered a synthetic value directly to the real 7779 listener with peer validation intact. This is not a fresh gateway MFA transaction. Receipt and rollback fixtures verify the owned profile identity, original file hash and list restoration, and refusal to replace foreign or modified profiles.

The main Chrome profile was still protected by beta.5 during the isolated trials above. The following tests used the regular Chrome session on the same Mac.

The owner subsequently installed the replacement Chrome profile. The old Chrome process initially returned ERR_NAME_NOT_RESOLVED for the one-time check. After a normal quit and relaunch with session restoration, the main Chrome request reached the router. The existing Smart Proxy Route Helper was switched off in the browser. In this same main profile, with Sota active and the native SOCKS listener absent, fresh corporate HTTPS showed ERR_TUNNEL_CONNECTION_FAILED and a fresh personal HTTPS page rendered. Adding the personal domain as an exact Work rule in the candidate app caused the next main Chrome request to fail with ERR_TUNNEL_CONNECTION_FAILED. Removing the test rule restored the original private list and the page rendered again. The Chrome process and managed profile stayed in place throughout these edits.

The candidate UI was then killed with the tunnel disconnected. Main Chrome still rendered the personal page. Killing the native HTTP router on port 1091 while the UI was absent kept the port reserved, launchd started a new PID, and main Chrome delivered a new one-time probe and rendered a fresh personal page. These trials used the packaged router and the ordinary app UI code opened alongside the preserved beta.5 installation. The following live checks exercised gateway authentication, active tunnel loss, sleep and the physical Wi-Fi connection.

A fresh live Passkey then succeeded in main Chrome under the fixed policy. The signed preview UI recorded the browser method, its session process was in browser mode, the original Check Point connection was Idle and Sota remained the primary route. Main Chrome with the proxy extension disabled displayed a fresh corporate robots.txt response and a fresh public HTTPS page from the same session. With the actual ocproxy process suspended and the HTTP router killed to discard old CONNECT tunnels, launchd recovered the router and retained the port. While ocproxy was still suspended, main Chrome returned ERR_TUNNEL_CONNECTION_FAILED for the corporate page and displayed the public one. Resuming ocproxy restored the corporate page on the same authenticated session.

During a real 56-second macOS sleep/wake cycle with the corporate session initially connected, the UI ended the session and the 1090 listener disappeared. The HTTP router continued to serve 1091 after wake. With Sota primary again, main Chrome showed a tunnel failure for a fresh Work request and rendered a fresh Life page before another login. A separate Wi-Fi interruption removed the active interface's IPv4 address, followed by reassociation, address acquisition and recovery of Sota's route. Main Chrome then delivered the one-time router probe and rendered a public HTTPS page. The Mac had one active physical interface; the physical test rejoined the same Wi-Fi network.

For the return to beta.5, macOS applied the saved original profile. Its effective proxy dictionary, receipt, original private rules and profile file fingerprint matched the pre-migration backup. After an ordinary Chrome restart with session restoration, a fresh Work request returned ERR_PROXY_CONNECTION_FAILED while the tunnel was disconnected; the same browser rendered a fresh Life HTTPS page. The trial router job was then unloaded. The first native app-relaunch request did not return a new browser process. Reopening the signed Chrome via macOS open with --restore-last-session succeeded; the candidate uses this checked launch before opening the separate one-time enrollment URL.

The signed beta.6 distribution was installed on the Mac, the published signed beta.5 bundle was restored using its installer, and the same beta.6 distribution was installed again. Each pass compared every installed bundle file with its source and verified the deep code signature, version and actual disconnected --login menu process. A separate fixture using the installed beta.6 engine kept a Work and a Life CONNECT stream exchanging bytes for 75 seconds; applying changed rules then revoked both. A 4 MiB transfer matched by SHA-256.

On the final installed bundle, resubmitting setup after an expired macOS prompt produced a new downloaded profile. Once approved, the forced Chrome dictionary contained only fixed_servers and http://127.0.0.1:1091. The installed application recorded the fresh ordinary Chrome challenge after its automatic restart. Both production Aqua jobs were unloaded, observed absent and reloaded from their installed plists. The menu started with --login and no corporate listener, and a second browser challenge reached the production router. Fresh main Chrome tabs showed ERR_TUNNEL_CONNECTION_FAILED for Work and rendered a personal HTTPS page. This exercised both login entries in the current Aqua session; the account was not logged out or the Mac rebooted. No separate Ethernet or second Wi-Fi network was available.
## DMG addition · 11 November 2026

The DMG is a distribution addition to published beta.6, not a new VPN build.
Its SHA-256 is `075fa3fc7700c43cf418d09181341f2b54ac3763c2c18ecd2b7572e7daf79547`.
The original Mac ZIP remains SHA-256
`83aa9bfbeb3a8441d9963e1c1fc32cf8d32b3eb97ee0055cd3684217e8ef293c`.
All 572 files and 54 directory modes in the embedded app match that ZIP;
its original CDHash is `06684ffbb00baba39f611a7d20c9c643791e893d`.

On an Apple Silicon Mac running macOS 27.0.1, local acceptance checked:

- `hdiutil verify`, read-only mounting/unmounting, and deep strict signature
  verification of both new shells and the original nested/installed app.
- Native macOS resolution of the background bookmark after mounting at another
  path; Finder displayed the background, custom volume icon and two app icons.
- Real non-root installation and actual `--login` GUI startup of the published
  app in a disposable Foundation home, disconnected and without credentials.
- A second app instance exited; the installer refused while the actual menu
  process held its lock, with no file changes. A damaged payload and a foreign
  login agent also refused before replacement.
- Updating the existing beta.6 produced one canonical app and an exact rollback
  backup. Synthetic site/account/profile data and the existing menu agent stayed
  byte-identical. Restoring that backup to the same path launched successfully.
- On the owner's real home, the distribution installer refused while Router was
  connected. The existing app, persistent VPN settings and LaunchAgent files
  matched their preflight hashes; the menu, SSL and HTTP worker PIDs remained
  unchanged and the tunnel still reported connected. No live update or restart
  was attempted. Private-denylist and public-content audits passed.

Both shells and the unchanged payload are ad hoc signed. The DMG is unsigned;
`spctl --assess` rejected the launcher, as expected without Developer ID and
notarization. A downloaded/quarantined first install with individual Gatekeeper
approval, a fresh physical user login, and another Mac/macOS version were not
tested. No security protection was disabled. See [DMG.md](DMG.md) for the local
build, install layout and remaining limitations; beta.5 profile rollback remains
the existing, separately confirmed app workflow.
