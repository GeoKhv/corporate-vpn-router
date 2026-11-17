# Текущий статус · 0.3.19 / 3019

На Mac получателя пользователь подтвердил для **0.3.18** вход с OTP, затем паролем, и одновременную работу рабочих и внешних сайтов с внешним VPN. Красная проверка HTTPS относилась к одному адресу; старый отчёт не содержал достаточных данных для установления точной причины её отказа.

Для **0.3.19** перед публикацией проверены: подписи факторов и сохранение их позиций; отсутствие лишнего CCC-запроса; реальные дочерние процессы и пакетный обмен на синтетических данных; отмена MFA и завершение при потере родителя; Rust fmt/clippy и тесты IKE/ESP поставляемого workspace (два теста системного Keychain пропущены); классификация HTTP/TLS/timeout; безопасный отчёт и его экспорт встроенным Python после ZIP roundtrip; копирование URL файла в отдельный именованный буфер. TLS fixtures включают положительный контроль и отказы для неверного имени, срока, CA и pin.

Проверены подписи и состав пакета, SHA-256 анонимного скачивания и обнаружение 0.3.19 через Sparkle из изолированных клиентов 0.3.17/0.3.18. Это не проверка установки на компьютере получателя. Бинарники помощника маршрутов, RouteClient и sing-box в 0.3.19 сохранены от предыдущего пакета.

**Не подтверждены для 0.3.19:** свежий вход на Mac получателя, повторное подключение, сон/пробуждение и длительная работа. Результаты ниже относятся к своим датам и версиям; их нельзя автоматически переносить на текущий выпуск. [Пакет и контрольные суммы](releases/0.3.19.json).

## Синхронизация исходников · 18 ноября 2026

В отдельной чистой ветке перед отправкой в main повторно прошли 88 основных проверок (`scripts/test.sh`), пять тестов IPsec-процессов/пакетного обмена, тест отчёта, AppKit-проверки классификации HTTPS и файлового буфера, а также изолированные тесты обычного и переносимого помощника. Python-файлы проверены на синтаксис, внутренние ссылки документации — на существование. Sources и Backend побайтово совпали с локальными исходниками 0.3.19. Личные журналы, конфигурация и ключи не включены. Никакое реальное подключение не запускалось; установленный Router и его помощник не менялись.

---

# Исторический журнал проверок

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

## Installer correction · 11 November 2026

The reported post-approval generic alert came from `Sources/main.swift` on a
*different* Mac. That machine and its failing process/error state were not
available. The message discarded the underlying error, so it cannot establish
Gatekeeper, an old installation, or any particular filesystem failure as the
cause of that incident. The current Mac has the correctly signed published
beta.6 at the canonical user path, no system-wide duplicate, valid menu/HTTP
LaunchAgents, and a connected session. Those observations do not diagnose the
other Mac.

Code inspection confirmed that the original menu installer discarded ditto and
codesign stderr, released the menu lock before replacing files, and did not undo
the app replacement if writing its LaunchAgent failed. The distribution shell
executed the nested original installer and depended on a sibling bundle for its
secondary drop target. Both paths made diagnosis and quarantined/translocated
launch fragile. The correction shares one transaction, keeps the menu lock,
restores the app on a post-placement login-item failure, preserves existing
agent bytes, captures both command streams, resolves its bundle independently
of argv[0], and separates installation from native launch confirmation.

The installer-fix.1 candidate passed non-root integration checks in a disposable
home on macOS 27.0.1 arm64:

- Empty-home install, exact payload inventory and deep strict signature.
- Actual menu startup, duplicate exclusion and refusal to replace a running app.
- A real Aqua launchd login job with a unique disposable label and isolated home.
- Rejection of a foreign login plist and a tampered payload before replacement.
- Actual LaunchAgents-directory permission denial after app replacement, with
  the exact previous app restored and no new rollback leftover.
- Update from the exact original beta.6 embedded in the old read-only DMG;
  exact backup, synthetic sites/accounts/profile data preserved, customized
  disabled RunAtLoad bytes preserved, one canonical app and one login plist.
- Restoration and launch of that original backup.
- All 83 existing project checks passed.

Two extracted writable test copies of the original ZIP acquired FinderInfo and
were rejected by strict codesign (`resource fork, Finder information, or similar
detritus not allowed`). No attributes were stripped. The update test instead
used the exact hash-verified original app on the old read-only DMG. This is a
specific observed verification error, not proof of the other Mac's incident.

On the real connected home, the corrected installer refused with the busy-lock
message and errno 35. The application and persistent settings matched preflight
SHA-256 values; menu PID 99095 and HTTP PID 99092 were unchanged, and the tunnel
still reported connected. Chrome and Sota were not restarted or reconfigured.

Native quarantine checks used Safari to download the exact candidate bytes from
an HTTP server bound only to 127.0.0.1. The download had Safari quarantine
`0083`, and DiskImageMounter mounted it with the `quarantine` flag. Gatekeeper
blocked the installer and the installed app until the user individually approved
them in Privacy & Security. Nothing stripped quarantine or disabled protection.

After approval, the application ran under a real App Translocation path in an
empty disposable home, held that home's menu lock and reported disconnected.
Its strict signature passed; its quarantine remained present (`00c3`, macOS's
user-approved state). The same installed path was then restored to the exact
published beta.6 and updated again from the Safari-downloaded image. The old
bundle was backed up exactly, synthetic sites/accounts/profile settings and a
customized disabled login agent stayed byte-identical, and the updated app
launched under App Translocation after macOS's new per-file approval.

This native test exposed an additional shell bug: NSWorkspace may return a
process that is still suspended by Gatekeeper. Testing isTerminated after two
seconds could report success before the user rejected launch. The final shell
waits for isFinishedLaunching, detects termination and has a 30-second timeout
with an explicit installed-path/permission message. The final image has SHA-256
`faa89825703a37a64a546351089313def91b6a10cc5374f120a6bdeb4f15279c`;
the payload CDHash remains `13f2a4efffe657f303fa79a3d6f5e7105c3e0248`,
identical to the app that passed native first-launch and update checks. Its full
integration suite passed again. Final-shell native acceptance passed: after individual approval, the final
Safari-downloaded shell installed in a new empty home. Gatekeeper blocked the
installed app; dismissing its warning with Done produced the explicit message
“Приложение установлено”, the exact destination, the launch-termination reason
and the per-app approval action. The shell did not report successful launch or
ask for reinstallation. Quarantine remained present on that installed app. No second physical
Mac, separate login, or fresh OS trust database has been certified.


## Private single-app colleague ZIP · 11 November 2026

See [the local demo acceptance record](DEMO-2026-11-12.md) for exact quarantine approvals, native relaunch, installation/rollback preservation and browser results. The ZIP contains corporate sites and is not a public release. Safari.app corporate browsing and second-Mac AdGuard VPN compatibility remain unaccepted. The working beta.6 and current session were preserved.

## Selective TUN laboratory checkpoint · 11 November 2026

The [selective TUN trial](../Research/SelectiveTunTrial/README.ru.md) reached
Jira, Confluence and OWA in ordinary Safari.app, Yandex and main-profile Chrome
with Sota connected. The corrected durable-map design was retested in Chrome
after the user removed the Router profile; CFPreferences reported forced=false.
Chrome was actually quit and ordinarily relaunched without custom arguments.

The real sing-box restart fixture exposed address reassignment after SIGKILL,
including with store_fakeip enabled. That design was rejected. The durable map
commits before DNS answers, never reuses an address and refuses corruption,
exhaustion and persistence failure. Real loopback tests kill the stack and bridge
and verify retained IPv4/IPv6 forward the original domain unchanged.

A fresh root session replayed all six host routes for the three retained names
before publishing DNS. Retained IPv4/IPv6 returned TLS-verified HTTPS without
DNS; fresh Safari and Chrome pages then rendered. The two-hour gap does not
prove browser DNS-cache retention. A later ordinary Safari relaunch initially
showed a blank window despite successful SOCKS connections; reload rendered Jira.
That first navigation is not counted as seamless success.

Actual SOCKS-worker suspension preserved fresh Life through the same Sota exit.
With the durable map Yandex waited during a 70-second pause, with eight SOCKS
errors and zero new successful Work connections; its waiting request rendered
after resume. Corrected Chrome showed ERR_CONNECTION_REFUSED during a roughly
99-second pause, fresh Life within the pause, then a fresh successful Jira URL.
These pauses did not themselves tear down SSL or repeat MFA.

The independent watchdog removed scoped resolver files, exact host routes and
all helpers after real supervisor SIGKILL. An earlier residual DNS helper was
fixed; subsequent crash and normal-stop passes report no helpers, no utun,
no resolver and unchanged default route. The latest lab cleanup completed at
17:02 MSK. The user chose to leave the old Chrome profile removed while the
separate private application is completed. Installed beta.6 is retained.

During integration tests, child Python interpreters created 127 extra bytecode
files in the old bundle. They were archived and removed; all 572 original file
hashes matched and the original signature verifies without re-signing. Child
tests now explicitly use -B. The integrated acceptance below supersedes this
laboratory checkpoint; AdGuard VPN on a second Mac, arbitrary DoH and Private
Relay are not certified.

## Private selective application · 0.3.0-alpha.1 · 11 November 2026

The separate TUN Trial app passed local acceptance with Sota connected on this
Apple Silicon Mac. All three resources (Jira, Confluence, OWA) rendered in
ordinary Safari.app, Yandex and the existing main Chrome profile. Fresh URL
nonces were correlated with local DNS and domain-preserving bridge records.
Chrome's old mandatory ProxySettings was absent; the user chose to leave that
profile removed. Yandex's existing ZeroOmega remained in System proxy mode;
system proxies were off and the observed path used TUN. An extension-free
Yandex installation was not separately tested.

Both actual authorization methods completed: browser passkey and code/password.
TLS, gateway pin, native SOCKS identity checks and the authentication engine
remain byte-identical to beta.6. The final footer link was confirmed by the user.

At 17:36:48 MSK the real SSL session process was killed, and its proxy children
exited. Ordinary Chrome's fresh Work navigation returned ERR_CONNECTION_REFUSED;
a fresh Life response at 17:36:53 retained the Sota exit, HTTP/2 and TLS 1.3.
This goes beyond the earlier worker suspension. After native authorization and
fresh passkey MFA at 17:45:02, a fresh Jira navigation rendered and Life again
retained the same exit at 17:46:17. No browser TLS errors were bypassed.

At 17:37:38 a real SIGKILL of the integrated root supervisor exercised the
independent watchdog: cleanup reported no helpers, no utun, no scoped resolver
and the original default route. Process and route checks confirmed the result.
The final recovered session was left connected for the user. App sessions have
an eight-hour bound; the default route is never replaced.

The integrated local suite passed durable-domain crash/persistence cases,
actual sing-box/bridge SIGKILL with retained IPv4/IPv6 and original SOCKS names,
UDP/TCP DNS backend failure, unsupported-policy refusal, editable settings and
the active-session edit barrier. Disposable-home installation verified the
separate destination, unchanged sibling beta.6/configuration, busy-lock refusal,
no new autostart or networking on launch, and exact backup/rollback. Existing
installation-location checks also passed. No new real network routes were
needed by these isolated tests.

The installed original beta.6 inventory matches all 572 baseline hashes and its
original strict signature. All 15 baseline persistent files and the demo.2 ZIP
also match. Private evidence is in `.private/selective-tun-build/evidence/`;
corporate defaults and journals remain private. No Actions or publication ran.

Following user feedback, the tested candidate was designated 0.3.0-alpha.1.
Only the version, its footer display and bundle/build metadata changed after
live acceptance; the final archive is checked against that candidate. The connected
installed instance retains its earlier label until a normal exit and update.
The same archive is intended for the second Mac; AdGuard VPN compatibility is
not claimed. See [the private-build guide](SELECTIVE-TUN-PRIVATE.ru.md) for
administrator permission, scoped DNS/host routes, rollback, TCP-only Work,
tree-only policy, 253-name capacity, DNS bypass and startup limitations.

Final artifact: `Corporate-VPN-Router-0.3.0-alpha.1-private-arm64.zip` (40,407,468
bytes), SHA-256 `1addfaa8a70f7cee354c7a30727158366a3eff834ddef96d671b5c0a8dc671a4`.
ZIP extraction reproduced every candidate file hash, passed deep strict
signature verification and reported 0.3.0-alpha.1. The final candidate again
passed disposable installation/rollback and editable-settings checks. The
existing AppKit menu fixture passed with the version in the footer; native
window screenshots were unavailable, so bitmap fixture previews are not claimed
as screenshots of the installed app. The user had already confirmed the actual
GitHub action before the version label was appended. No live network tests
were repeated for that label-only change.

## First-use correction · private 0.3.0-alpha.2 · 11 November 2026

The second-Mac user reported missing login entry, a generic app icon and
OFFICIAL_SITE_AMBIGUOUS. The official `trac info` command returned “service is
not started”. Opening the official GUI without VPN login changed the visible
state, but a later alpha.1 attempt still displayed its generic error. This does
not establish successful authentication or AdGuard VPN compatibility.

Alpha.2 exposes a memory-only OTP username field on the main window before
connection. Empty entry blocks setup, typed entry is sent only on the gateway's
verified scoped username request, and storage still requires successful MFA.
Saved-account editing and browser-account isolation remain intact. An AppKit
fixture compiled with `-Onone` (assertions enabled) exercised these transitions,
no username in diagnostics, method switching and the existing menu behavior.

Official-client state errors now distinguish stopped service, command failure,
missing/unsupported/ambiguous sites and unknown state. The selective controller
checks this signed client before creating its map, listeners, admin request or
network changes. Tests cover refusals at that boundary and reject capturing the
actual gateway in Work DNS even before a saved receipt exists. Saved-site/pin
and handoff regression checks passed. The original trust functions other than
local-state error classification match structurally; TLS, MFA and native-worker
resources remain byte-identical. No official VPN was activated by these changes.

The existing project-owned Router icon is now embedded and declared by
CFBundleIconFile. The archive contains exactly one top-level `.app`, with no
wrapper directory or instruction file. The system administrator prompt remains
necessary for utun/scoped DNS; no permanent privileged service was introduced.

A user-requested private domain is bundled in the defaults and a one-time
additive update. A disposable real-app launch verifies preservation of custom
sites, ports and exceptions, an exact old-list backup, honoring later deletion,
and refusal to migrate while a previous route session is active. The running
first-Mac installation and network were not changed during this correction.
The additional site's actual browser access and successful second-Mac login
remain untested; the prior Sota browser matrix applies to alpha.1's routing core.

Final alpha.2 archive: 41,518,231 bytes, SHA-256
`3b4efef470ae614264bb2cdc805b69d4c89a00a26696e410d5d5e57409b610ec`.
Extraction verified one application at the root, an exact candidate inventory,
deep strict signature, 0.3.0-alpha.2 version, the declared icon and the requested
private domain/addition record. Original beta.6, all 15 baseline persistent
files on the first Mac and the preserved demo.2 archive still match their
baseline hashes. Evidence: `.private/selective-alpha2-evidence/`.

## Persistent route broker · private 0.3.0-alpha.3 · 12 November 2026

**Cause of repeated administration prompts.** Alpha.2 invokes `osascript` with
`with administrator privileges` for each new selective-network session. The
command launches staged Python 3.13 and `network.py`; it is not a Python
installation request. That supervisor has an eight-hour limit and also ends on
owner loss/heartbeat failure. Starting again repeats Authorization Services.
The per-session mechanism is confirmed in code; the exact trigger of the user's
particular overnight termination was not reconstructed from an identified log.

**Supported installation boundary.** The installed Apple SDK's
`ServiceManagement.framework/Headers/SMAppService.h` states that applications
containing LaunchDaemons must be notarized, while existing root-installed
`/Library/LaunchDaemons` jobs remain supported. `security find-identity -v -p
codesigning` returned zero available identities; this app is ad hoc signed.
Consequently this build uses a native, explicitly admin-authorized installer
for a root-owned launchd job, without claiming SMAppService/notarization support.
Reference: https://developer.apple.com/documentation/servicemanagement/smappservice
No signing purchase, certificate import, Gatekeeper/quarantine/SIP change,
Check Point installation change, or corporate policy change was made.

The service exposes only begin, route, publish, heartbeat, stop and status.
It accepts the enrolled effective UID and an exact hardened RouteClient cdhash,
using NSXPCConnection's per-message code requirement. A session belongs to its
particular connection. Inputs cannot specify executables, shell, file paths,
adapter config, gateway routes or external proxy addresses. Domains and ports
must be subsets of a build-time approved policy; route addresses are individual
members 1–253 of fixed synthetic IPv4/IPv6 pools. `utun73`, the local adapter
configuration and authenticated loopback SOCKS endpoint are fixed. The adapter
binary is root-owned and checked against its pinned SHA-256 before each start.
Python, synthetic DNS and the corporate transport run unprivileged. Root runs
only the broker and the fixed sing-box adapter that needs utun privileges.

State changes have an fsynced root-owned journal before mutation. Existing
resolver files/exact host routes are not adopted or overwritten. Cleanup checks
resolver contents/ownership and interface identity before deletion, kills only
its own adapter, and preserves unrelated changed files. launchd restarts the
broker and it reconciles its journal before accepting new work. XPC EOF,
adapter exit and a 20-second heartbeat lease independently trigger cleanup.
The application also stops routes on disconnect, SSL termination and sleep;
it does not silently reauthenticate or recreate a lost session. The old
8-hour route-supervisor limit and root Python startup have been removed.

**Implementation defects found and corrected during acceptance.** Running the
native installer directly from the protected Documents development directory
was rejected by macOS before installation. Running the same built installer
from the application staging directory succeeded; no privacy protection was
changed. The normal UI invokes the copy installed under Applications.
A second route cycle exposed Foundation `Process.waitUntilExit` stranded on a
dispatch worker. A real process sample established that stack. Child execution
and teardown were changed to POSIX spawn/waitpid with bounded waits. The final
repeated-cycle and crash tests were run after this correction. Test-time
administrative commands to sample/kill/update/uninstall the broker are separate
from ordinary connection operations and are not counted as prompt-free use.

**Executed on this Mac.** Evidence is private under
`.private/helper-alpha3-evidence/`:

- Native policy/address and malformed-operation tests; injection, subnet,
  out-of-pool and out-of-policy values refused; unsafe root parents refused;
  cross-worker child termination regression passed.
- Live XPC refused a differently signed native client and the correctly signed
  client running as `nobody`. Another connection could not alter a live session.
- Two complete starts/stops, then SIGKILL of the unprivileged controller. Every
  cycle resolved Work names, retained Life HTTPS 200 and returned the broker
  to idle without utun/resolvers. No authorization subprocess was involved.
- Suspending the controller for 24 seconds expired the lease and cleaned the
  network. Resuming it reported the finished session.
- SIGKILL of the actual root daemon while routes were active: launchd started
  a new PID, the journal was reconciled, routes/resolvers disappeared, and a
  subsequent start/stop succeeded without elevation.
- Native helper uninstall removed the launchd job, plist, binaries and state;
  immediate reinstall succeeded. This explicit acceptance operation happened
  after the sleep test and caused the one admin prompt the user observed then.
- AppKit `-Onone` checks: first-use/scoped login, post-auth storage, method
  isolation, diagnostics, Check Point error and light/dark rendering passed.
- Installed-app temporary-home tests preserved beta.6 and user fixtures,
  refused replacing a running app, preserved custom settings through one-time
  domain additions, and retained exact rollback bundles.
- Original alpha.2 archive hash verified; alpha.3 → alpha.2 installation in an
  isolated home preserved the durable map. Real installed beta.6 files still
  match the initial inventory byte for byte.
- Original TLS/pin/authentication/transport resources remain unchanged except
  local official-state classification in `trust.official_info`; build-time
  structural/resource comparison passed. Bundled-runtime TLS fixtures passed
  valid, wrong-name, expired, untrusted, pin/policy and redirect rejection cases;
  no application data was sent on rejected TLS cases. Handoff tests passed.
- DNS frontend UDP/TCP negative responses with missing backend/outside names
  passed. It now calls the native broker for bounded host-route operations.
- Fresh browser authentication succeeded. Ordinary Chrome and Safari displayed
  Jira; ordinary Yandex displayed its System Dashboard. OWA in Yandex reached
  a server authentication challenge; no password was entered for that test.
  The user separately confirmed OWA Widget working before and after sleep.
- Fresh curl requests to the established Jira/Confluence/OWA hosts returned
  401/302/302 with `ssl_verify_result=0`; Life returned 200. Initial probes of
  shorter, unestablished hostnames were refused and are not counted as success.
  Those two allocated synthetic names remain reserved; existing assignments
  were not recycled or changed.
- macOS power log: Software Sleep at 10:29:18 MSK, Wake from Deep Idle at
  10:29:23 MSK (five seconds). Work stopped, utun73/resolvers and both families
  of synthetic host routes were absent, and Life's default remained utun4.
  A new Work session and fresh verified HTTPS requests succeeded after waking.

**Check Point finding and limits.** On the main Mac the official
`com.checkpoint.epc.service` LaunchDaemon was running, with signed `trac info`
reporting `Idle`, both with Router routes off and on. Its GUI was not needed.
This is normal disconnected VPN state. Error handling recognizes explicit
service-not-started / VPN-Service-down / lost-service messages and separately
classifies timeout, failed command, unknown state and absent/ambiguous sites.
It never infers service failure merely from no active VPN.

The second Mac is not reachable through this environment. The user reports the
same official-service error with Router off, applications closed normally, and
again after reboot. This weakens a live-route-only explanation but does not
identify a broken daemon, unsupported installed version, management restriction
or leftover configuration. No cause-specific repair of Check Point is justified
yet. `checkpoint_diagnostic.py` / the standalone `Check Check Point.command`
collect only local read-only service/version/process/network evidence and
bounded, redacted OS error logs. The A/B/C route comparison is offered only if
the initial service probe responds. No registry, full authentication logs,
credentials or packets are collected or uploaded. A separate instruction file
for Codex on that Mac requests vendor compatibility checks and crash evidence
before any change. AdGuard VPN on that Mac remains unvalidated.

The test is a private Apple Silicon build, not a notarized public release.
Power-off boot, reboot with active routes, overnight/multiday operation and
long sleep are not yet executed; the normal reboot below, short physical sleep
and simulated lease loss do not substitute for those. Live code/password
authentication was not repeated in alpha.3.
Browser bypass modes (forced DoH/Private Relay) remain outside the earlier
supported scope. Ending routing removes interception and returns Work names to
the ordinary system resolver; this is not a permanent fail-closed DNS policy.

Final uncontaminated UI reconnect: normal Disconnect → Connect, with no
install/uninstall/admin testing in that interval. The app returned to Connected
and the user explicitly confirmed that no administrator prompt appeared.
OWA Widget after wake was also confirmed by the user. Work is left connected.

**Normal reboot, 12 November 2026.** The owner restarted macOS after a normal
Router quit. Boot time changed to 10:42:30 MSK. Before starting TUN Trial,
the root helper was already running (PID 528, run count 1, never exited),
inactive, with no pending cleanup. No utun73, owned resolvers or synthetic
routes remained. Sota was connected; signed Check Point state was Idle;
fresh Life HTTPS returned 200 with certificate verification. The checked
beta.6/alpha.3/client/root-helper/map hashes matched the pre-reboot snapshot.

The pre-existing beta.6 menu login item also launched. The owner then explicitly
requested that earlier Router launches be removed and only the latest version
remain. Its menu and HTTP LaunchAgents were backed up, disabled, unloaded and
removed from the user's LaunchAgents directory. The dedicated alpha.3 menu
LaunchAgent starts the installed TUN Trial with `--login`, RunAtLoad and no
KeepAlive. Real launchd bootstrap in the current Aqua session started alpha.3;
the old jobs and ports 1088/1089/1091 were absent. This is a local opt-in change,
not an automatic behavior of the private installer. No app bundle, root helper,
Check Point, external VPN or system proxy was changed. The new menu login item
has not yet been exercised by a second physical reboot. Reversible migration
and evidence are under `.private/helper-alpha3-evidence/reboot/`.

After this normal reboot the owner completed fresh browser MFA/Passkey and
explicitly confirmed no administrator password prompt and working OWA Widget.
The helper reported an active alpha.3 session. Ordinary Chrome rendered the
authenticated Jira/Tempo page; fresh direct curl requests returned Work
401/302/302 and Life 200, all with successful TLS verification. Signed official
Check Point state remained Idle. A normal UI disconnect then returned the
helper to inactive with no pending cleanup; utun73, owned resolvers and both
synthetic route families were absent, and Life HTTPS still returned 200.
The owner completed another browser login after the cleanup check; the UI
returned to Connected and Work was left enabled.

Final private archive: `Corporate-VPN-Router-0.3.0-alpha.3-private-arm64.zip`,
70,788,788 bytes, SHA-256
`9ee19ef8ca3203d80222b5c91d185e9b8c7cea392d4c196a6f76ad71db1403df`.
One app at ZIP root; extracted deep-strict signature and exact file inventory
match the candidate and installed alpha.3. No public upload/release/push.

## 2026-11-12 — alpha.4 first-use helper setup

The second Mac reported `HELPER_UNAVAILABLE`, then AppleScript syntax error
`-2741` from the explicit helper install action. Alpha.3 used a JSON-encoded
shell command as AppleScript source; escaped path separators are not valid
AppleScript string escapes. Compiling a representative command with the old
serialization failed locally (`-2740`). Alpha.4 passes the command and prompt
as argv to a fixed `on run` script. Shell path quoting remains separate.

Main-window setup now probes the helper without elevation. Missing, outdated,
unavailable and ready helpers expose install/update/restore/start actions in
the same window. Connection is disabled until a helper responds successfully.
After explicit maintenance, cancellation or failure, the main window is shown
with the result; success also requires a fresh helper status response.

Evidence in `.private/helper-alpha4-evidence/`:

- AppKit tests passed fresh-install controls, cancellation/retry, installation
  errors, failed verification, update, verified success, window visibility,
  duplicate-action prevention, prior login handling and light/dark rendering.
  The first test incorrectly assumed that `performClick` could not process an
  immediate mocked async reply and raised an assertion, causing a visible macOS
  crash dialog. A synchronized fixture fixed that assumption. Test failures now
  exit normally instead of raising an assertion crash.
- The exact privileged AppleScript compiled successfully. Its argv and shell
  handoff executed against an inert fixture with the privilege clause removed,
  including spaces, quotes, Cyrillic, backslash, dollar and backtick characters
  in the executable path. No system helper installation was performed.
- Disposable-home installation passed separate app placement, unchanged beta.6
  and user settings, active-app refusal, exact rollback and no new autostart.
  The packaged app recognized the real installed alpha.3 helper through its
  read-only status request without elevation or route setup.
- Package comparison against the SHA-256-pinned alpha.3 archive found exactly
  four changed files: app executable, Info.plist, INSTALLER_REVISION and app
  signature resources. Helper, enrolled client, routing/auth/TLS backend,
  runtime, work-site defaults and durable map are byte-identical. Rebuilding
  the native client changes its cdhash, so this UI-only patch explicitly reuses
  the verified alpha.3 helper payload to preserve existing enrollment.
- ZIP extraction, deep/strict signature verification, embedded version and
  single-app archive root passed. No public upload/release/push.

Artifact: `Corporate-VPN-Router-0.3.0-alpha.4-private-arm64.zip`, 70,795,559 bytes,
SHA-256 `bc0c69a8084187053293161d3d90c15cf70e56de331933eee44e356828fd79e5`.
The actual new administrator prompt/install and second-Mac connection remain
unverified; alpha.3 live network results above are not new alpha.4 live tests.

## 2026-11-12 — alpha.5 connection sequencing, trust and certificates

The subsequent report from the second Mac confirms alpha.4 OTP authentication
and coexistence with connected AdGuard VPN. It records routes ready at
11:02:28.580 MSK, gateway approval at 11:02:33.038 and cleanup at 11:02:46.099;
a second route session from 11:04:13.582 to cleanup at 11:04:27.444; and a third
session ready at 11:04:48.334, authenticated at 11:05:43.649, SSL ready at
11:05:44.864 and SOCKS ready at 11:05:45.220. There were no recorded route errors.
The first two SSL errors and exit codes were not retained. An earlier errno 2
has no named file or proven link to those exits. Their historical cause remains
unknown. The current successful state cannot reconstruct it.

Source inspection confirmed a separate UI defect: route cleanup could replace
the original SSL failure with a disconnected status. Alpha.5 latches the first
failure and records bounded, private state/code/errno/exit events. Connect now
orders helper readiness, route preparation, gateway verification and MFA.
Cleanup is verified before another attempt. No automatic authentication retry
or weakening of TLS is introduced. Journal contents deliberately exclude raw
stderr, prompts, identities, responses, tokens and passwords.

The private gateway manifest comes from the owner's approved existing working
configuration. Exact site/IP/CN/CA SHA-256 equality is required in addition to
the signed official client, its protected stored pin, DNS/IP agreement, SAN,
certificate validity and strict live TLS. Only the redundant first-use technical
dialog is omitted. This provenance is not claimed as independent IT approval.

Three current work HTTPS endpoints were probed through the existing SOCKS
route without weakening TLS: one returned 200 and two returned 302. Raw peer
chains and public CA certificates from the owner's existing Keychain identified
two roots and two intermediates. Explicit per-root OpenSSL chain/signature
verification succeeded, including root signatures; each chain matched one
root. Both intermediates are supplied by the servers. The original Mac needs
zero imports. The second Mac's required additions depend on its own trust.
Private hostnames, CA fingerprints and gateway configuration are not published.

The separate certificate wizard assesses fresh actual chains and the approved
CA set before proposing additions. Import requires exact fingerprint matching
and explicit consent, uses the user's login Keychain, and never imports keys.
Rollback checks ownership, exact DER and unchanged recorded user trust.
Corporate CA import/rollback was not performed on the already-working Mac;
positive real import/rollback and online revocation are not certified.

Evidence is local under `.private/alpha5-evidence/`:

- 88 core checks, including fresh/stale/wrong-host prospective chain checks,
  already-trusted no-import behavior and stale-import rejection.
- Isolated one-click flow: first and repeat authentication, retained gateway
  failure through cleanup, retry, route failure, cancellation before readiness
  and a journal without synthetic secrets. These fixtures do not establish
  the historical cause of the second Mac's SSL exits.
- Controller failures after partial begin, publish and heartbeat: original
  error precedes cleanup; pending cleanup blocks retry; no automatic begin loop.
- Strict TLS and gateway fixtures reject wrong names, expiry, untrusted chains,
  changed official pins, changed saved receipts, invalid manifests and redirects.
  Tests passed against the packaged runtime as well as the source fixture.
- Actual strict gateway first/repeat trust checks passed using temporary local
  receipts and the packaged code, with no technical confirmation callback.
  This did not start a new corporate MFA session or alter the live receipt.
- Disposable-home installation preserved beta.6, settings and an exact rollback
  copy; active-app refusal and absence of new autostart passed. The packaged
  client recognized the existing alpha.3 helper read-only.
- Certificate wizard light/dark rendering passed. No CA was imported.
- Existing menu regressions passed helper maintenance/cancellation/recovery,
  safe AppleScript argv handling, login persistence, service errors, private
  diagnostics and light/dark rendering. One outdated fixture expectation was
  corrected: standalone helper maintenance disables a concurrent Connect action.
  The test exited normally on that failed check; no application crash occurred.
- The archive round trip has one app at its root and passes deep/strict signing.
  Compared with alpha.4, seven existing files changed: native executable,
  Info.plist, installer revision, signature resources, trust.py, session.py and
  the selective controller. Public approved CA/gateway resources were added.
  Helper/client, TLS policy, SOCKS engine, runtime and work-site defaults remain
  byte-identical. The existing helper enrollment is preserved.

Icon metadata now includes the full app display name and `Router.icns`.
Installation registers only this app URL in the actual user's Launch Services;
disposable test homes are excluded. No global launcher/icon reset is performed.
The reported generic launcher icon still requires confirmation on the second Mac.

Candidate: `Corporate-VPN-Router-0.3.0-alpha.5-private-arm64.zip`, 70,961,674 bytes,
SHA-256 `2c158353e7f440c968e401f9582844f34d36aa10bf63c9620d4ce8cb93e0659d`.
Alpha.4 is preserved for rollback. The main Mac's installed app and active
session were not replaced; no public release, upload, commit or push occurred.
First/repeat alpha.5 MFA, AdGuard coexistence, HTTPS and launcher icon on the
second Mac are pending. The candidate is not represented as remotely validated.
