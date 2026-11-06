# Mac Beta validation

Recorded locally on 2026-11-06. This is a manually curated summary, not a diagnostic snapshot. No corporate hostnames, IPs, certificates, configuration, logs or identities are published here.

## Test environment and scope

- macOS 27.0.1, Apple Silicon arm64.
- Installed Check Point Endpoint Security VPN, bundle build `986203103`, active IdP authentication. Authentication was not migrated or shared.
- External VPN in the test environment: Sota Connect 1.7.7. The product neither depends on it nor manages it. Other external VPNs and other Check Point builds remain unverified.
- New product on a separate loopback port alongside a private compatibility helper. Private routing rules and individual authentication were retained. The native installer/diagnostics do not write system proxy, DNS or routing settings or automatically change certificate trust.

## Completed

| Check | Result | Evidence boundary |
|---|---|---|
| Native arm64 build, ad-hoc signature verification | PASS | Local build/run, no Python runtime dependency |
| Local policy, DNS parser, SOCKS relay and simulated failures | PASS: 83 assertions | Includes denied suffix/IP/IPv6/UDP/ports, no DNS on denied requests, route denial, simulated VPN/network change/recovery and vendor-command I/O isolation |
| Darwin interface binding | PASS | `IP_BOUND_IF` applied and read back on a real socket |
| Untrusted TLS test server | PASS | System trust failure aborts TLS; no HTTP application data received by the fixture |
| Certificate consent/source/fingerprint rejection paths | PASS | No Keychain mutation; no consent, wrong hash, insecure/credential/token URL, private key and bundle rejected |
| Corporate HTTPS via SOCKS5h | PASS | Verified TLS and HTTP response; no account cookies or successful application login implied |
| OWA / Jira / Confluence diagnostic HTTPS HEAD | PASS | TLS validation passed; responses 302 / 200 / 302 respectively |
| Certificate wizard UI | PASS | Settings, readable result pane, live HTTPS output and refusal without IT confirmation observed |
| Check Point signature/service/authentication indicators | PASS for observed state | Missing Network Extension listing is reported separately and is not treated as proof of missing permission |
| TrustSettings/public certificate inventory before/after inspection | UNCHANGED | Existing trust was preserved; corporate authenticity was not inferred from trust |
| Native monitor liveness | PASS | 40 consecutive ready samples; heartbeat age no more than 1.98 s |
| Real Beta process crash | PASS | Request refused during crash, launchd recovery 9.45 s, verified HTTPS after recovery |
| Real Beta process suspension | PASS | Stale heartbeat reported RECOVERING; request timed out; recovered after SIGCONT. This is not a real sleep test |
| Stop and busy loopback port | PASS | Stop removes product LaunchAgent; stopped proxy refuses connection; occupied port reports PROXY_FAILED |
| Installation/configuration/backup/rollback/uninstall | PASS | File lifecycle exercised in a separate temporary install tree; unrelated app namespace preserved |
| Actual Check Point disconnect | PASS for blocking | Existing relay closed, all 12 new test requests refused while disconnected. Normal interactive IdP login was required. A hung passkey attempt was cancelled; a fresh vendor GUI request completed. No keys or trust were reset |
| External VPN packet observation during loss | PASS within observed scope | Zero matching packets for the finite corporate DNS/test-HTTPS filter on the current external VPN interface during a five-minute observation. Packet payloads were not saved. Physical egress was not captured |
| Physical network change and return | PASS | Multiple physical IPv4/network states observed. Wi-Fi itself required reauthentication. Beta recovered without a manual restart; both proxies passed HTTPS afterward. Overall interruption is not a Router recovery-time SLA |
| Real macOS sleep/wake | PASS for Beta | OS Sleep/User Wake counters incremented, service generations changed, verified HTTPS returned without restarting Beta. Short sleep only |
| Existing compatibility helper after sleep | RESTORED | It answered SOCKS greeting and updated state, but HTTPS requests timed out; restarting its original LaunchAgent restored HTTPS. This behavior is separate from the native Beta |
| Real reboot and login autostart | PASS | Boot-session UUID changed. Beta was already running on the first read, with one launch, fresh state and the same automatically started PID throughout verification. Binary, configuration and LaunchAgent matched preboot hashes. No manual Beta start was used |
| Corporate path after boot | PASS | With Check Point off, first state was WAITING_FOR_VPN. Once the VPN was Connected, all three configured corporate services passed HTTPS through the automatically started Beta |
| Private browser-helper startup dependency | FIXED LOCALLY | Selected external rules still use the old loopback helper. Its corporate/external monitors were separated and its process class updated with backups; private configuration and routing methods remained unchanged. With a simulated 30 s corporate read delay, external readiness was 0.1 s and verified HTTPS succeeded; live process restart to external HTTPS took 0.75 s. These are controlled smoke timings, not a cold-boot/browser SLA |
| Preservation after boot | PASS within recorded scope | Private configuration and certificate inventory/TrustSettings matched the initial comparisons. System web/SOCKS proxy matched the valid preboot host snapshot. Local compatibility-helper source/agent changes were intentional, backed up and separately reversible |

## Remaining coverage gaps

| Scenario | Status |
|---|---|
| Physical-interface packet capture / all-client non-leakage | NOT ESTABLISHED; scoped external-VPN observation does not provide a host-wide guarantee |

## Explicit limitations

- This is an experimental prerelease for a controlled pilot, not broad production certification.
- Downloaded/quarantined installation on a separate clean Mac, Developer ID signing and notarization are not completed. Local install/signature checks do not prove Gatekeeper acceptance.
- macOS 13 is a compilation target only. macOS versions other than 27.0.1, Intel, different Check Point modes and other external VPN products are not verified.
- Windows has an architecture/validation plan only. No supported Windows build exists.
- No authenticated browser application login was tested for the new product. PAC/extension failure, browser bypass, DoH and clients that fall back to DIRECT are outside the demonstrated SOCKS guarantee.
- During the controlled disconnect, Beta was temporarily stopped to isolate a hanging interactive passkey login. The original path recovered after a fresh normal login, then Beta was restarted. Automatic Beta recovery was subsequently demonstrated during physical network and sleep transitions; automatic MFA/passkey approval is not provided.
- The network-change test included separate Wi-Fi reauthentication; the user observed a few minutes of unavailable mail during the transition. This must not be reported as a measured Router-only recovery time.
- Full cold boot and sleep were not repeated after the private compatibility-helper maintenance. Native Beta boot/sleep evidence remains independent of that helper. The complete initial browser-delay timeline was not captured, so the discovered startup dependency is not claimed to explain every second of that delay.
- VPN interface ownership uses route/peer evidence, not a vendor attestation. Different VPN topologies require independent tests.
- No independent authorized corporate certificate source was available. CA authenticity remains unconfirmed. No new real CA was installed or removed; consented import/undo still needs an authorized pilot with IT.
- TLS diagnostics evaluate local trust/hostname/validity offline. Online revocation, all possible SSO/client-certificate flows and every Check Point OS approval are not certified.
- The configured Check Point site's HTTPS certificate failed system SSL policy in the observed environment. It was not trusted automatically. Its HTTPS chain is not proof of the IKE gateway chain or a reason to alter working Check Point trust.
- There is no host-wide firewall, multi-user authentication, transparent routing, IPv6 transport or UDP forwarding. Only explicit SOCKS5 domain CONNECT is supported.

All tests above were run locally. GitHub Actions are disabled; no workflow is part of this repository.
