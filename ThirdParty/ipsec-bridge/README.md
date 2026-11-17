# Corporate VPN Router IPsec test bridge

This is a process-isolated derivative of snx-rs 6.6.1 / isakmp under AGPL-3.0.
It is built only for the optional macOS arm64 test candidate. It does not install
a service, create a TUN interface, change routes/DNS, or assert SCV compliance.
The normal SSL worker remains available and is selected unless the pinned SSL
empty-session preflight explicitly returns 205.

`src/main.rs` implements a bounded anonymous-pipe protocol. The Router supplies
a fresh CCC ClientHello obtained over its existing CA + leaf + hostname policy.
The IKE signing certificate must either match that authenticated identity itself,
or have a valid chain to a matching CA. Merely appending a trusted certificate
is not sufficient. The gateway's IKE signature is checked before MFA.
Missing trust and IKEv2-only/preferred configurations are refused by this test
bridge. Only the two-password OTP realm is exposed by the Router integration.

`run_ipsec` in Backend/ipsec_session.py forwards IPv4 datagrams to the existing
restricted SOCKS worker. Listener readiness and process ownership are verified
before route activation. SIGTERM, errors and parent loss stop owned processes.
No session keys or cookies are persisted. Rust tracing is disabled; diagnostic
text is filtered against a fixed word vocabulary by the Python parent.

OpenSSL is statically linked with no DSO loading. Its unused build-specific
engine/provider directory strings are replaced with a fixed nonexistent path
by `openssl-paths.patch`; cryptographic operations are not modified.

## Sources and reproduction

Pinned upstream snx-rs: 7ef1327ced2809d84cb02992e2a38e6b7e168f7b.
Pinned upstream isakmp: ce07353f7a1e3f62ef3a200bca34e3de0f72d0dc.
OpenSSL source crate: see Cargo.lock. The release source ZIP contains the full
modified trees and vendored Cargo dependencies, including OpenSSL source.
The workspace contains only the bridge and its libraries; upstream GUI/service
applications are not shipped. Their optional mobile-access feature is not used.

On an Apple Silicon Mac with Xcode command-line tools and Rust 1.100.0:

    cd source/snx-rs
    ./build-router.sh

This builds target/release/cvr-ipsec without network access. Runtime credentials
must never be supplied on a command line or in a configuration file. The bridge
is started only by Router and consumes its configuration over anonymous stdin.

Validation uses the complete shipped-workspace fmt/clippy gates and unit/integration
suites. System Keychain tests are explicitly skipped to preserve the developer's
login keychain. All network tests use fixtures/loopback servers. A separate live
probe verifies the gateway IKE identity without username, password, OTP, session
configuration, routes or DNS changes. The recipient reported successful OTP/password authentication and working corporate
and external sites in 0.3.18. Fresh login with 0.3.19, reconnect, sleep/wake and
long-running operation remain acceptance tests; preflight alone is not a
successful user connection.

0.3.18 removes the unused post-authentication CCC ClientSettings request. The upstream TUN uses it for OS route ranges and an optional internal gateway address. This bridge uses neither: Office Mode IP/DNS and ESP material come from authenticated IKE, and Router applies its existing restricted SOCKS policy. Gateway authorization, certificate validation and MFA are unchanged. A rejected CCC request is never treated as success; this unused request is no longer sent.

0.3.19 restores selected-realm custom factor labels for generic password prompts. Explicit dynamic prompts remain authoritative; missing labels retain their factor positions. No factors or credential submissions are invented or skipped.

Complete source/dependencies: [0.3.19 release](https://github.com/GeoKhv/corporate-vpn-router/releases/tag/v0.3.19-ipsec-test). Archive hashes: [release manifest](../../docs/releases/0.3.19.json).
