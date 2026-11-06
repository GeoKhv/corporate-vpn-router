# Architecture and trust boundary

## Components

- `Core.swift`: configuration, suffix/port policy, platform boundary, redacted state.
- `DNS.swift`: bounded DNS A/CNAME parser, question/transaction validation, TCP retry for truncation.
- `MacOS.swift`: Check Point status, tunnel discovery, route ownership, interface/source binding and DNS/TCP I/O.
- `Proxy.swift`: SOCKS5 domain CONNECT, bounded sessions, relay cancellation and freshness watchdog.
- `Lifecycle.swift`: per-user install, launchd supervision, policy update, backup, rollback and uninstall.
- `Certificates.swift`: public certificate inspection, strict hostname-aware system trust, guarded CA import and scoped undo.
- `CertificateWizard.swift`: first-run certificate workflow and Check Point permission indicators; no enrollment or credential storage.
- `UI.swift` / `main.swift`: local settings and CLI. No local web server, telemetry, updater or remote control API.

The existing working local prototype supplied the routing algorithm. This distribution is a native Swift implementation with a separate product namespace and no embedded organization or external VPN configuration.

## Routing invariants

1. An explicit domain suffix and port allowlist is required. IP/IPv6/UDP requests never cause upstream work. No SOCKS authentication is provided: local processes belonging to other users of the same Mac may reach loopback. Do not use the beta on an untrusted multi-user host.
2. Check Point must report Connected. All configured DNS routes must select one `utun` and one IPv4 peer. Its point-to-point source must differ from its peer; the public reference route must use another interface. Interface indices are discovered, never hardcoded.
3. Discovery uses the prototype's route/peer evidence. It is a heuristic, not a vendor-provided cryptographic mapping of a utun to Check Point. A different VPN's topology can invalidate the assumptions. Such combinations are unsupported until tested, even if discovery happens to succeed.
4. Every DNS and destination route is checked. Every socket uses Darwin `IP_BOUND_IF`, verifies the option was accepted, then binds the tunnel source IPv4. A failed bind, DNS query or route check rejects the request. No resolver fallback or route mutation exists.
5. Network signature, source, peer, interface or index changes increment a generation and cancel all current sessions. A separate watchdog invalidates observations older than six seconds. Every relay chunk rechecks the generation/freshness; socket shutdown prevents an already checked write from surviving cancellation.
6. DNS TTL caching is deliberately absent. DNS timeouts and failed state reads are retried only inside the corporate path. Old sessions are never migrated to a new interface.

The product does not enforce a host-wide packet filter and cannot stop a client from making its own direct connection. DNS prefetch, DoH, PAC failure, bypass lists, extension disablement and direct browser login remain client integration concerns. No claim of browser-wide non-leakage is made by a SOCKS unit test.

## Certificates

HTTPS diagnostics reuse the same corporate adapter for DNS and transport. Network.framework provides TLS 1.2/1.3 through a one-use loopback bridge to the already bound corporate socket; it never opens a second unbound service connection. The TLS verification callback requires hostname-aware `SecTrustEvaluateWithError` with network fetching disabled. A negative result aborts TLS before HTTP. No allow-expired, allow-hostname-mismatch, insecure curl option, custom permissive anchor or trust-all callback is used. A successful TLS trust result still does not establish independent corporate source authenticity. Normal proxied applications perform their own TLS verification; the Router does not intercept their TLS.

Only a single valid public CA with an independently entered matching SHA-256 and explicit consent can enter the import path. Roots get user SSL trust; intermediates get no trust override. Existing certificates are not modified. Receipts are written before mutation for crash recovery. Undo is exact-hash and login-keychain scoped; system/admin certificates and client identities are outside this mechanism. Rollback of a failed or interrupted trust import requires reviewing the retained receipt and the actual Keychain state.

The optional Check Point site HTTPS diagnostic is explicitly separate control-plane traffic over the system route to the site reported by the vendor CLI. It sends no credentials. It is not IKE certificate inspection and cannot be repurposed to probe arbitrary corporate hosts through that route.

## Lifecycle

The service is `com.geokhv.corporate-vpn-router`, independent of legacy router labels and ports. `launchd` starts it at user login and restarts crashes with a 10-second throttle. There is no pre-login daemon and no automatic VPN login. The service rediscovers after a network transition; MFA/session expiry stays in Check Point.

Installation stages an app copy, preserves the previous product app, and restores it on failure. Configuration changes unload the service before replacing policy and preserve the previous configuration. Stop removes this product's LaunchAgent; start recreates it. Uninstall does not silently undo CA trust: that needs separate explicit consent. Purge is blocked while import receipts remain active.

All private settings use a user-only directory and files. Public status contains no hostnames, tunnel IPs or vendor command output. Certificate diagnostic output is private by design. Temporary vendor output is mode 0600 in a mode 0700 temporary directory and is removed after each read. No raw vendor logging is persisted.
