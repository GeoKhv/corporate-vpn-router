# Windows adapter: planned, not supported

No Windows executable or installer is released. The Mac binary cannot run on Windows. The interfaces below define implementation work, not demonstrated compatibility.

`VPNPlatform` must have an independent Windows implementation. It must identify the actual corporate interface using the installed Check Point version's supported status and Windows interface LUID/index, verify routes against its encryption domain, pin IPv4 DNS/TCP with the correct Windows socket options/source address, and invalidate all sockets on interface, route or network change. A Darwin option number must never be reused on Windows. Default DNS, WPAD and automatic DIRECT fallback are forbidden on the corporate path.

The Windows certificate wizard must implement the same states: UNCHECKED, PRESENT, VALID, SYSTEM_TRUSTED, SOURCE_UNCONFIRMED, MISSING, EXPIRED, NAME_MISMATCH, CLIENT_ENROLLMENT_REQUIRED, USER_CONSENT_REQUIRED, IMPORTED, RECHECK_REQUIRED and UNDONE. The serialized public certificate metadata (subject, issuer, validity, SHA-256, CA role) and the guarded import receipt are shared concepts; OS trust operations are not shared code.

Use Windows chain/hostname validation and the appropriate certificate stores. A new approved root belongs in CurrentUser Root only if policy permits; an intermediate in CurrentUser CA without a root trust override. LocalMachine and domain/GPO-managed roots require an administrator/IT deployment path. CurrentUser/My, LocalMachine/My, smart cards and private keys are individual enrollment concerns; never ship, export or copy them. HTTPS-inspection CA is conditional and must have independent IT confirmation. Detect GPO restrictions rather than bypassing them. Explicit consent and exact-hash rollback must precede every trust mutation.

## Required real-device validation

- Record actual Windows edition/build, CPU architecture, Check Point version, VPN mode and external VPN version. Verify interface identity and socket constraints against packet capture and route inspection.
- Install/uninstall as a standard user; exercise UAC denial, locked stores, GPO/MDM restrictions, upgrade failure and rollback without changing existing trust or credentials.
- Test missing/expired/wrong-name/untrusted chains, missing intermediate, HTTPS inspection, revoked certificates under the chosen offline/online policy, root import consent/cancel, fingerprint mismatch and exact-hash undo in an isolated test organization.
- Test password/IdP/MFA and, if applicable, real user and machine certificate enrollment, renewal, non-exportable keys and smart cards. Absence of an identity in one store is not proof that no certificate is required.
- Verify Windows services, drivers, firewall/network filtering, required approvals, sleep/hibernate, fast startup, reboot/login, Wi-Fi/Ethernet changes, proxy crash and VPN loss/recovery.
- Demonstrate DNS/TCP non-leakage at the external interface for supported client configurations, including browser/PAC failure and bypass behavior.
- Produce signed installable artifacts only after a full clean-machine test and a private-data audit. Do not label a scaffold or cross-compiled artifact supported.

See `Sources/Core.swift` for the current platform boundary and `docs/CERTIFICATES.ru.md` for the user consent rules. A Windows implementation remains required work before a Windows beta can be advertised.
