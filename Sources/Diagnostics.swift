import Foundation
import Darwin

struct DiagnosticReport: Codable {
    var version = productVersion
    var platform = "macOS-arm64"
    var configurationValid = false
    var checkpointCLIInstalled = false
    var tunnelReady = false
    var listenerReachable = false
    var dnsProbe = "NOT_REQUESTED"
    var destinationRoute = "NOT_REQUESTED"
    var tcpProbe = "NOT_REQUESTED"
    var reason = "UNCONFIGURED"
    var certificateStatus = "NOT_CHECKED_OPEN_CERTIFICATE_WIZARD"
    var scope = "Local checks only. No TLS, login, sleep, reboot or browser guarantee. No raw diagnostics collected."
}

enum Diagnostics {
    static func run(paths: ProductPaths, probe: String? = nil) -> DiagnosticReport {
        var report = DiagnosticReport()
        report.checkpointCLIInstalled = FileManager.default.isExecutableFile(atPath: tracPath)
        guard let config = try? Configuration.load(paths.config) else { return report }
        report.configurationValid = true
        if !Certificates.preferences(paths).hosts.isEmpty { report.certificateStatus = "ENDPOINTS_CONFIGURED_RUN_CERTIFICATE_WIZARD_FOR_LIVE_TLS" }
        if let s = try? OwnedSocket(Darwin.socket(AF_INET, SOCK_STREAM, 0)) {
            s.timeouts(1)
            let adapter = MacOSAdapter()
            if (try? adapter.connectSocket(s, address: "127.0.0.1", port: config.listenPort)) != nil { report.listenerReachable = true }
            s.close()
        }
        let platform = MacOSAdapter(), snapshot = platform.discover(dnsServers: config.dnsServers)
        report.reason = snapshot.reason
        guard let link = snapshot.link else { return report }
        report.tunnelReady = true
        guard let host = probe else { return report }
        guard config.permits(host, port: 443) else { report.reason = "PROBE_REQUIRES_ALLOWLISTED_HOST_AND_PORT_443"; return report }
        let session = Session(); defer { session.cancel() }
        do {
            let answers = try platform.resolve(host: host, servers: config.dnsServers, link: link, session: session)
            report.dnsProbe = "PASS"
            let routed = answers.filter { platform.routeAllowed(address: $0, link: link) }
            guard !routed.isEmpty else { throw RouterError.routeDenied }
            report.destinationRoute = "PASS"
            var connected = false
            for addr in routed {
                if let s = try? platform.connect(address: addr, port: 443, link: link, session: session) { session.remove(s); connected = true; break }
            }
            guard connected else { throw RouterError.io }
            report.tcpProbe = "PASS"; report.reason = "DNS_ROUTE_TCP_PASS"
        } catch {
            if report.dnsProbe == "NOT_REQUESTED" { report.dnsProbe = "FAIL" }
            else if report.destinationRoute == "NOT_REQUESTED" { report.destinationRoute = "FAIL" }
            else { report.tcpProbe = "FAIL" }
            report.reason = (error as? RouterError)?.rawValue ?? "PROBE_FAILED"
        }
        return report
    }

    static func pac(_ c: Configuration) throws -> String {
        _ = try c.validated()
        let encoded = try JSONEncoder().encode(c.domains)
        let domains = String(data: encoded, encoding: .utf8)!
        return """
        // Private local configuration. Consumer must enforce mandatory PAC and remote SOCKS DNS.
        // The product does not install this PAC or guarantee a browser's fallback behavior.
        function FindProxyForURL(url, host) {
          host = host.toLowerCase().replace(/\\.$/, '');
          var domains = \(domains);
          for (var i = 0; i < domains.length; i++) {
            var d = domains[i];
            if (host === d || host.slice(-(d.length + 1)) === '.' + d)
              return 'SOCKS5 127.0.0.1:\(c.listenPort)';
          }
          return 'DIRECT';
        }
        """
    }
}

func jsonString<T: Encodable>(_ value: T) -> String {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return (try? String(data: encoder.encode(value), encoding: .utf8)) ?? "{}"
}

func readStatus(_ paths: ProductPaths) -> PublicStatus {
    let config = try? Configuration.load(paths.config)
    let fallback = PublicStatus(state: config == nil ? "UNCONFIGURED" : "STOPPED", reason: config == nil ? "CONFIGURE_DOMAINS_AND_DNS" : "START_SERVICE", listen: "127.0.0.1:\(config?.listenPort ?? 1089)", activeConnections: 0, generation: 0)
    let job = command("/bin/launchctl", ["print", paths.service])
    guard job.code == 0, let data = try? Data(contentsOf: paths.state),
          var status = try? JSONDecoder().decode(PublicStatus.self, from: data) else { return fallback }
    if status.state != "PROXY_FAILED" && !job.output.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "state = running" }) {
        status.state = "RECOVERING"; status.reason = "LAUNCHD_RESTART_PENDING"
    } else if abs(Date().timeIntervalSince1970 - status.updatedAt) > 7 {
        status.state = "RECOVERING"; status.reason = "SERVICE_HEARTBEAT_STALE"
    }
    return status
}
