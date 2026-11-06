import Foundation
import AppKit
import Darwin
import Security

umask(0o077)
var args = Array(CommandLine.arguments.dropFirst())
var root: String?
if let i = args.firstIndex(of: "--root") {
    guard i + 1 < args.count, args[i+1].hasPrefix("/") else { fputs("--root needs an absolute test directory\n", stderr); exit(2) }
    root = args[i+1]; args.removeSubrange(i...i+1)
}
let paths = ProductPaths(root: root)
let mode = args.first ?? "--ui"
do {
    switch mode {
    case "--version": print(productVersion)
    case "--help":
        print("""
        Corporate VPN Router \(productVersion) — macOS Apple Silicon Beta
        --ui                       Open local settings (default)
        --install                  Install per user; starts only after configuration
        --configure FILE           Validate/copy private config; preserve previous config
        --start | --stop           Manage only this product's launch agent
        --status                   Redacted local service state
        --diagnose [HOST]          Redacted checks; optional allowlisted DNS/route/TCP probe
        --certificates [HOST ...]  PRIVATE live HTTPS chains, validity and system trust
        --inspect-ca FILE          PRIVATE metadata only; never imports or changes trust
        --find-ca NAME             PRIVATE matching public CA metadata from Keychain
        --permissions              Check Point signature, service and approval indicators
        --gateway-certificate      PRIVATE configured site HTTPS; normal route, not IKE
        --export-pac FILE          Export private PAC; no automatic client configuration
        --restore-config           Restore previous private configuration
        --rollback                 Restore previous product app after an upgrade
        --uninstall [--purge]       Remove app/agent; --purge also deletes private settings
        --root ABSOLUTE_DIRECTORY  Isolated install/test tree (uses same launchd label)
        No commands change system DNS, routing, certificates or other VPN services.
        """)
    case "--install": try Lifecycle.install(paths); print("Installed. Open the app to configure your corporate domains and DNS.")
    case "--configure":
        guard args.count == 2 else { throw RouterError.invalidConfiguration }
        try Lifecycle.save(Configuration.load(URL(fileURLWithPath: args[1])), paths: paths); print("Private configuration saved.")
    case "--start": try Lifecycle.start(paths); print("Service loaded. Use --status to check readiness.")
    case "--stop": try Lifecycle.stop(paths); print("Service stopped.")
    case "--status": print(jsonString(readStatus(paths)))
    case "--diagnose": print(jsonString(Diagnostics.run(paths: paths, probe: args.count > 1 ? args[1] : nil)))
    case "--permissions": print(jsonString(CheckPointPermissions.inspect()))
    case "--gateway-certificate":
        guard let host = CheckPointPermissions.siteHost() else { throw RouterError.vpnUnavailable }
        print(jsonString(HTTPSCertificates.inspect(host: host, configuration: Configuration(), controlPlane: true)))
    case "--certificates":
        let config = try Configuration.load(paths.config)
        let hosts = args.count > 1 ? Array(args.dropFirst()) : Certificates.preferences(paths).hosts
        guard !hosts.isEmpty, hosts.count <= 16 else { throw RouterError.invalidConfiguration }
        print(jsonString(hosts.map { HTTPSCertificates.inspect(host: $0, configuration: config) }))
    case "--inspect-ca":
        guard args.count == 2 else { throw RouterError.invalidConfiguration }
        print(jsonString(Certificates.describe(try Certificates.parse(Data(contentsOf: URL(fileURLWithPath: args[1]))))))
    case "--find-ca":
        guard args.count == 2, !args[1].isEmpty else { throw RouterError.invalidConfiguration }
        print(jsonString(Certificates.inventory().filter { (SecCertificateCopySubjectSummary($0) as String? ?? "").localizedCaseInsensitiveContains(args[1]) }.map { Certificates.describe($0) }))
    case "--export-pac":
        guard args.count == 2 else { throw RouterError.invalidConfiguration }
        let url = URL(fileURLWithPath: args[1])
        try Diagnostics.pac(Configuration.load(paths.config)).write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        print("Private PAC exported. Configure mandatory PAC and remote SOCKS DNS in the consumer.")
    case "--restore-config":
        let previous = try Configuration.load(paths.data.appendingPathComponent("config.previous.json"))
        try Lifecycle.save(previous, paths: paths); print("Previous private configuration restored.")
    case "--rollback": try Lifecycle.rollback(paths); print("Previous product app restored.")
    case "--uninstall": try Lifecycle.uninstall(paths, purge: args.contains("--purge")); print("Product removed. Reconfigure SOCKS clients if needed.")
    case "--service":
        try paths.createData()
        let config = try Configuration.load(paths.config)
        let service = RouterService(configuration: config, platform: MacOSAdapter(), statusURL: paths.state)
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        term.setEventHandler { service.stop(); exit(0) }; interrupt.setEventHandler { service.stop(); exit(0) }
        term.resume(); interrupt.resume()
        do { try service.run() }
        catch {
            try? JSONFile.write(PublicStatus(state: "PROXY_FAILED", reason: "LISTENER_UNAVAILABLE", listen: "127.0.0.1:\(config.listenPort)", activeConnections: 0, generation: 0), to: paths.state)
            throw error
        }
        withExtendedLifetime((term, interrupt)) {}
    case "--ui":
        let app = NSApplication.shared, delegate = AppController(paths: paths)
        app.delegate = delegate; app.run(); withExtendedLifetime(delegate) {}
    default: throw RouterError.invalidConfiguration
    }
} catch {
    fputs("Corporate VPN Router: \((error as? RouterError)?.rawValue ?? "localFileError"). See --help.\n", stderr)
    exit(1)
}
