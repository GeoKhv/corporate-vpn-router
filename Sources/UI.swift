import AppKit

final class AppController: NSObject, NSApplicationDelegate {
    let paths: ProductPaths
    var window: NSWindow!
    let statusLabel = NSTextField(wrappingLabelWithString: "")
    let details = NSTextField(wrappingLabelWithString: "")
    let domains = NSTextField(string: ""), dns = NSTextField(string: "")
    let ports = NSTextField(string: "443"), port = NSTextField(string: "1089")
    var timer: Timer?
    var certificateWizard: CertificateWizard?
    init(paths: ProductPaths) { self.paths = paths }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu(), item = NSMenuItem(); menu.addItem(item)
        let appMenu = NSMenu(); appMenu.addItem(withTitle: "Quit Corporate VPN Router", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"); item.submenu = appMenu; NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 650), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Corporate VPN Router — Mac Beta \(productVersion)"
        window.center()
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 22)])
        let title = NSTextField(labelWithString: "Corporate SOCKS5, alongside your external VPN")
        title.font = .boldSystemFont(ofSize: 18); stack.addArrangedSubview(title)
        statusLabel.font = .boldSystemFont(ofSize: 14); stack.addArrangedSubview(statusLabel)
        details.font = .systemFont(ofSize: 12); stack.addArrangedSubview(details)
        let help = NSTextField(wrappingLabelWithString: "Sign in using your own Check Point app. Ask your administrator for the domain suffixes and corporate IPv4 DNS servers. Settings stay on this Mac. Beta is tested only with the documented macOS setup.")
        stack.addArrangedSubview(help)
        let c = (try? JSONDecoder().decode(Configuration.self, from: Data(contentsOf: paths.config))) ?? Configuration()
        domains.stringValue = c.domains.joined(separator: ", "); dns.stringValue = c.dnsServers.joined(separator: ", ")
        ports.stringValue = c.ports.map(String.init).joined(separator: ", "); port.stringValue = String(c.listenPort)
        for (label, input, placeholder) in [("Corporate domain suffixes (comma separated)", domains, "intranet.example.com, mail.example.com"), ("Corporate IPv4 DNS servers (comma separated)", dns, "192.0.2.53, 192.0.2.54"), ("Allowed TCP ports", ports, "443"), ("Local SOCKS5 port (loopback only)", port, "1089")] {
            stack.addArrangedSubview(NSTextField(labelWithString: label)); input.placeholderString = placeholder
            input.widthAnchor.constraint(equalToConstant: 590).isActive = true; stack.addArrangedSubview(input)
        }
        let row = NSStackView(); row.spacing = 8
        for (label, selector) in [("Save & Start", #selector(saveStart)), ("Stop", #selector(stop)), ("Check Point Login", #selector(login)), ("Diagnose", #selector(diagnose))] {
            let button = NSButton(title: label, target: self, action: selector); button.bezelStyle = .rounded; row.addArrangedSubview(button)
        }
        stack.addArrangedSubview(row)
        let row2 = NSStackView(); row2.spacing = 8
        for (label, selector) in [("Certificates & Permissions…", #selector(certificates)), ("Export PAC…", #selector(exportPAC)), ("Uninstall…", #selector(uninstall))] {
            let button = NSButton(title: label, target: self, action: selector); button.bezelStyle = .rounded; row2.addArrangedSubview(button)
        }
        stack.addArrangedSubview(row2)
        let note = NSTextField(wrappingLabelWithString: "Use remote DNS (SOCKS5h) with no direct fallback. Only listed corporate destinations are accepted. The app does not change system DNS, routes, proxy, certificates or VPN policies. Stop blocks configured SOCKS clients; check your client's own fallback behavior.")
        note.font = .systemFont(ofSize: 11); stack.addArrangedSubview(note)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in self.refresh() }
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func items(_ field: NSTextField) -> [String] { field.stringValue.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map { String($0).lowercased() } }
    func alert(_ message: String, detail: String = "") {
        let a = NSAlert(); a.messageText = message; a.informativeText = detail; a.runModal()
    }
    func refresh() {
        let s = readStatus(paths)
        let labels = ["UNCONFIGURED": "Set up your corporate connection", "STOPPED": "Proxy stopped", "WAITING_FOR_VPN": "Corporate VPN unavailable — requests blocked", "TUNNEL_READY": "Corporate tunnel detected — ready for a request", "READY": "Ready — last connection succeeded", "CONNECTION_BLOCKED": "Connection blocked — check DNS and routes", "RECOVERING": "Recovering — service heartbeat delayed"]
        statusLabel.stringValue = labels[s.state] ?? s.state
        details.stringValue = "\(s.listen)   •   \(s.activeConnections) connections   •   \(s.reason)"
    }
    @objc func saveStart() {
        do {
            var c = Configuration(); c.domains = items(domains); c.dnsServers = items(dns)
            let rawPorts = items(ports); c.ports = rawPorts.compactMap(Int.init)
            guard rawPorts.count == c.ports.count, let localPort = Int(port.stringValue) else { throw RouterError.invalidConfiguration }
            c.listenPort = localPort; _ = try c.validated()
            try Lifecycle.install(paths); try Lifecycle.save(c, paths: paths); try Lifecycle.start(paths); refresh()
        } catch { alert("Could not save or start", detail: "Check the domain suffixes, numeric IPv4 DNS servers and ports. Port must be free. Code: \((error as? RouterError)?.rawValue ?? "LOCAL_FILE_ERROR"). Existing legacy VPN service is separate.") }
    }
    @objc func stop() { do { try Lifecycle.stop(paths); refresh() } catch { alert("Could not stop the service", detail: "Code: \((error as? RouterError)?.rawValue ?? "LOCAL_ERROR")") } }
    @objc func login() {
        DispatchQueue.global().async {
            _ = command("/usr/bin/open", ["-a", "/Applications/Endpoint Security VPN.app"])
            _ = command(tracPath, ["connectgui"])
        }
    }
    @objc func diagnose() {
        DispatchQueue.global().async {
            let result = Diagnostics.run(paths: self.paths)
            DispatchQueue.main.async { self.alert("Local diagnostic summary", detail: jsonString(result)) }
        }
    }
    @objc func certificates() {
        if certificateWizard == nil { certificateWizard = CertificateWizard(paths: paths) }
        certificateWizard?.show()
    }
    @objc func exportPAC() {
        do {
            let text = try Diagnostics.pac(Configuration.load(paths.config))
            let panel = NSSavePanel(); panel.nameFieldStringValue = "corporate-private.pac"
            if panel.runModal() == .OK, let url = panel.url {
                try text.write(to: url, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                alert("Private PAC exported", detail: "Configure a client that enforces mandatory PAC and remote SOCKS DNS. This export does not change browser settings. A disabled or failed PAC can allow direct traffic in some clients.")
            }
        } catch { alert("Configure and save the service first") }
    }
    @objc func uninstall() {
        let a = NSAlert(); a.messageText = "Uninstall Corporate VPN Router?"
        a.informativeText = "The app and its launch agent will be removed. Private configuration is kept for reinstall. If you imported a CA, undo it first in Certificates & Permissions if desired; trust is never removed automatically. Your existing VPNs and legacy router are separate. Remove the proxy from your client afterward to restore normal browsing."
        a.addButton(withTitle: "Cancel"); a.addButton(withTitle: "Uninstall")
        if a.runModal() == .alertSecondButtonReturn {
            do { try Lifecycle.uninstall(paths); NSApp.terminate(nil) } catch { alert("Uninstall failed", detail: "Stop the service and retry with the documented command.") }
        }
    }
}
