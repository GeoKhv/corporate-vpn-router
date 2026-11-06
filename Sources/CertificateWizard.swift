import AppKit
import Security
import UniformTypeIdentifiers

final class CertificateWizard: NSObject {
    let paths: ProductPaths
    var window: NSWindow!
    let hosts = NSTextField(string: ""), source = NSTextField(string: ""), expected = NSTextField(string: "")
    var report = NSTextView()
    var selectedCertificate: SecCertificate?
    let confirmed = NSButton(checkboxWithTitle: "I verified this SHA-256 through an authorized IT channel, independently of this file/server.", target: nil, action: nil)
    init(paths: ProductPaths) { self.paths = paths }
    func show() {
        if window != nil { window.makeKeyAndOrderFront(nil); return }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: 760), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Certificate setup — Corporate VPN Router"; window.center(); window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 780, height: 760)
        let stack = NSStackView(); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 10; stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -20), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 20)])
        let intro = NSTextField(wrappingLabelWithString: "1. Check corporate HTTPS and Check Point permissions. 2. Obtain missing CA files and independent SHA-256 from your IT team. 3. Review and explicitly approve each import. 4. Repeat the HTTPS check. Existing certificates are never replaced here. Client identities must be enrolled through your organization.")
        stack.addArrangedSubview(intro)
        stack.addArrangedSubview(NSTextField(labelWithString: "Corporate HTTPS hosts (comma separated, already in your allowlist)"))
        hosts.placeholderString = "mail.corp.example.com, wiki.corp.example.com"; hosts.stringValue = Certificates.preferences(paths).hosts.joined(separator: ", ")
        hosts.widthAnchor.constraint(greaterThanOrEqualToConstant: 720).isActive = true; stack.addArrangedSubview(hosts)
        let first = NSStackView(); first.spacing = 10
        for (label, action) in [("Check HTTPS & permissions", #selector(check)), ("Site HTTPS", #selector(gateway)), ("Review CA file…", #selector(choose))] {
            first.addArrangedSubview(NSButton(title: label, target: self, action: action))
        }
        stack.addArrangedSubview(first)
        stack.addArrangedSubview(NSTextField(labelWithString: "Authorized IT source URL (HTTPS, no passwords or token query)"))
        source.placeholderString = "https://it.corp.example.com/certificates"; source.widthAnchor.constraint(greaterThanOrEqualToConstant: 720).isActive = true; stack.addArrangedSubview(source)
        stack.addArrangedSubview(NSTextField(labelWithString: "Independently confirmed SHA-256 (paste the IT-provided fingerprint)"))
        expected.widthAnchor.constraint(greaterThanOrEqualToConstant: 720).isActive = true; stack.addArrangedSubview(expected)
        stack.addArrangedSubview(confirmed)
        let second = NSStackView(); second.spacing = 10
        second.addArrangedSubview(NSButton(title: "Review & Import…", target: self, action: #selector(importCA)))
        second.addArrangedSubview(NSButton(title: "Undo an import…", target: self, action: #selector(undo)))
        stack.addArrangedSubview(second)
        let scroll = NSTextView.scrollableTextView(); scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder
        report = scroll.documentView as! NSTextView
        report.isEditable = false; report.font = .monospacedSystemFont(ofSize: 11, weight: .regular); report.isVerticallyResizable = true
        report.autoresizingMask = [.width]; report.textContainer?.widthTracksTextView = true
        window.contentView!.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 20), scroll.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -20), scroll.topAnchor.constraint(equalTo: stack.bottomAnchor, constant: 12), scroll.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -20), scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 220)])
        report.string = "No certificate changes made. Results are private and stay in this window. Local trust is not proof of corporate authenticity."
        window.makeKeyAndOrderFront(nil)
    }
    func alert(_ message: String, _ detail: String) { let a = NSAlert(); a.messageText = message; a.informativeText = detail; a.runModal() }
    @objc func check() {
        let list = hosts.stringValue.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map { String($0).lowercased() }
        do { try Certificates.saveHosts(list, paths: paths) }
        catch { alert("Save the main configuration first", "Every HTTPS host must be in the corporate allowlist with port 443 permitted."); return }
        report.string = "Checking. No trust changes, credentials, cookies or private keys are used."
        DispatchQueue.global().async {
            guard let config = try? Configuration.load(self.paths.config) else { return }
            let permissions = CheckPointPermissions.inspect()
            let results = list.map { HTTPSCertificates.inspect(host: $0, configuration: config) }
            let text = "PRIVATE LOCAL RESULTS\n\(jsonString(permissions))\n\(jsonString(results))\n\nSource authenticity must still be confirmed with IT. HTTP 401/302 can indicate a reachable service requesting normal login. No browser session was tested."
            DispatchQueue.main.async { self.report.string = text }
        }
    }
    @objc func choose() {
        let panel = NSOpenPanel(); panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        panel.allowedContentTypes = ["cer", "crt", "pem", "der"].compactMap { UTType(filenameExtension: $0) }
        if panel.runModal() == .OK, let url = panel.url {
            do {
                let certificate = try Certificates.parse(Data(contentsOf: url))
                selectedCertificate = certificate; confirmed.state = .off; expected.stringValue = ""
                report.string = "PRIVATE CA FILE REVIEW\n\(jsonString(Certificates.describe(certificate)))\n\nThe displayed fingerprint is computed from this file. Obtain the expected fingerprint independently from IT. Do not copy this value into the confirmation field without independent verification."
            } catch { selectedCertificate = nil; alert("Not a single public certificate", "Only a single DER or PEM certificate is accepted. Private keys, identity bundles and certificate bundles are rejected.") }
        }
    }
    @objc func gateway() {
        let a = NSAlert(); a.messageText = "Inspect the configured Check Point site's HTTPS?"
        a.informativeText = "This optional control-plane check uses the normal system route so the login site can work before the corporate VPN connects. It sends no credentials and does not inspect or replace Check Point's IKE certificate validation. Corporate work hosts continue to use bound VPN sockets."
        a.addButton(withTitle: "Cancel"); a.addButton(withTitle: "Inspect site HTTPS")
        guard a.runModal() == .alertSecondButtonReturn else { return }
        DispatchQueue.global().async {
            guard let host = CheckPointPermissions.siteHost() else { DispatchQueue.main.async { self.report.string = "No configured site hostname available from Check Point." }; return }
            let result = HTTPSCertificates.inspect(host: host, configuration: Configuration(), controlPlane: true)
            DispatchQueue.main.async { self.report.string = "PRIVATE CHECK POINT SITE HTTPS\n\(jsonString(result))\n\nThe VPN's IKE gateway certificate and site pinning remain managed by Check Point and require vendor/IT confirmation." }
        }
    }
    @objc func importCA() {
        guard let certificate = selectedCertificate, confirmed.state == .on else { alert("Independent IT confirmation is required", "Review a CA file and confirm its SHA-256 with an authorized source first."); return }
        let info = Certificates.describe(certificate)
        guard info.isCA, info.currentlyValid, !info.presentInKeychain,
              Certificates.canonicalFingerprint(expected.stringValue) == Certificates.canonicalFingerprint(info.sha256) else {
            alert("Import blocked", "The fingerprint must match exactly. The CA must be within its validity period and absent from the checked keychains. Existing trust settings require manual IT review."); return
        }
        let a = NSAlert(); a.messageText = "Import this CA into your login keychain?"
        a.informativeText = "\(info.subject)\nIssuer: \(info.issuer)\nValid: \(info.notBefore) — \(info.notAfter)\nSHA-256: \(info.sha256)\nSource: \(source.stringValue)\n\n" + (info.selfIssued ? "This will explicitly trust a new root for SSL for your macOS user. It can authorize HTTPS certificates beyond this product. Only proceed with IT approval." : "This imports an intermediate certificate without an Always Trust override.")
        a.addButton(withTitle: "Cancel"); a.addButton(withTitle: "Import this certificate")
        guard a.runModal() == .alertSecondButtonReturn else { return }
        let fingerprint = expected.stringValue, reference = source.stringValue
        DispatchQueue.global().async {
            do {
                try Certificates.importConfirmed(certificate, expectedSHA256: fingerprint, sourceURL: reference, consent: true, paths: self.paths)
                DispatchQueue.main.async { self.selectedCertificate = nil; self.confirmed.state = .off; self.report.string = "CA import completed. Run Check HTTPS & permissions again. Local trust does not independently authenticate the source." }
            } catch { DispatchQueue.main.async { self.alert("Import did not complete", "No TLS checks were bypassed. Check the source URL, exact fingerprint and macOS authorization. Review the local receipt before retrying.") } }
        }
    }
    @objc func undo() {
        let receipts = Certificates.receipts(paths).filter { !$0.undone }
        guard !receipts.isEmpty else { alert("No product CA imports", "Certificates that were present before setup are never removed by this wizard."); return }
        let a = NSAlert(); a.messageText = "Choose a product import to undo"
        let menu = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 580, height: 28))
        receipts.forEach { menu.addItem(withTitle: $0.sha256) }; a.accessoryView = menu
        a.informativeText = "This removes the exact certificate and its user trust from your login keychain. Services relying on it may stop validating TLS. System and pre-existing certificates are not touched."
        a.addButton(withTitle: "Cancel"); a.addButton(withTitle: "Undo selected import")
        if a.runModal() == .alertSecondButtonReturn {
            let receipt = receipts[menu.indexOfSelectedItem]
            DispatchQueue.global().async {
                do { try Certificates.undoConfirmed(receipt.sha256, consent: true, paths: self.paths); DispatchQueue.main.async { self.report.string = "Import undone. Repeat HTTPS checks and confirm the intended trust state with IT." } }
                catch { DispatchQueue.main.async { self.alert("Undo failed", "Review the exact fingerprint in Keychain Access with your IT team. The receipt was retained.") } }
            }
        }
    }
}

struct CheckPointPermissionReport: Codable {
    var cliInstalled: Bool
    var appSignatureValid: Bool
    var vendorServiceReachable: Bool
    var connected: Bool
    var networkExtensionListed: Bool
    var authenticationMethod: String
    var clientIdentityCount: Int
    var approvalStatus = "USER_OR_IT_REVIEW_REQUIRED_FOR_OS_APPROVALS"
    var note = "No permissions were changed. A missing system-extension entry alone is not a failure. Full Disk Access, system approval and MFA cannot be certified by these local checks."
}
enum CheckPointPermissions {
    static func siteHost() -> String? {
        let info = command(tracPath, ["info"])
        for line in info.output.components(separatedBy: .newlines) {
            let text = line.trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("Conn "), text.hasSuffix(":") {
                let host = String(text.dropFirst(5).dropLast()).lowercased()
                if Configuration.validHost(host) { return host }
            }
        }
        return nil
    }
    static func inspect() -> CheckPointPermissionReport {
        let info = command(tracPath, ["info"])
        let extensions = command("/usr/bin/systemextensionsctl", ["list"]).output.lowercased()
        let identities = command("/usr/bin/security", ["find-identity", "-v", "-p", "ssl-client"]).output
        let counts = identities.components(separatedBy: .newlines).filter { $0.contains("valid identities found") }.compactMap { Int($0.trimmingCharacters(in: .whitespaces).split(separator: " ").first ?? "") }
        let auth = field(info.output, "authentication method") ?? "UNKNOWN"
        let safeAuth = ["identity_provider", "certificate", "username-password", "password"].contains(auth) ? auth : "VENDOR_SPECIFIC_OR_UNKNOWN"
        return CheckPointPermissionReport(cliInstalled: FileManager.default.isExecutableFile(atPath: tracPath),
            appSignatureValid: command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "/Applications/Endpoint Security VPN.app"]).code == 0,
            vendorServiceReachable: info.code == 0 && !info.output.isEmpty,
            connected: info.output.components(separatedBy: .newlines).contains { $0.trimmingCharacters(in: .whitespaces) == "status: Connected" },
            networkExtensionListed: extensions.contains("checkpoint") || extensions.contains("check-point"), authenticationMethod: safeAuth, clientIdentityCount: counts.first ?? -1)
    }
}
