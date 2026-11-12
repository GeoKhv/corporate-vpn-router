import AppKit
import Security
import UniformTypeIdentifiers

final class CertificateWizard: NSObject {
    let paths: ProductPaths
    let resources: URL
    var permitsHost: ((String) -> Bool)?
    var inspectHost: ((String) -> HTTPSCertificateResult)?
    var window: NSWindow!
    let hosts = NSTextField(), expected = NSTextField(), source = NSTextField(labelWithString: "")
    let choices = NSPopUpButton()
    let confirmed = NSButton(checkboxWithTitle: "Сверил SHA-256 с одобренным списком и согласен на импорт выбранного CA", target: nil, action: nil)
    var report = NSTextView(), selectedCertificate: SecCertificate?
    var entries = [ApprovedCertificateEntry](), candidates = [SecCertificate](), results = [HTTPSCertificateResult]()
    var captured = Date.distantPast, busy = false
    init(paths: ProductPaths, resources: URL? = nil) {
        self.paths = paths
#if CVR_UPDATES
        self.resources = resources ?? Provisioning.directory(paths)
#else
        self.resources = resources ?? paths.app.appendingPathComponent("Contents/Resources")
#endif
    }
    func show() {
        NSApp.activate(ignoringOtherApps: true)
        if window != nil { window.makeKeyAndOrderFront(nil); return }
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 790, height: 660), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Сертификаты рабочих HTTPS-сайтов"; window.center(); window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 790, height: 660)
        let column = NSStackView(); column.orientation = .vertical; column.alignment = .leading; column.spacing = 10; column.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(column)
        NSLayoutConstraint.activate([column.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 20), column.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -20), column.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 20)])
        let intro = NSTextField(wrappingLabelWithString: "Подключите VPN и проверьте сайты. Если HTTPS уже работает, ничего импортировать не нужно. Мастер предлагает только недостающие CA после проверки цепочки. Настройка сертификатов не влияет на обычную кнопку «Подключить».")
        intro.preferredMaxLayoutWidth = 745; column.addArrangedSubview(intro)
        column.addArrangedSubview(NSTextField(labelWithString: "Рабочие HTTPS-сайты, через запятую"))
        var initial = Certificates.preferences(paths).hosts
        if initial.isEmpty, let data = try? Data(contentsOf: resources.appendingPathComponent("CertificateEndpoints.json")), let defaults = try? JSONDecoder().decode(CertificatePreferences.self, from: data) { initial = defaults.hosts }
        hosts.stringValue = initial.joined(separator: ", "); hosts.widthAnchor.constraint(equalToConstant: 745).isActive = true
        column.addArrangedSubview(hosts)
        column.addArrangedSubview(NSButton(title: "Проверить HTTPS и цепочки", target: self, action: #selector(check)))
        if let bundle = try? CertificatePlan.load(resources) { entries = bundle.0.certificates; candidates = bundle.1 }
        choices.addItems(withTitles: entries.map { $0.subject + " · " + String($0.sha256.suffix(17)) })
        choices.target = self; choices.action = #selector(selectCA); choices.widthAnchor.constraint(equalToConstant: 745).isActive = true
        column.addArrangedSubview(choices)
        source.stringValue = "Источник: существующий Keychain владельца; точные отпечатки и цепочки проверены при сборке."
        source.font = .systemFont(ofSize: 11); column.addArrangedSubview(source)
        column.addArrangedSubview(NSTextField(labelWithString: "Ожидаемый SHA-256 из одобренного списка"))
        expected.isEditable = false; expected.isSelectable = true; expected.widthAnchor.constraint(equalToConstant: 745).isActive = true
        column.addArrangedSubview(expected); column.addArrangedSubview(confirmed)
        let actions = NSStackView(views: [NSButton(title: "Проверить файл CA…", target: self, action: #selector(choose)), NSButton(title: "Импортировать выбранный CA…", target: self, action: #selector(importCA)), NSButton(title: "Отменить прежний импорт…", target: self, action: #selector(undo))])
        column.addArrangedSubview(actions)
        let scroll = NSTextView.scrollableTextView(); scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder
        report = scroll.documentView as! NSTextView; report.isEditable = false; report.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        window.contentView!.addSubview(scroll)
        NSLayoutConstraint.activate([scroll.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 20), scroll.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -20), scroll.topAnchor.constraint(equalTo: column.bottomAnchor, constant: 12), scroll.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -20), scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 180)])
        selectCA(); report.string = candidates.isEmpty ? "Проверенный набор CA отсутствует. Импорт заблокирован; обычное VPN-подключение доступно." : "Начните с проверки HTTPS. Согласие на импорт запрашивается для каждого необходимого CA отдельно."
        window.makeKeyAndOrderFront(nil)
    }
    func alert(_ title: String, _ text: String) { let a = NSAlert(); a.messageText = title; a.informativeText = text; a.runModal() }
    @objc func selectCA() {
        confirmed.state = .off
        guard candidates.indices.contains(choices.indexOfSelectedItem) else { selectedCertificate = nil; return }
        selectedCertificate = candidates[choices.indexOfSelectedItem]
        expected.stringValue = entries[choices.indexOfSelectedItem].sha256
    }
    @objc func choose() {
        guard !busy else { return }
        let panel = NSOpenPanel(); panel.allowedContentTypes = ["cer", "crt", "pem", "der"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let cert = try Certificates.parse(Data(contentsOf: url)), sha = Certificates.fingerprint(cert)
            guard let index = candidates.firstIndex(where: { Certificates.fingerprint($0) == sha }) else { throw RouterError.destinationDenied }
            choices.selectItem(at: index); selectCA()
            report.string = "Файл совпал с заранее одобренным SHA-256. Перед импортом выполните проверку сайтов.\n" + jsonString(Certificates.describe(cert))
        } catch { alert("Файл не принят", "Нужен один публичный сертификат с точным отпечатком из одобренного списка. Неизвестные CA, закрытые ключи и наборы идентификации не импортируются.") }
    }
    @objc func check() {
        guard !busy else { return }
        let list = Array(Set(hosts.stringValue.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map { String($0).lowercased() })).sorted()
        guard !list.isEmpty, list.count <= 16, list.allSatisfy({ Configuration.validHost($0) && (permitsHost?($0) ?? ((try? Configuration.load(paths.config))?.permits($0, port: 443) == true)) }) else { alert("Проверьте список сайтов", "Все имена должны быть разрешены в «Рабочих сайтах» для порта 443."); return }
        do { try JSONFile.write(CertificatePreferences(hosts: list), to: paths.data.appendingPathComponent("certificate-endpoints.json")) }
        catch { alert("Не удалось сохранить список", error.localizedDescription); return }
        busy = true; results = []; confirmed.state = .off; report.string = "Проверка HTTPS без логинов, cookies и изменения доверия…"
        let inspect = inspectHost
        DispatchQueue.global().async {
            let values = list.map { host -> HTTPSCertificateResult in
                if let inspect { return inspect(host) }
                guard let config = try? Configuration.load(self.paths.config) else { return HTTPSCertificateResult(host: host) }
                return HTTPSCertificates.inspect(host: host, configuration: config)
            }
            let now = Date()
            let plans = values.map { CertificatePlan.assess(.init(result: $0, candidates: self.candidates, captured: now)) }
            var lines = [String]()
            for (value, plan) in zip(values, plans) {
                let state = value.tlsTrusted ? "HTTPS доверен" : value.issue
                lines.append(value.host + ": " + state + "\n" + plan.explanation)
            }
            let summary = lines.joined(separator: "\n\n")
            DispatchQueue.main.async { self.busy = false; self.results = values; self.captured = now; self.report.string = summary + "\n\n" + jsonString(values) }
        }
    }
    @objc func importCA() {
        guard !busy, confirmed.state == .on, let certificate = selectedCertificate else { alert("Подтвердите выбранный CA", "Сначала проверьте HTTPS и сверяйте SHA-256 с одобренным списком."); return }
        let sha = Certificates.fingerprint(certificate)
        let evidence = results.map { CertificateImportEvidence(result: $0, candidates: candidates, captured: captured) }.first { CertificatePlan.assess($0).needed.contains(sha) }
        guard let evidence else { alert("Импорт не требуется или не подтверждён", "Повторите проверку HTTPS. Импорт доступен только для недостающего CA, с которым цепочка нужного сайта проходит проверку. Существующее доверие не заменяется."); return }
        let info = Certificates.describe(certificate), a = NSAlert()
        a.messageText = "Добавить этот CA в вашу связку ключей?"
        a.informativeText = "\(info.subject)\nSHA-256: \(sha)\nСрок: \(info.notBefore) — \(info.notAfter)\n\n" + (info.selfIssued ? "Корневой CA получит доверие для SSL в вашей учётной записи macOS. Это доверие применяется и вне Router." : "Промежуточный CA будет добавлен без настройки «Всегда доверять».")
        a.addButton(withTitle: "Отмена"); a.addButton(withTitle: "Импортировать этот CA")
        guard a.runModal() == .alertSecondButtonReturn else { return }
        busy = true
        DispatchQueue.global().async {
            do {
                try Certificates.importConfirmed(certificate, expectedSHA256: sha, sourceURL: "owner-approved-keychain:" + Certificates.canonicalFingerprint(sha), consent: true, paths: self.paths, evidence: evidence)
                DispatchQueue.main.async { self.busy = false; self.confirmed.state = .off; self.check() }
            } catch { DispatchQueue.main.async { self.busy = false; self.alert("Импорт не завершён", "Проверки доверия не обходились. Локальная квитанция сохранена для диагностики и безопасного отката.") } }
        }
    }
    @objc func undo() {
        guard !busy else { return }
        let receipts = Certificates.receipts(paths).filter { !$0.undone }
        guard !receipts.isEmpty else { alert("Нет импортов Router", "Предустановленные сертификаты этот мастер не удаляет."); return }
        let a = NSAlert(), menu = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 580, height: 28))
        receipts.forEach { menu.addItem(withTitle: $0.sha256) }; a.accessoryView = menu
        a.messageText = "Отменить выбранный импорт?"
        a.informativeText = "Будет удалён только сертификат, добавленный Router в вашу связку ключей. Если его доверие было изменено позже, автоматический откат будет заблокирован."
        a.addButton(withTitle: "Отмена"); a.addButton(withTitle: "Отменить импорт")
        guard a.runModal() == .alertSecondButtonReturn else { return }
        let receipt = receipts[menu.indexOfSelectedItem]; busy = true
        DispatchQueue.global().async {
            do { try Certificates.undoConfirmed(receipt.sha256, consent: true, paths: self.paths); DispatchQueue.main.async { self.busy = false; self.report.string = "Импорт отменён. Повторите проверку HTTPS." } }
            catch { DispatchQueue.main.async { self.busy = false; self.alert("Откат не выполнен", "Доверие изменилось после импорта либо состояние не подтверждено. Квитанция сохранена; чужие настройки не удалялись.") } }
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
