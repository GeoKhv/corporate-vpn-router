#if CVR_SELECTIVE_TUN
import AppKit
import Darwin

// Deliberately records startup metadata only: never settings, account names,
// gateway addresses, environment variables, passwords or connection logs.
final class StartupDiagnostics {
    static let shared = StartupDiagnostics()
    private let mutex = NSLock()
    private var lines = [String]()
    private var file: URL?
    private var exportHome = FileManager.default.homeDirectoryForCurrentUser
    func begin(home: URL, source: URL) {
        exportHome = home
        let directory = home.appendingPathComponent("Library/Logs/Corporate VPN Router")
        do {
            try AppInstallation.rejectLink(directory)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let url = directory.appendingPathComponent("launch-\(UUID().uuidString).txt")
            let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            if fd >= 0 { close(fd); file = url }
            let previous = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
            let logs = previous.filter { $0.lastPathComponent.hasPrefix("launch-") && $0.pathExtension == "txt" }
                .sorted { ((try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) > ((try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) }
            for old in logs.dropFirst(6) { try? AppInstallation.rejectLink(old); if (try? old.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true { try? FileManager.default.removeItem(at: old) } }
        } catch { /* The in-memory report remains available. */ }
        record("main_entered", "version=\(productVersion) os=\(ProcessInfo.processInfo.operatingSystemVersionString) pid=\(getpid()) source=\(source.path)")
    }
    static func redact(_ value: String) -> String {
        var text = value.replacingOccurrences(of: FileManager.default.homeDirectoryForCurrentUser.path, with: "<HOME>")
        for pattern in [#"/Users/[^/\s]+"#, #"https?://[^\s<>]+"#, #"(?i)(password|authorization|cookie|access_token|refresh_token|secret)\s*[:=][^\n]*"#] {
            text = text.replacingOccurrences(of: pattern, with: "<REDACTED>", options: .regularExpression)
        }
        return String(text.prefix(8192))
    }
    func record(_ event: String, _ detail: String = "") {
        mutex.lock(); defer { mutex.unlock() }
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(event) \(Self.redact(detail))"
        lines.append(line); if lines.count > 100 { lines.removeFirst() }
        if let file {
            let fd = open(file.path, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC)
            if fd >= 0 { let data = Data((line + "\n").utf8); _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }; close(fd) }
        }
    }
    func report() -> String {
        mutex.lock(); defer { mutex.unlock() }
        return "Corporate VPN Router — запуск\nЭтот отчёт начинается после main; отказы macOS до main требует резервного сборщика из комплекта.\n\n" + lines.joined(separator: "\n") + "\n"
    }
    func exportReport() throws -> URL {
        let directory = exportHome.appendingPathComponent("Desktop")
        try AppInstallation.rejectLink(directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("Router-launch-\(UUID().uuidString).txt")
        let data = Data(report().utf8)
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                guard written > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                offset += written
            }
        }
        return url
    }
    func save(window: NSWindow?) {
        let alert: NSAlert
        do {
            let url = try exportReport()
            alert = NSAlert(); alert.messageText = "Отчёт сохранён на рабочем столе"
            alert.informativeText = "\(url.lastPathComponent)\n\nПередайте этот TXT разработчику. Отчёт остаётся на этом Mac; автоматической отправки нет."
        } catch { alert = NSAlert(error: error) }
        if let window { alert.beginSheetModal(for: window) }
        else { alert.runModal() }
    }
}

enum FirstLaunchAction: Equatable { case runInstalled, install, openExisting }
enum StartupHandoff {
    static func receipt(_ token: String, paths: ProductPaths) throws -> URL {
        guard UUID(uuidString: token) != nil else { throw RouterError.invalidConfiguration }
        let url = paths.home.appendingPathComponent("Library/Logs/Corporate VPN Router/handoff-\(token).txt")
        try AppInstallation.rejectLink(url)
        return url
    }
    static func requestedToken() -> String? {
        let args = CommandLine.arguments
        guard let index = args.firstIndex(of: "--startup-receipt"), args.indices.contains(index + 1) else { return nil }
        return args[index + 1]
    }
    static func acknowledge(_ paths: ProductPaths) {
        guard let token = requestedToken(), let url = try? receipt(token, paths: paths) else { return }
        try? Data("ready\n".utf8).write(to: url, options: .withoutOverwriting)
    }
    static func openInstalled(_ target: URL, paths: ProductPaths, timeout: TimeInterval = 25, request: ((URL, String) throws -> Void)? = nil) throws {
        let existing = NSRunningApplication.runningApplications(withBundleIdentifier: AppInstallation.identifier)
            .first { item in item.processIdentifier != getpid() && item.bundleURL.map { AppInstallation.sameLocation($0, target) } == true }
        if let existing {
            existing.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
            _ = try AppInstallation.run("/usr/bin/open", [target.path], step: "Не удалось открыть существующее окно")
            return
        }
        let token = UUID().uuidString, url = try receipt(token, paths: paths)
        defer { try? FileManager.default.removeItem(at: url) }
        if let request { try request(target, token) }
        else { _ = try AppInstallation.run("/usr/bin/open", ["-n", target.path, "--args", "--ui", "--startup-receipt", token], step: "macOS не разрешила открыть установленный Router") }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if (try? String(contentsOf: url)) == "ready\n" { return }
            Thread.sleep(forTimeInterval: 0.1)
        }
        throw InstallationError(step: "Установка проверена, но открытие не подтверждено", detail: "macOS могла остановить запуск до появления окна. Если заменялась прежняя версия, её резервная копия сохранена. Сохраните отчёт; если macOS не даёт открыть Router, используйте сборщик из комплекта.")
    }
}
struct FirstLaunchPlan {
    let action: FirstLaunchAction
    let destination: URL
    let message: String
    static func make(source: URL, paths: ProductPaths, running: Bool = false) throws -> FirstLaunchPlan {
        let fm = FileManager.default
        let user = paths.home.appendingPathComponent("Applications/" + AppInstallation.appName)
        let system = paths.systemApplications.appendingPathComponent(AppInstallation.appName)
        if fm.fileExists(atPath: user.path) && fm.fileExists(atPath: system.path) {
            throw InstallationError(step: "Найдены две установки Router", detail: "Обе копии сохранены. Отчёт поможет выбрать одну установку без потери настроек.")
        }
        try AppInstallation.rejectLink(paths.app)
        if AppInstallation.sameLocation(source, paths.app) {
            return FirstLaunchPlan(action: .runInstalled, destination: paths.app, message: "")
        }
        if fm.fileExists(atPath: paths.app.path) {
            let old = try BundleMetadata.read(paths.app), new = try BundleMetadata.read(source)
            guard old.identifier == AppInstallation.identifier else {
                throw InstallationError(step: "Папка занята другим приложением", detail: paths.app.path)
            }
            if running || old.build.compare(new.build, options: .numeric) != .orderedAscending {
                return FirstLaunchPlan(action: .openExisting, destination: paths.app,
                    message: "Router \(old.version) уже установлен\(running ? " и работает" : ""). Откроется существующая копия; замена не требуется.")
            }
            return FirstLaunchPlan(action: .install, destination: paths.app,
                message: "Обновить установленный Router \(old.version) до \(new.version)? Прежняя копия будет сохранена для отката. Настройки, рабочие сайты и помощник сохранятся.")
        }
        return FirstLaunchPlan(action: .install, destination: paths.app,
            message: "Router установится в постоянную папку Вашего пользователя и откроется оттуда. Перемещать приложение вручную не нужно.")
    }
}

struct BundleMetadata {
    let identifier: String, build: String, version: String
    static func read(_ app: URL) throws -> BundleMetadata {
        guard let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")), format: nil) as? [String: Any],
              let identifier = value["CFBundleIdentifier"] as? String,
              let build = value["CFBundleVersion"] as? String,
              let version = value["CFBundleShortVersionString"] as? String else {
            throw InstallationError(step: "Не удалось прочитать пакет", detail: app.path)
        }
        return BundleMetadata(identifier: identifier, build: build, version: version)
    }
}

// This is a window of Router itself, not an installer application. No menu,
// helper probing, automatic updates or VPN work starts in a download copy.
final class FirstLaunchWindow: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let source: URL, paths: ProductPaths
    var plan: FirstLaunchPlan?
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 300), styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let message = NSTextField(wrappingLabelWithString: "")
    let primary = NSButton(title: "Установить и открыть", target: nil, action: nil)
    let cancel = NSButton(title: "Отмена", target: nil, action: nil)
    let report = NSButton(title: "Сохранить отчёт…", target: nil, action: nil)
    var initialError: Error?
    var busy = false
    var finish: () -> Void = { NSApp.terminate(nil) }
    // Injection is used by the native window tests; production uses the real transaction.
    var install: (URL, ProductPaths) throws -> URL = { source, paths in
        try AppInstallation.install(source: source, home: paths.home, systemApplications: paths.systemApplications)
    }
    var launch: ((URL) throws -> Void)?
    init(source: URL, paths: ProductPaths, plan: FirstLaunchPlan? = nil, error: Error? = nil) {
        self.source = source; self.paths = paths; self.plan = plan; initialError = error
        super.init()
    }
    func applicationDidFinishLaunching(_ notification: Notification) { show() }
    func show() {
        window.title = "Corporate VPN Router"; window.delegate = self; window.isReleasedWhenClosed = false
        let title = NSTextField(labelWithString: "Corporate VPN Router")
        title.font = .boldSystemFont(ofSize: 22)
        message.font = .systemFont(ofSize: 14)
        message.maximumNumberOfLines = 8
        let location = NSTextField(wrappingLabelWithString: "Папка: " + paths.app.path.replacingOccurrences(of: paths.home.path, with: "~"))
        location.textColor = .secondaryLabelColor; location.font = .systemFont(ofSize: 11)
        primary.target = self; primary.action = #selector(proceed); primary.keyEquivalent = "\r"
        cancel.target = self; cancel.action = #selector(cancelInstall); cancel.keyEquivalent = "\u{1b}"
        report.target = self; report.action = #selector(saveReport); report.isHidden = true
        let buttons = NSStackView(views: [report, cancel, primary]); buttons.spacing = 12
        let stack = NSStackView(views: [title, message, location, buttons]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 28), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -28), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 28), stack.bottomAnchor.constraint(lessThanOrEqualTo: window.contentView!.bottomAnchor, constant: -24)])
        message.stringValue = plan?.message ?? "Не удалось запустить Router."
        if plan?.action == .openExisting { primary.title = "Открыть установленное" }
        if let initialError { failure(initialError) }
        window.center(); NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil)
    }
    @objc func proceed() {
        guard !busy, let plan else { return }
        busy = true; primary.isEnabled = false; cancel.isEnabled = false; window.standardWindowButton(.closeButton)?.isEnabled = false
        message.stringValue = plan.action == .install ? "Проверка и установка приложения…" : "Открытие установленного Router…"
        StartupDiagnostics.shared.record("install_confirmed", "destination=\(plan.destination.path) action=\(plan.action)")
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let target = plan.action == .install ? try self.install(self.source, self.paths) : plan.destination
                try AppInstallation.verify(target)
                StartupDiagnostics.shared.record("installed_verified", target.path)
                if let launch = self.launch { try launch(target) }
                else { try StartupHandoff.openInstalled(target, paths: self.paths) }
                StartupDiagnostics.shared.record("launch_requested", target.path)
                DispatchQueue.main.async { self.finish() }
            } catch { DispatchQueue.main.async { self.failure(error) } }
        }
    }
    func failure(_ error: Error) {
        busy = false; primary.isHidden = true; cancel.title = "Закрыть"; cancel.isEnabled = true
        window.standardWindowButton(.closeButton)?.isEnabled = true
        message.stringValue = AppInstallation.describe(error)
        window.setContentSize(NSSize(width: 560, height: 380))
        report.isHidden = false
        StartupDiagnostics.shared.record("startup_failed", AppInstallation.describe(error))
    }
    @objc func saveReport() { StartupDiagnostics.shared.save(window: window) }
    @objc func cancelInstall() { guard !busy else { return }; StartupDiagnostics.shared.record("installation_cancelled"); finish() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { if !busy { cancelInstall() }; return false }
}
#endif
