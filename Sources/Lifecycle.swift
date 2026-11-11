import Foundation
import Darwin

struct ProductPaths {
    let home: URL
    init(root: String? = nil) {
        home = root.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? FileManager.default.homeDirectoryForCurrentUser
    }
    let label = "com.geokhv.corporate-vpn-router"
    var data: URL { home.appendingPathComponent("Library/Application Support/Corporate VPN Router", isDirectory: true) }
    var app: URL { home.appendingPathComponent("Applications/Corporate VPN Router.app", isDirectory: true) }
    var config: URL { data.appendingPathComponent("config.json") }
    var state: URL { data.appendingPathComponent("state.json") }
    var plist: URL { home.appendingPathComponent("Library/LaunchAgents/\(label).plist") }
    var executable: URL { app.appendingPathComponent("Contents/MacOS/CorporateVPNRouter") }
    var service: String { "gui/\(getuid())/\(label)" }
    var domain: String { "gui/\(getuid())" }
    var isTestRoot: Bool { home.standardizedFileURL != FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL }
    var rootArguments: [String] { isTestRoot ? ["--root", home.path] : [] }
    func createData() throws {
        try FileManager.default.createDirectory(at: data, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: data.path)
    }
}

enum Lifecycle {
    static func sourceApp() throws -> URL {
        // argv[0] is caller-controlled and may be only the executable name.
        let app = Bundle.main.bundleURL.resolvingSymlinksInPath()
        guard app.pathExtension == "app", FileManager.default.fileExists(atPath: app.appendingPathComponent("Contents/Info.plist").path) else {
            throw InstallationError(step: "Не удалось определить папку запущенного приложения", detail: app.path)
        }
        return app
    }
    static func installed(_ paths: ProductPaths) -> Bool { FileManager.default.isExecutableFile(atPath: paths.executable.path) }
    static func running(_ paths: ProductPaths) -> Bool { command("/bin/launchctl", ["print", paths.service]).code == 0 }

    static func verifyOwnership(_ paths: ProductPaths) throws {
        for url in [paths.data, paths.app, paths.plist] {
            let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey])
            if values?.isSymbolicLink == true { throw RouterError.destinationDenied }
        }
        if FileManager.default.fileExists(atPath: paths.plist.path) {
            guard let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: paths.plist), format: nil) as? [String: Any],
                  value["Label"] as? String == paths.label,
                  let args = value["ProgramArguments"] as? [String], args.first == paths.executable.path else { throw RouterError.destinationDenied }
        }
        if FileManager.default.fileExists(atPath: paths.app.path) {
            let info = paths.app.appendingPathComponent("Contents/Info.plist")
            guard let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: info), format: nil) as? [String: Any],
                  value["CFBundleIdentifier"] as? String == paths.label else { throw RouterError.destinationDenied }
        }
    }

    #if !CVR_MENU_BETA
    static func stop(_ paths: ProductPaths) throws {
        try verifyOwnership(paths)
        if running(paths) {
            guard command("/bin/launchctl", ["bootout", paths.service]).code == 0 else { throw RouterError.io }
            for _ in 0..<50 {
                if !running(paths) { break }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if running(paths) { throw RouterError.timeout }
        }
        if FileManager.default.fileExists(atPath: paths.plist.path) { try FileManager.default.removeItem(at: paths.plist) }
    }

    static func install(_ paths: ProductPaths) throws {
        let source = try sourceApp(), fm = FileManager.default
        try verifyOwnership(paths)
        guard source.standardizedFileURL != paths.app.standardizedFileURL else { return }
        try paths.createData()
        try fm.createDirectory(at: paths.app.deletingLastPathComponent(), withIntermediateDirectories: true)
        let stage = paths.app.deletingLastPathComponent().appendingPathComponent(".CorporateVPNRouter-\(UUID().uuidString).app")
        defer { try? fm.removeItem(at: stage) }
        try fm.copyItem(at: source, to: stage)
        let backup = paths.data.appendingPathComponent("previous.app")
        let hadApp = fm.fileExists(atPath: paths.app.path), wasRunning = running(paths)
        try stop(paths)
        var movedOld = false, placedNew = false
        do {
            if hadApp {
                if fm.fileExists(atPath: backup.path) { try fm.removeItem(at: backup) }
                try fm.moveItem(at: paths.app, to: backup)
                movedOld = true
            }
            try fm.moveItem(at: stage, to: paths.app)
            placedNew = true
            if !fm.fileExists(atPath: paths.config.path) { try JSONFile.write(Configuration(), to: paths.config) }
            if wasRunning { try start(paths) }
        } catch {
            if placedNew { try? fm.removeItem(at: paths.app) }
            if movedOld { try? fm.moveItem(at: backup, to: paths.app) }
            if wasRunning { try? start(paths) }
            throw error
        }
    }

    static func start(_ paths: ProductPaths) throws {
        _ = try Configuration.load(paths.config)
        try verifyOwnership(paths)
        guard installed(paths) else { throw RouterError.io }
        if running(paths) { return }
        try paths.createData()
        try FileManager.default.createDirectory(at: paths.plist.deletingLastPathComponent(), withIntermediateDirectories: true)
        let spec: [String: Any] = ["Label": paths.label,
            "ProgramArguments": [paths.executable.path, "--service"] + paths.rootArguments,
            "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 10,
            "ProcessType": "Interactive", "WorkingDirectory": paths.data.path,
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
            "Umask": 0o077]
        let data = try PropertyListSerialization.data(fromPropertyList: spec, format: .xml, options: 0)
        try data.write(to: paths.plist, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: paths.plist.path)
        guard command("/bin/launchctl", ["bootstrap", paths.domain, paths.plist.path]).code == 0 else { throw RouterError.io }
    }

    static func save(_ config: Configuration, paths: ProductPaths) throws {
        let valid = try config.validated()
        try paths.createData(); try verifyOwnership(paths)
        let wasRunning = running(paths)
        // Stop before changing policy: no request can use an obsolete allowlist.
        try stop(paths)
        if FileManager.default.fileExists(atPath: paths.config.path) {
            let old = paths.data.appendingPathComponent("config.previous.json")
            if FileManager.default.fileExists(atPath: old.path) { try FileManager.default.removeItem(at: old) }
            try FileManager.default.copyItem(at: paths.config, to: old)
        }
        try JSONFile.write(valid, to: paths.config)
        if wasRunning { try start(paths) }
    }

    static func uninstall(_ paths: ProductPaths, purge: Bool = false) throws {
        if purge && Certificates.receipts(paths).contains(where: { !$0.undone }) { throw RouterError.destinationDenied }
        try verifyOwnership(paths); try stop(paths)
        let fm = FileManager.default
        for item in [paths.plist, paths.app] where fm.fileExists(atPath: item.path) { try fm.removeItem(at: item) }
        if purge && fm.fileExists(atPath: paths.data.path) { try fm.removeItem(at: paths.data) }
    }

    static func rollback(_ paths: ProductPaths) throws {
        try verifyOwnership(paths)
        let backup = paths.data.appendingPathComponent("previous.app"), fm = FileManager.default
        guard fm.fileExists(atPath: backup.path) else { throw RouterError.io }
        let wasRunning = running(paths)
        try stop(paths)
        let displaced = paths.data.appendingPathComponent("displaced.app")
        if fm.fileExists(atPath: displaced.path) { try fm.removeItem(at: displaced) }
        if fm.fileExists(atPath: paths.app.path) { try fm.moveItem(at: paths.app, to: displaced) }
        do {
            try fm.moveItem(at: backup, to: paths.app)
            if wasRunning { try start(paths) }
        } catch {
            try? stop(paths)
            if fm.fileExists(atPath: paths.app.path) { try? fm.moveItem(at: paths.app, to: backup) }
            if fm.fileExists(atPath: displaced.path) { try? fm.moveItem(at: displaced, to: paths.app) }
            if wasRunning { try? start(paths) }
            throw error
        }
    }
    #endif
}
