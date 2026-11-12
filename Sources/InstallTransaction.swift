import Foundation
import Darwin

struct InstallationError: LocalizedError {
    let step: String
    let detail: String
    var errorDescription: String? { "\(step)\n\(detail)" }
}

// Shared by the DMG UI and the application's explicit --install command.
// No VPN engine is executed, no launchd job is stopped or reloaded.
enum AppInstallation {
#if CVR_SELECTIVE_TUN
    static let appName = "Corporate VPN Router TUN Trial.app"
    static let identifier = "com.geokhv.corporate-vpn-router.tun-trial"
#else
    static let appName = "Corporate VPN Router.app"
    static let identifier = "com.geokhv.corporate-vpn-router"
#endif
    static let label = identifier + ".menu"
    static let fm = FileManager.default

    static func describe(_ error: Error) -> String {
        if let failure = error as? InstallationError { return failure.localizedDescription }
        let value = error as NSError
        let path = value.userInfo[NSFilePathErrorKey] as? String ?? ""
        return "\(value.localizedDescription)\n\(path) [\(value.domain):\(value.code)]"
    }

    static func checked(_ step: String, _ body: () throws -> Void) throws {
        do { try body() }
        catch let error as InstallationError { throw error }
        catch {
            let error = error as NSError
            throw InstallationError(step: step, detail: "\(error.localizedDescription) [\(error.domain):\(error.code)]")
        }
    }

    // Capture BOTH streams, and bound runtime without blocking a pipe/run loop.
    static func run(_ tool: String, _ args: [String], step: String) throws -> String {
        let temp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: temp, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: temp) }
        let output = temp.appendingPathComponent("output")
        guard fm.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw InstallationError(step: step, detail: "Не удалось создать временный файл диагностики: \(output.path)")
        }
        let handle = try FileHandle(forWritingTo: output)
        defer { try? handle.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool); process.arguments = args
        process.standardOutput = handle; process.standardError = handle; process.standardInput = FileHandle.nullDevice
        do { try process.run() }
        catch { throw InstallationError(step: step, detail: "\(tool): \(error.localizedDescription)") }
        let deadline = Date().addingTimeInterval(90)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL); process.waitUntilExit()
            throw InstallationError(step: step, detail: "\(tool): превышено время ожидания (90 с).")
        }
        process.waitUntilExit()
        let text = String(decoding: (try Data(contentsOf: output)).prefix(8192), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationReason == .exit && process.terminationStatus == 0 else {
            throw InstallationError(step: step, detail: "\(tool), код \(process.terminationStatus): \(text.isEmpty ? "нет диагностического вывода" : text)")
        }
        return text
    }

    static func verify(_ app: URL, requirement: String? = nil) throws {
        var args = ["--verify", "--deep", "--strict"]
        if let requirement = requirement { args += ["-R=" + requirement] }
        _ = try run("/usr/bin/codesign", args + [app.path], step: "Не прошла проверка подписи: \(app.path)")
    }

    static func rejectLink(_ url: URL) throws {
        // lstat sees dangling links as well. Check every ancestor before writes.
        var current = url
        while current.path != "/" {
            var info = stat()
            if lstat(current.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK {
                // Foundation deliberately abbreviates /private/tmp and /private/var.
                // Accept only the root-owned standard macOS aliases, never a user link.
                if ["/tmp", "/var"].contains(current.path), info.st_uid == 0,
                   let target = try? fm.destinationOfSymbolicLink(atPath: current.path),
                   ["/private" + current.path, "private" + current.path].contains(target) {
                    current.deleteLastPathComponent(); continue
                }
                throw InstallationError(step: "Небезопасный путь установки", detail: "Обнаружена символическая ссылка: \(current.path). Приложение и настройки не заменены.")
            }
            current.deleteLastPathComponent()
        }
    }

    static let systemApplications = URL(fileURLWithPath: "/Applications", isDirectory: true)

    static func destination(home: URL, systemApplications: URL = systemApplications) -> URL {
        let userApp = home.appendingPathComponent("Applications/" + appName)
        let sharedApp = systemApplications.appendingPathComponent(appName)
        // Respect the location the user already chose. A system-wide app is
        // itself an installed copy, not evidence of a second installation.
        if fm.fileExists(atPath: userApp.path) { return userApp }
        if fm.fileExists(atPath: sharedApp.path) { return sharedApp }
        return userApp
    }

    static func agent(_ home: URL, systemApplications: URL = systemApplications) throws -> URL {
        let app = destination(home: home, systemApplications: systemApplications)
        let executable = app.appendingPathComponent("Contents/MacOS/CorporateVPNRouter").path
        let agent = home.appendingPathComponent("Library/LaunchAgents/" + label + ".plist")
        try rejectLink(agent)
        for (url, expectedLabel, exact) in [(agent, label, true), (home.appendingPathComponent("Library/LaunchAgents/" + identifier + ".plist"), identifier, false)] {
            try rejectLink(url)
            if fm.fileExists(atPath: url.path) {
                let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil) as? [String: Any]
                let args = value?["ProgramArguments"] as? [String]
                guard value?["Label"] as? String == expectedLabel,
                      exact ? args == [executable, "--login"] : args?.first == executable else {
                    throw InstallationError(step: "Автозапуск содержит другой путь или команду", detail: "\(url.path)\nОжидается \(executable). Существующий файл сохранён. Проверьте его в Finder; не удаляйте настройки Router.")
                }
            }
        }
        return agent
    }

    static func lock(_ url: URL, busy: String) throws -> Int32 {
        try rejectLink(url)
        let fd = open(url.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw InstallationError(step: "Не удалось проверить блокировку", detail: "\(url.path): \(String(cString: strerror(errno))) (errno \(errno)).") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno; close(fd)
            throw InstallationError(step: code == EWOULDBLOCK ? busy : "Ошибка блокировки", detail: "\(url.path)\n\(String(cString: strerror(code))) (errno \(code)).")
        }
        return fd
    }

    static func install(source: URL, home suppliedHome: URL, requirement: String? = nil, systemApplications: URL = systemApplications) throws -> URL {
        let home = suppliedHome.resolvingSymlinksInPath()
        let app = destination(home: home, systemApplications: systemApplications)
        let data = home.appendingPathComponent("Library/Application Support/Corporate VPN Router")
        for url in [app, data] { try rejectLink(url) }
        if fm.fileExists(atPath: app.path) {
            let value = try PropertyListSerialization.propertyList(from: Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")), format: nil) as? [String: Any]
            guard value?["CFBundleIdentifier"] as? String == identifier else {
                throw InstallationError(step: "В папке установки находится другое приложение", detail: app.path + "\nСохраните его в резервной папке и повторите установку.")
            }
        }
        let agentURL = try agent(home, systemApplications: systemApplications)
        try verify(source, requirement: requirement)
        try checked("Нет доступа к папке данных: \(data.path)") {
            try fm.createDirectory(at: data, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        let menuFD = try lock(data.appendingPathComponent("menu.lock"), busy: "Router работает. Установка не начата; VPN-сеанс сохранён. Когда закончите работу, выберите «Завершить» в меню Router и повторите установку.")
        defer { close(menuFD) }
        let userApp = home.appendingPathComponent("Applications/" + appName)
        let sharedApp = systemApplications.appendingPathComponent(appName)
        if fm.fileExists(atPath: userApp.path) && fm.fileExists(atPath: sharedApp.path) {
            throw InstallationError(step: "Найдены две папки установки Router", detail: "\(userApp.path)\n\(sharedApp.path)\nОбе копии сохранены. Завершите Router и оставьте одну папку установки; настройки не удаляйте.")
        }
        if source.resolvingSymlinksInPath() == app.resolvingSymlinksInPath() { return app }
        try checked("Нет доступа к папке установки: \(app.deletingLastPathComponent().path)") {
            try fm.createDirectory(at: app.deletingLastPathComponent(), withIntermediateDirectories: true)
        }
        let stage = app.deletingLastPathComponent().appendingPathComponent(".CVR-\(UUID().uuidString).app")
        defer { try? fm.removeItem(at: stage) }
        // ditto preserves quarantine. Never execute a quarantined nested payload.
        _ = try run("/usr/bin/ditto", [source.path, stage.path], step: "Не удалось скопировать приложение в \(stage.path)")
        try verify(stage, requirement: requirement)
        let backup = data.appendingPathComponent("rollback-\(UUID().uuidString).app")
        let hadApp = fm.fileExists(atPath: app.path)
        let oldAgent = try fm.fileExists(atPath: agentURL.path) ? Data(contentsOf: agentURL) : nil
        var movedOld = false, placedNew = false, wroteAgent = false
        do {
            if hadApp {
                try checked("Не удалось сохранить прежнее приложение: \(backup.path)") { try fm.moveItem(at: app, to: backup) }
                movedOld = true
            }
            try checked("Не удалось поместить приложение: \(app.path)") { try fm.moveItem(at: stage, to: app) }
            placedNew = true
            try verify(app, requirement: requirement)
#if !CVR_SELECTIVE_TUN
            if oldAgent == nil {
                try checked("Не удалось сохранить автозапуск: \(agentURL.path)") {
                    try fm.createDirectory(at: agentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                    let spec: [String: Any] = ["Label": label, "ProgramArguments": [app.appendingPathComponent("Contents/MacOS/CorporateVPNRouter").path, "--login"], "RunAtLoad": true, "LimitLoadToSessionType": "Aqua", "Umask": 0o077]
                    let bytes = try PropertyListSerialization.data(fromPropertyList: spec, format: .xml, options: 0)
                    try bytes.write(to: agentURL, options: .atomic)
                    wroteAgent = true
                    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: agentURL.path)
                }
            }
#endif
            _ = try agent(home, systemApplications: systemApplications)
        } catch {
            let original = error
            do {
                if wroteAgent { try fm.removeItem(at: agentURL) }
                if placedNew { try fm.moveItem(at: app, to: stage) }
                if movedOld { try fm.moveItem(at: backup, to: app) }
            } catch {
                throw InstallationError(step: "\(original.localizedDescription)\nАвтоматический откат не завершён", detail: "\(error.localizedDescription)\nПредыдущая копия: \(backup.path)\nПапка установки: \(app.path). Настройки не удалены.")
            }
            throw InstallationError(step: original.localizedDescription, detail: "Замена отменена; прежнее приложение и автозапуск сохранены. Настройки не изменены.")
        }
        return app
    }
}
