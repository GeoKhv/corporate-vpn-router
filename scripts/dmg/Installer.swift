// Distribution UI only. The published VPN bundle is never rebuilt or re-signed.
import AppKit
import Foundation
import Darwin

struct InstallFailure: LocalizedError {
    let errorDescription: String?
    init(_ text: String) { errorDescription = text }
}

enum Distribution {
    static let appName = "Corporate VPN Router.app"
    static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
    static var destination: URL { home.appendingPathComponent("Applications/" + appName) }
    static var payload: URL {
        let bundle = Bundle.main.bundleURL
        let launcher = bundle.lastPathComponent == appName ? bundle : bundle.deletingLastPathComponent().appendingPathComponent(appName)
        return launcher.appendingPathComponent("Contents/Resources/Payload/" + appName)
    }
    static func run(_ tool: String, _ args: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool); process.arguments = args
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit(); return process.terminationStatus
    }
    static func verifiedPayload() throws -> URL {
        let source = payload
        guard try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R=cdhash H\"06684ffbb00baba39f611a7d20c9c643791e893d\"", source.path]) == 0,
              try String(contentsOf: source.appendingPathComponent("Contents/Resources/VERSION")).trimmingCharacters(in: .whitespacesAndNewlines) == "0.2.0-beta.6" else {
            throw InstallFailure("Не удалось проверить исходное приложение beta.6. Скачайте DMG заново из GitHub Releases.")
        }
        return source
    }
    static func install(launch: Bool) throws {
        // This guard must precede all writes and the original --install call.
        // Never move a live app or restart its HTTP router / SSL worker.
        let data = home.appendingPathComponent("Library/Application Support/Corporate VPN Router")
        let lock = data.appendingPathComponent("menu.lock")
        if FileManager.default.fileExists(atPath: lock.path) {
            let fd = open(lock.path, O_RDONLY | O_NOFOLLOW)
            guard fd >= 0 else { throw InstallFailure("Не удалось проверить работающее приложение.") }
            defer { close(fd) }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                throw InstallFailure("Router работает. Установка не начата; VPN-сеанс сохранён. Когда закончите работу, выберите «Завершить» в меню Router и повторите перенос.")
            }
        }
        // A system-wide copy would be a second app: refuse instead of deleting it.
        if FileManager.default.fileExists(atPath: "/Applications/" + appName) {
            throw InstallFailure("В /Applications уже есть Corporate VPN Router. Завершите его и уберите эту лишнюю копию в резервную папку. Затем повторите установку в ~/Applications. Настройки Router не удаляйте.")
        }
        let source = try verifiedPayload()
        guard try run(source.appendingPathComponent("Contents/MacOS/CorporateVPNRouter").path, ["--install"]) == 0 else {
            throw InstallFailure("Штатный установщик отказал в замене приложения или автозапуска. Завершите Router и повторите установку. Пользовательские настройки не удаляйте.")
        }
        guard try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "-R=cdhash H\"06684ffbb00baba39f611a7d20c9c643791e893d\"", destination.path]) == 0 else {
            throw InstallFailure("Установленная копия не прошла проверку подписи.")
        }
        if launch {
            guard try run("/usr/bin/open", [destination.path]) == 0 else {
                throw InstallFailure("Приложение установлено в ~/Applications. Откройте его из этой папки.")
            }
        }
    }
}

final class Installer: NSObject, NSApplicationDelegate {
    var started = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async { self.perform() }
    }
    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        // Accept only our launcher. Never execute an arbitrary dropped bundle.
        let expected = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent(Distribution.appName).standardizedFileURL
        guard filenames.count == 1, URL(fileURLWithPath: filenames[0]).standardizedFileURL == expected else {
            show("Перенесите Corporate VPN Router из этого DMG на «Программы»."); return
        }
        perform()
        sender.reply(toOpenOrPrint: .success)
    }
    func perform() {
        guard !started else { return }; started = true
        do {
            try Distribution.install(launch: true)
            NSApp.terminate(nil)
        } catch { show(error.localizedDescription) }
    }
    func show(_ text: String) {
        let alert = NSAlert(); alert.messageText = "Установка Corporate VPN Router"; alert.informativeText = text
        NSApp.activate(ignoringOtherApps: true); alert.runModal(); NSApp.terminate(nil)
    }
}

umask(0o077)
if CommandLine.arguments.dropFirst().first == "--install-only" {
    do { try Distribution.install(launch: false); print(Distribution.destination.path) }
    catch { fputs(error.localizedDescription + "\n", stderr); exit(1) }
} else if CommandLine.arguments.dropFirst().first == "--home" {
    print(Distribution.home.path)
} else {
    let app = NSApplication.shared, delegate = Installer()
    app.setActivationPolicy(.accessory); app.delegate = delegate; app.run()
    withExtendedLifetime(delegate) {}
}
