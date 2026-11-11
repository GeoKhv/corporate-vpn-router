// Self-contained distribution UI; all filesystem mutations use the shared transaction.
import AppKit
import Foundation
import Darwin

enum Distribution {
    static let appName = AppInstallation.appName
    static var home: URL { FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath() }
    static var destination: URL { home.appendingPathComponent("Applications/" + appName) }
    static var payload: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/Payload/" + appName) }
    static func install() throws {
        _ = try AppInstallation.install(source: payload, home: home, requirement: payloadRequirement)
    }
}

final class Installer: NSObject, NSApplicationDelegate {
    var started = false
    var finishedLaunch = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async { self.perform() }
    }
    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        // Dropped paths are never executed or copied. Install only our pinned payload.
        perform()
        sender.reply(toOpenOrPrint: .success)
    }
    func perform() {
        guard !started else { return }; started = true
        do {
            try Distribution.install()
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.createsNewApplicationInstance = true
            // Preserve explicit disposable-home overrides during native launch tests.
            if ProcessInfo.processInfo.environment["CFFIXED_USER_HOME"] != nil {
                configuration.environment = ["HOME": Distribution.home.path, "CFFIXED_USER_HOME": Distribution.home.path]
            }
            NSWorkspace.shared.openApplication(at: Distribution.destination, configuration: configuration) { application, error in
                DispatchQueue.main.async {
                    guard !self.finishedLaunch else { return }
                    if let error = error { self.launchFailed(error.localizedDescription); return }
                    guard let application = application else { self.launchFailed("LaunchServices не вернул запущенное приложение."); return }
                    self.checkLaunch(application)
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                if !self.finishedLaunch { self.launchFailed("macOS не подтвердила запуск за 30 секунд.") }
            }
        } catch { show(AppInstallation.describe(error)) }
    }
    func checkLaunch(_ application: NSRunningApplication) {
        guard !finishedLaunch else { return }
        if application.isTerminated {
            launchFailed("macOS завершила приложение до окончания запуска.")
        } else if application.isFinishedLaunching {
            finishedLaunch = true; NSApp.terminate(nil)
        } else {
            // A process suspended by Gatekeeper exists but has not launched AppKit.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { self.checkLaunch(application) }
        }
    }
    func launchFailed(_ detail: String) {
        finishedLaunch = true
        show("Приложение установлено: \(Distribution.destination.path)\n\(detail)\nЕсли macOS показывает блокировку, разрешите именно Corporate VPN Router: «Системные настройки → Конфиденциальность и безопасность → Всё равно открыть», затем откройте его из ~/Applications. Повторно устанавливать DMG не нужно.")
    }
    func show(_ text: String) {
        let alert = NSAlert(); alert.messageText = "Установка Corporate VPN Router"; alert.informativeText = text
        NSApp.activate(ignoringOtherApps: true); alert.runModal(); NSApp.terminate(nil)
    }
}

umask(0o077)
if CommandLine.arguments.dropFirst().first == "--install-only" {
    do { try Distribution.install(); print(Distribution.destination.path) }
    catch { fputs(AppInstallation.describe(error) + "\n", stderr); exit(1) }
} else if CommandLine.arguments.dropFirst().first == "--home" {
    print(Distribution.home.path)
} else {
    let app = NSApplication.shared, delegate = Installer()
    app.setActivationPolicy(.accessory); app.delegate = delegate; app.run()
    withExtendedLifetime(delegate) {}
}
