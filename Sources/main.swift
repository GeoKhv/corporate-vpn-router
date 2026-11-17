import Foundation
import AppKit
import Darwin
umask(0o077)
let paths=ProductPaths(), mode=CommandLine.arguments.dropFirst().first ?? "--ui"
#if CVR_SELECTIVE_TUN
StartupDiagnostics.shared.begin(home: paths.home, source: Bundle.main.bundleURL)
#endif
do{
    switch mode {
    case "--version":print(productVersion)
    case "--installation-home":print(paths.home.path)
    case "--install":try BetaInstall.install(paths);print("Installed: "+paths.app.path)
    case "--diagnose":
        if let data=try? Data(contentsOf:paths.data.appendingPathComponent("ssl-status.json")){print(String(decoding:data,as:UTF8.self))}
        else{print("Menu app has not started.")}
    case "--ui","--login":
#if CVR_SELECTIVE_TUN
        let source = try Lifecycle.sourceApp()
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: AppInstallation.identifier)
            .contains { item in item.processIdentifier != getpid() && item.bundleURL.map { AppInstallation.sameLocation($0, paths.app) } == true }
        let plan = try FirstLaunchPlan.make(source: source, paths: paths, running: running)
        let handedOff = try StartupHandoff.requestedToken() != nil && BetaInstall.isInstalledCopy(source, paths)
        if plan.action != .runInstalled && !handedOff {
            guard mode != "--login" else { throw InstallationError(step: "Автозапуск указывает на переносную копию", detail: "Откройте Router обычным двойным кликом для установки. Настройки сохранены.") }
            let app = NSApplication.shared, delegate = FirstLaunchWindow(source: source, paths: paths, plan: plan)
            app.setActivationPolicy(.regular); app.delegate = delegate; app.run()
            withExtendedLifetime(delegate) {}; exit(0)
        }
        try AppInstallation.verify(paths.app)
        StartupDiagnostics.shared.record("installed_source_verified", paths.app.path)
        let wasInstalled = true
#else
        let wasInstalled = try BetaInstall.isInstalledCopy(Lifecycle.sourceApp(), paths)
        if !wasInstalled {
#if CVR_SELECTIVE_TUN
            guard !FileManager.default.fileExists(atPath: paths.app.path) else {
                throw InstallationError(step: "Запущена другая копия Router", detail: "Откройте установленное приложение: \(paths.app.path). Резервная копия не заменяет его при обычном запуске. Для обновления используйте меню установленного Router.")
            }
#endif
            try BetaInstall.install(paths)
#if !CVR_DEMO_SINGLE || CVR_SELECTIVE_TUN
            _ = try AppInstallation.run("/usr/bin/open", ["-n", paths.app.path], step: "Приложение установлено, но macOS не разрешила запуск. Откройте его из ~/Applications; при запросе используйте «Конфиденциальность и безопасность → Всё равно открыть».")
#if CVR_SELECTIVE_TUN
            exit(0)
#endif
#endif
        }
#endif
#if CVR_DEMO_SINGLE
        let runMenu = true
#else
        let runMenu = wasInstalled
#endif
        if runMenu {
            let lockURL=paths.data.appendingPathComponent("menu.lock")
            try paths.createData()
            let lockFD=open(lockURL.path,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0o600)
            guard lockFD >= 0 else{
                throw InstallationError(step: "Не удалось запустить меню Router", detail: "\(lockURL.path): \(String(cString: strerror(errno))) (errno \(errno)). Проверьте доступ к папке данных.")
            }
            if flock(lockFD,LOCK_EX|LOCK_NB) != 0 {
#if CVR_SELECTIVE_TUN
                if let existing = NSRunningApplication.runningApplications(withBundleIdentifier: AppInstallation.identifier)
                    .first(where: { item in item.processIdentifier != getpid() && item.bundleURL.map { AppInstallation.sameLocation($0, paths.app) } == true }) {
                    existing.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
                    StartupDiagnostics.shared.record("installed_instance_already_running")
                    StartupHandoff.acknowledge(paths)
                }
#endif
                exit(0)
            }
#if CVR_SELECTIVE_TUN
            try AppInstallation.relocateLogin(home: paths.home, systemApplications: paths.systemApplications)
#endif
#if CVR_DEMO_SINGLE && !CVR_SELECTIVE_TUN
            try BetaInstall.registerLogin(paths)
#endif
            try BetaInstall.seedWorkSites(paths)
#if CVR_SELECTIVE_TUN && CVR_UPDATES
            try Provisioning.migrate(paths, resources: paths.app.appendingPathComponent("Contents/Resources"))
#endif
            let app=NSApplication.shared, delegate=BetaMenu(paths: paths)
            app.setActivationPolicy(.accessory);app.delegate=delegate;app.run()
            withExtendedLifetime(delegate){};close(lockFD)
        }
    default:throw RouterError.invalidConfiguration
    }
}catch{
#if CVR_SELECTIVE_TUN
    StartupDiagnostics.shared.record("startup_failed", AppInstallation.describe(error))
    if mode == "--ui" {
        let app = NSApplication.shared, delegate = FirstLaunchWindow(source: Bundle.main.bundleURL, paths: paths, error: error)
        app.setActivationPolicy(.regular); app.delegate = delegate; app.run(); withExtendedLifetime(delegate) {}
    }
#else
if mode=="--ui" {
    let a=NSAlert();a.messageText="Установка не завершена"
    a.informativeText=AppInstallation.describe(error)
    NSApplication.shared.activate(ignoringOtherApps:true);a.runModal()
}
#endif
fputs("Corporate VPN Router: \(AppInstallation.describe(error))\n",stderr); exit(1)}
