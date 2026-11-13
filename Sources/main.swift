import Foundation
import AppKit
import Darwin
umask(0o077)
let paths=ProductPaths(), mode=CommandLine.arguments.dropFirst().first ?? "--ui"
do{
    switch mode {
    case "--version":print(productVersion)
    case "--installation-home":print(paths.home.path)
    case "--install":try BetaInstall.install(paths);print("Installed: "+paths.app.path)
    case "--diagnose":
        if let data=try? Data(contentsOf:paths.data.appendingPathComponent("ssl-status.json")){print(String(decoding:data,as:UTF8.self))}
        else{print("Menu app has not started.")}
    case "--ui","--login":
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
            if flock(lockFD,LOCK_EX|LOCK_NB) != 0 {exit(0)}
#if CVR_DEMO_SINGLE && !CVR_SELECTIVE_TUN
            try BetaInstall.registerLogin(paths)
#endif
            try BetaInstall.seedWorkSites(paths)
#if CVR_SELECTIVE_TUN && CVR_UPDATES
            try Provisioning.migrate(paths, resources: Bundle.main.resourceURL!)
#endif
            let app=NSApplication.shared, delegate=BetaMenu()
            app.setActivationPolicy(.accessory);app.delegate=delegate;app.run()
            withExtendedLifetime(delegate){};close(lockFD)
        }
    default:throw RouterError.invalidConfiguration
    }
}catch{if mode=="--ui" {
    let a=NSAlert();a.messageText="Установка не завершена"
    a.informativeText=AppInstallation.describe(error)
    NSApplication.shared.activate(ignoringOtherApps:true);a.runModal()
}; fputs("Corporate VPN Router: \(AppInstallation.describe(error))\n",stderr); exit(1)}
