import Foundation
import AppKit
import Darwin
umask(0o077)
let paths=ProductPaths(), mode=CommandLine.arguments.dropFirst().first ?? "--ui"
do{
    switch mode {
    case "--version":print(productVersion)
    case "--install":try BetaInstall.install(paths);print("Installed: "+paths.app.path)
    case "--diagnose":
        if let data=try? Data(contentsOf:paths.data.appendingPathComponent("ssl-status.json")){print(String(decoding:data,as:UTF8.self))}
        else{print("Menu app has not started.")}
    case "--ui","--login":
        if try Lifecycle.sourceApp().standardizedFileURL != paths.app.standardizedFileURL {
            try BetaInstall.install(paths)
            let result=command("/usr/bin/open",["-n",paths.app.path])
            if result.code != 0{throw RouterError.io}
        }else{
            let lockURL=paths.data.appendingPathComponent("menu.lock")
            try paths.createData()
            let lockFD=open(lockURL.path,O_CREAT|O_RDWR,0o600)
            guard lockFD >= 0 else{throw RouterError.io}
            if flock(lockFD,LOCK_EX|LOCK_NB) != 0 {exit(0)}
            let app=NSApplication.shared, delegate=BetaMenu()
            app.setActivationPolicy(.accessory);app.delegate=delegate;app.run()
            withExtendedLifetime(delegate){};close(lockFD)
        }
    default:throw RouterError.invalidConfiguration
    }
}catch{if mode=="--ui" {
    let a=NSAlert();a.messageText="Установка не завершена"
    a.informativeText=(error as? RouterError) == .staleNetwork ? "Завершите прежнюю версию через меню VPN и снова откройте новое приложение." : "Не удалось проверить или заменить приложение и его автозапуск. Предыдущую настройку можно проверить в Finder."
    NSApplication.shared.activate(ignoringOtherApps:true);a.runModal()
}; fputs("Corporate VPN Router: installation or launch failed.\n",stderr); exit(1)}
