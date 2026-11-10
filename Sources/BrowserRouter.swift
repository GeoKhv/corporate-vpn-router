import Foundation
import Darwin

struct ProxyFailure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

enum BrowserRouter {
    static let label = "com.geokhv.corporate-vpn-router.http"
    static func forcedProxy() -> NSDictionary? {
        let chrome="com.google.Chrome" as CFString, key="ProxySettings" as CFString
        CFPreferencesAppSynchronize(chrome)
        let proxy=CFPreferencesCopyAppValue(key,chrome) as? NSDictionary
        return CFPreferencesAppValueIsForced(key,chrome) ? proxy : nil
    }
    static func effective() -> Bool {
        return forcedProxy()?.isEqual(to:[
            "ProxyMode":"fixed_servers","ProxyServer":"http://127.0.0.1:1091"]) == true
    }
    static func restored(_ paths:ProductPaths) -> Bool {
        let url=paths.data.appendingPathComponent("active-proxy.json")
        guard let data=try? Data(contentsOf:url),
              let old=try? JSONSerialization.jsonObject(with:data) as? [String:Any],
              old["ProxyMode"] as? String=="pac_script" else{return false}
        return forcedProxy()?.isEqual(to:old)==true
    }
    static func agentSpec(_ p:ProductPaths)->[String:Any] {
        let resources=p.app.appendingPathComponent("Contents/Resources")
        let args=[resources.appendingPathComponent("Runtime/bin/python3.13").path,"-I","-B",
                  resources.appendingPathComponent("Engine/http_router.py").path,"--launchd"]
        return ["Label":label,"ProgramArguments":args,"RunAtLoad":true,"KeepAlive":true,
                "Sockets":["Listener":["SockNodeName":"127.0.0.1","SockServiceName":"1091","SockFamily":"IPv4","SockType":"stream"]],
                "LimitLoadToSessionType":"Aqua","ThrottleInterval":2,"Umask":0o077]
    }
    static func startAgent(_ p: ProductPaths) throws {
        try Lifecycle.verifyOwnership(p)
        let spec=agentSpec(p)
        let folder = p.home.appendingPathComponent("Library/LaunchAgents")
        try FileManager.default.createDirectory(at:folder,withIntermediateDirectories:true)
        let url=folder.appendingPathComponent(label + ".plist")
        if FileManager.default.fileExists(atPath:url.path) {
            guard try url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink != true,
                  let actual = try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? NSDictionary,
                  actual.isEqual(to:spec) else {throw ProxyFailure("Файл автозапуска маршрутизатора изменён.")}
        } else {
            try PropertyListSerialization.data(fromPropertyList:spec,format:.xml,options:0).write(to:url,options:.withoutOverwriting)
        }
        let job=p.domain + "/" + label
        if command("/bin/launchctl",["print",job]).code != 0 {
            guard command("/bin/launchctl",["bootstrap",p.domain,url.path]).code == 0 else {
                throw ProxyFailure("macOS не разрешила запустить фоновый маршрутизатор.")
            }
        }
        for _ in 0..<40 {
            if BetaMenu.routeCommand("ready").code == 0 {return}
            Thread.sleep(forTimeInterval:0.1)
        }
        throw ProxyFailure("Фоновый маршрутизатор не подтвердил запуск. Проверьте занятость локального порта.")
    }

    static func stopAgent(_ p:ProductPaths) throws {
        let url=p.home.appendingPathComponent("Library/LaunchAgents/" + label + ".plist")
        if FileManager.default.fileExists(atPath:url.path) {
            guard try url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink != true,
                  let spec=try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? NSDictionary,
                  spec.isEqual(to:agentSpec(p)) else {throw ProxyFailure("Файл автозапуска изменился.")}
            let job=p.domain + "/" + label
            if command("/bin/launchctl",["print",job]).code==0 && command("/bin/launchctl",["bootout",job]).code != 0 {
                throw ProxyFailure("Не удалось завершить собственный маршрутизатор.")
            }
            try FileManager.default.removeItem(at:url)
        }
        try JSONFile.write("off",to:p.data.appendingPathComponent("routing-mode.json"))
    }
}
