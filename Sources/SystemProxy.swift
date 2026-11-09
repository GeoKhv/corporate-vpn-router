import Foundation
import SystemConfiguration
import Security
import Darwin

struct ProxyFailure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

enum SystemProxy {
    static let endpoint: [String: Any] = [
        "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 1091,
        "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": 1091
    ]
    static let label = "com.geokhv.corporate-vpn-router.http"
    typealias Receipt = [String: [String: Any]]
    static func receipt(_ p: ProductPaths) -> URL { p.data.appendingPathComponent("system-proxy.plist") }
    static func equal(_ a: Any?, _ b: Any?) -> Bool {
        if a == nil { return b == nil }
        return (a as? NSObject)?.isEqual(b) == true
    }
    static func effective() -> Bool {
        let cfg = SCDynamicStoreCopyProxies(nil) as? [String: Any] ?? [:]
        return endpoint.allSatisfy { equal(cfg[$0.key], $0.value) } && !bypass(cfg)
    }
    static func chromeProxyForced() -> Bool {
        let chrome="com.google.Chrome" as CFString
        CFPreferencesAppSynchronize(chrome)
        return ["ProxySettings","ProxyMode","ProxyServer","ProxyPacUrl","ProxyPacMandatory","ProxyBypassList","ProxyOverrideRules"].contains {
            CFPreferencesAppValueIsForced($0 as CFString,chrome)
        }
    }
    static func bypass(_ cfg: [String: Any]) -> Bool {
        ["ProxyAutoConfigEnable","ProxyAutoDiscoveryEnable","SOCKSEnable"].contains {
            (cfg[$0] as? NSNumber)?.boolValue == true
        } || !(cfg["ExceptionsList"] as? [String] ?? []).isEmpty
    }

    static func startAgent(_ p: ProductPaths) throws {
        try Lifecycle.verifyOwnership(p)
        let resources = p.app.appendingPathComponent("Contents/Resources")
        let args = [resources.appendingPathComponent("Runtime/bin/python3.13").path, "-I", "-B",
                    resources.appendingPathComponent("Engine/http_router.py").path]
        let spec: [String:Any] = ["Label":label,"ProgramArguments":args,"RunAtLoad":true,"KeepAlive":true,
                                   "LimitLoadToSessionType":"Aqua","ThrottleInterval":2,"Umask":0o077]
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
            let args=[p.app.appendingPathComponent("Contents/Resources/Runtime/bin/python3.13").path,"-I","-B",
                      p.app.appendingPathComponent("Contents/Resources/Engine/http_router.py").path]
            guard try url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink != true,
                  let spec=try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any],
                  spec["Label"] as? String==label,spec["ProgramArguments"] as? [String]==args else {throw ProxyFailure("Файл автозапуска изменился.")}
            let job=p.domain + "/" + label
            if command("/bin/launchctl",["print",job]).code==0 && command("/bin/launchctl",["bootout",job]).code != 0 {
                throw ProxyFailure("Не удалось завершить собственный маршрутизатор.")
            }
            try FileManager.default.removeItem(at:url)
        }
        try JSONFile.write("off",to:p.data.appendingPathComponent("routing-mode.json"))
    }
    static func authorize() throws -> (AuthorizationRef, SCPreferences) {
        var auth: AuthorizationRef?
        guard AuthorizationCreate(nil,nil,[],&auth)==errAuthorizationSuccess, let auth else {
            throw ProxyFailure("macOS не предоставила системное подтверждение.")
        }
        guard let prefs = SCPreferencesCreateWithAuthorization(nil,"Corporate VPN Router" as CFString,nil,auth) else {
            AuthorizationFree(auth,[]); throw ProxyFailure("Не удалось открыть настройки сети.")
        }
        return (auth,prefs)
    }
    static func transact(_ p: ProductPaths, restore: Bool) throws {
        let url=receipt(p), fm=FileManager.default
        if restore && !fm.fileExists(atPath:url.path) {return}
        let (auth,prefs)=try authorize()
        defer {AuthorizationFree(auth,[])}
        guard SCPreferencesLock(prefs,false) else {throw ProxyFailure("Настройки сети заняты или macOS не разрешила изменение.")}
        defer {SCPreferencesUnlock(prefs)}
        guard let set=SCNetworkSetCopyCurrent(prefs),let services=SCNetworkSetCopyServices(set) as? [SCNetworkService] else {
            throw ProxyFailure("Не удалось получить активную сетевую конфигурацию.")
        }
        var saved=Receipt()
        if fm.fileExists(atPath:url.path) {
            guard try url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink != true,
                  let data=try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? Receipt else {
                throw ProxyFailure("Не удалось проверить резервную копию сети.")
            }
            saved=data
        }
        if restore {
            // Look up by stable ID, including services in other network locations.
            for (id, entry) in saved {
                guard let service=SCNetworkServiceCopy(prefs,id as CFString),
                      let proto=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeProxies) else {continue}
                let cfg=SCNetworkProtocolGetConfiguration(proto) as? [String:Any] ?? [:]
                guard let old=entry["before"] as? [String:Any] else {throw ProxyFailure("Резервная копия повреждена.")}
                var revised=cfg
                // Restore each protocol as a group. A later change of server, port or
                // enable state transfers the entire group to the new controller.
                for prefix in ["HTTP","HTTPS"] {
                    let keys=["Enable","Proxy","Port"].map { prefix + $0 }
                    if keys.allSatisfy({equal(cfg[$0],endpoint[$0])}) {
                        for key in keys {revised[key]=old[key]}
                    }
                }
                guard SCNetworkProtocolSetConfiguration(proto,revised as CFDictionary) else {
                    throw ProxyFailure("Не удалось восстановить параметры службы.")
                }
            }
        } else {
            let global = SCDynamicStoreCopyProxies(nil) as? [String:Any] ?? [:]
            let otherManual = ["HTTPEnable","HTTPSEnable"].contains{(global[$0] as? NSNumber)?.boolValue == true}
            guard !bypass(global), !otherManual || (!saved.isEmpty && effective()) else {
                throw ProxyFailure("Основная сеть уже публикует другую конфигурацию прокси.")
            }
            for service in services where SCNetworkServiceGetEnabled(service) {
                guard let iface=SCNetworkServiceGetInterface(service),
                      let type=SCNetworkInterfaceGetInterfaceType(iface) as String?,
                      ["Ethernet","IEEE80211"].contains(type),
                      let id=SCNetworkServiceGetServiceID(service) as String?,
                      let proto=SCNetworkServiceCopyProtocol(service,kSCNetworkProtocolTypeProxies) else {continue}
                let cfg=SCNetworkProtocolGetConfiguration(proto) as? [String:Any] ?? [:]
                guard SCNetworkProtocolGetEnabled(proto), !bypass(cfg) else {throw ProxyFailure("У сетевой службы уже настроены исключения или другой прокси.")}
                if saved[id] != nil {
                    guard endpoint.allSatisfy({equal(cfg[$0.key],$0.value)}) else {throw ProxyFailure("Сетевые настройки изменены после установки.")}
                    continue
                }
                guard ["HTTPEnable","HTTPSEnable"].allSatisfy({(cfg[$0] as? NSNumber)?.boolValue != true}) else {throw ProxyFailure("Служба уже использует другой прокси.")}
                saved[id]=["before":cfg]
                let after=cfg.merging(endpoint){_,new in new}
                guard SCNetworkProtocolSetConfiguration(proto,after as CFDictionary) else {throw ProxyFailure("Системная служба отклонила параметры прокси.")}
            }
            guard !saved.isEmpty else {throw ProxyFailure("Нет доступных служб Wi-Fi или Ethernet.")}
            try PropertyListSerialization.data(fromPropertyList:saved,format:.binary,options:0).write(to:url,options:.atomic)
        }
        guard SCPreferencesCommitChanges(prefs),SCPreferencesApplyChanges(prefs) else {throw ProxyFailure("macOS не подтвердила запись. Резервная копия доступна в приложении.")}
        if restore {try fm.removeItem(at:url)}
    }
}
