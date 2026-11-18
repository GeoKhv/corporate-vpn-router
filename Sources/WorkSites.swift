import AppKit

enum TCPPorts: Codable {
    case any, selected([Int])
    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if (try? value.decode(String.self)) == "*" { self = .any }
        else { self = .selected(try value.decode([Int].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self { case .any: try value.encode("*"); case .selected(let ports): try value.encode(ports) }
    }
    var label: String {
        switch self { case .any: return "*"; case .selected(let ports): return ports.map(String.init).joined(separator:", ") }
    }
}
struct WorkSite: Codable { var domain: String; var scope: String; var tcp: TCPPorts?; var alias: String? }
struct SharedTCPRule: Decodable {
    let kind: String
    let domain: String
    let ports: [Int]
    let shortName: Bool
}
struct WorkProfile: Codable {
    var version = 1
    var sites: [WorkSite] = []
    var beforeLogin: [String] = []
    var ports = [443]
    func enrollment(desktop: String) throws -> Data {
        let rules = sites.map { row -> [String:Any] in
            let selection = row.tcp ?? .selected(ports)
            var value: [String:Any] = ["domain":row.domain, "scope":row.scope]
            switch selection {
            case .any: value["ports"] = [Int](); value["anyTCP"] = true
            case .selected(let ports): value["ports"] = Array(Set(ports)).sorted(); value["anyTCP"] = false
            }
            if let alias = row.alias { value["alias"] = alias }
            return value
        }
        return try JSONSerialization.data(withJSONObject:["domains":sites.map{$0.domain}, "desktop":desktop, "rules":rules])
    }
    func work(_ h: String) -> Bool {
        !beforeLogin.contains(h) && sites.contains { h == $0.domain || ($0.scope == "tree" && h.hasSuffix("."+$0.domain)) }
    }
}
final class SitesPanel {
    var draft = WorkProfile()
    let list = NSPopUpButton(), scope = NSPopUpButton(), domain = NSTextField(), login = NSTextField(), address = NSTextField()
    let ports = NSTextField(), short = NSButton(checkboxWithTitle:"Использовать короткое имя узла",target:nil,action:nil)
    var suggestion: (String,Int,String)?
    var requestID = UUID()
    let applySuggestion = NSButton()
    let status = NSTextField(wrappingLabelWithString:""), preview = NSTextField(wrappingLabelWithString:"")
}

extension BetaMenu {
    static func routeCommand(_ op: String, _ args: [String] = []) -> CommandResult {
        let res = ProductPaths().app.appendingPathComponent("Contents/Resources")
#if CVR_SELECTIVE_TUN
        if op == "save" || op == "validate" || op == "check-draft" {
            return command(res.appendingPathComponent("Runtime/bin/python3.13").path,
                ["-I", "-B", res.appendingPathComponent("Engine/Selective/controller.py").path, op] + args, timeout: 20)
        }
#endif
        let result=command(res.appendingPathComponent("Runtime/bin/python3.13").path,
                       ["-I","-B",res.appendingPathComponent("Engine/routing.py").path,op]+args,timeout:28)
        if op=="status" && result.output.hasPrefix("Chrome ·") && !BrowserRouter.effective() {
            return CommandResult(code:1,output:"macOS пока не подтвердила постоянный прокси Chrome.")
        }
        return result
    }
    var workURL: URL { paths.data.appendingPathComponent("work-sites.json") }
    func storedWork() -> WorkProfile? {
        if FileManager.default.fileExists(atPath:workURL.path) { return try? JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:workURL)) }
        var v = WorkProfile()
        guard let old=legacyPolicy() else { return nil }
        v.ports=old.ports; v.sites=old.domains.map{ WorkSite(domain:$0,scope:"tree") };return v
    }
    func gateway() -> String? {
        let u=paths.data.appendingPathComponent("ssl-site.json")
        return (try? JSONSerialization.jsonObject(with:Data(contentsOf:u)) as? [String:String])?["site"]
    }
    func panelButton(_ title:String,_ action:Selector)->NSButton { NSButton(title:title,target:self,action:action) }
    @objc func settings() {
        let p=sitesPanel
        if settingsWindow == nil {
            let w=makeWindow("Рабочие сайты",740,640)
            w.isRestorable = false
            p.list.target=self;p.list.action=#selector(selectSite)
            p.scope.addItems(withTitles:["Только это имя","Имя и все поддомены"])
            p.domain.placeholderString="wiki.company.example"; p.address.placeholderString="Адрес сайта или URL"
            for field in [p.domain,p.address,p.login] {field.widthAnchor.constraint(equalToConstant:320).isActive=true}
            for field in [p.status,p.preview,settingsNote] {field.preferredMaxLayoutWidth=580}
            let row1=NSStackView(views:[p.list,panelButton("Добавить",#selector(newSite)),panelButton("Удалить строку",#selector(removeSite))])
            let row2=NSStackView(views:[p.domain,p.scope,panelButton("В список",#selector(editSite))])
            p.applySuggestion.title = "Добавить/изменить правило"
            p.applySuggestion.target = self; p.applySuggestion.action = #selector(useSuggestion)
            p.applySuggestion.isHidden = true
            let portRow = NSStackView(views:[NSTextField(labelWithString:"TCP-порты ( * — любой TCP )"),p.ports,p.short])
            p.ports.widthAnchor.constraint(equalToConstant:120).isActive=true
            let row3=NSStackView(views:[p.address,panelButton("Проверить подключение",#selector(previewRoute))])
#if CVR_SELECTIVE_TUN
            let routeHeading = "2. Рабочие маршруты для обычных приложений"
            let row4=NSStackView(views:[panelButton("Проверить состояние",#selector(routeStatus)),panelButton("Сертификаты HTTPS…",#selector(certificates))])
#else
            let routeHeading = "2. Постоянный прокси Chrome"
            let row4=NSStackView(views:[panelButton("Настроить Chrome…",#selector(appRouting)),panelButton("Проверить состояние",#selector(routeStatus))])
#endif
            let row5=NSStackView(views:[panelButton("Импорт профиля…",#selector(importSites)),panelButton("Сохранить список",#selector(savePolicy)),panelButton("Вернуть прежние правила",#selector(undoSites))])
            attachColumn(makeColumn([NSTextField(labelWithString:"1. Рабочие сайты · добавьте домен или импортируйте профиль"),row1,row2,portRow,
                NSTextField(labelWithString:"Доступ до входа · точные имена шлюза и авторизации, через запятую"),p.login,
                row5,row3,p.preview,p.applySuggestion,NSTextField(labelWithString:routeHeading),row4,p.status,settingsNote]),to:w)
            settingsWindow=w
        }
        routeStatus()
        p.draft=storedWork() ?? WorkProfile()
        if let g=gateway(), !p.draft.beforeLogin.contains(g){p.draft.beforeLogin.append(g)}
        loadDraft()
        settingsNote.stringValue="После настройки вернитесь в главное окно и выберите способ входа."
        NSApp.activate(ignoringOtherApps:true);settingsWindow?.makeKeyAndOrderFront(nil)
    }
    func loadDraft(_ selected:Int=0) {
        let p=sitesPanel;p.login.stringValue=p.draft.beforeLogin.joined(separator:", ")
        p.list.removeAllItems();p.list.addItems(withTitles:p.draft.sites.map{$0.domain});p.list.addItem(withTitle:"Новая строка")
        p.list.selectItem(at:min(selected,p.draft.sites.count));selectSite()
    }
    @objc func selectSite(){let p=sitesPanel,i=p.list.indexOfSelectedItem
        if p.draft.sites.indices.contains(i){let r=p.draft.sites[i];p.domain.stringValue=r.domain;p.scope.selectItem(at:r.scope=="tree" ? 1 : 0);p.ports.stringValue=(r.tcp ?? .selected(p.draft.ports)).label;p.short.state=r.alias == nil ? .off : .on}
        else {p.domain.stringValue="";p.scope.selectItem(at:0);p.ports.stringValue=TCPPorts.selected(p.draft.ports).label;p.short.state = .off}
    }
    @objc func newSite(){sitesPanel.list.selectItem(at:sitesPanel.draft.sites.count);selectSite();settingsWindow?.makeFirstResponder(sitesPanel.domain)}
    func readLogin(){sitesPanel.draft.beforeLogin=sitesPanel.login.stringValue.lowercased().split(whereSeparator:{$0=="," || $0.isWhitespace}).map(String.init)}
    @objc func removeSite(){let p=sitesPanel,i=p.list.indexOfSelectedItem;guard p.draft.sites.indices.contains(i) else{return};readLogin();p.draft.sites.remove(at:i);loadDraft()}
    @discardableResult @objc func editSite()->Bool {
        let p=sitesPanel,h=p.domain.stringValue.trimmingCharacters(in:.whitespacesAndNewlines).lowercased(),i=p.list.indexOfSelectedItem
        guard Configuration.validHost(h), h.contains("."), !p.draft.sites.enumerated().contains(where:{$0.offset != i && $0.element.domain==h}) else{
            settingsNote.stringValue="Введите уникальное доменное имя без пути и без *.";return false }
        let raw=p.ports.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
        let tokens=raw.split(separator:",",omittingEmptySubsequences:false)
        let ports=tokens.compactMap { Int($0.trimmingCharacters(in:.whitespaces)) }
        guard raw == "*" || (ports.count == tokens.count && (1...32).contains(ports.count) && ports.allSatisfy({(1...65535).contains($0)}))
        else { settingsNote.stringValue="Укажите порты через запятую или * для любого TCP.";return false }
        let r=WorkSite(domain:h,scope:p.scope.indexOfSelectedItem==1 ? "tree":"exact",
                       tcp:raw == "*" ? .any : .selected(Array(Set(ports)).sorted()),
                       alias:p.short.state == .on ? h.components(separatedBy:".").first : nil)
        p.draft.version = 2
        readLogin()
        if p.draft.sites.indices.contains(i){p.draft.sites[i]=r}else{p.draft.sites.append(r)}
        loadDraft(i);settingsNote.stringValue="Строка добавлена в черновик. Сохраните список.";return true
    }
    @objc func importSites(){let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        guard panel.runModal() == .OK, let u=panel.url else{return}
        do{let data=try Data(contentsOf:u);guard data.count<=131072 else{throw RouterError.invalidConfiguration}
            if let rule = try? JSONDecoder().decode(SharedTCPRule.self, from:data) {
                guard rule.kind == "exact-tcp-rule", Configuration.validHost(rule.domain), rule.domain.contains("."),
                      !rule.ports.isEmpty, rule.ports.count <= 32, rule.ports.allSatisfy({ (1...65535).contains($0) }),
                      !sitesPanel.draft.beforeLogin.contains(rule.domain) else { throw RouterError.invalidConfiguration }
                let p = sitesPanel
                let exact = p.draft.sites.firstIndex { $0.domain == rule.domain }
                guard exact.map({ p.draft.sites[$0].scope == "exact" }) ?? true else {
                    settingsNote.stringValue="Для этого имени уже задано правило с поддоменами. Выберите разрешения вручную."
                    return
                }
                let inherited = p.draft.sites.filter { $0.domain == rule.domain ||
                    ($0.scope == "tree" && rule.domain.hasSuffix("." + $0.domain)) }.max { $0.domain.count < $1.domain.count }
                let base = inherited.map { $0.tcp ?? .selected(p.draft.ports) } ?? .selected([])
                if let index = exact { p.list.selectItem(at:index); selectSite() } else { newSite(); p.domain.stringValue=rule.domain }
                switch base {
                case .any: p.ports.stringValue="*"
                case .selected(let ports): p.ports.stringValue=TCPPorts.selected(Array(Set(ports + rule.ports)).sorted()).label
                }
                if rule.shortName { p.short.state = .on }
                if editSite() { settingsNote.stringValue="В черновике изменено одно точное правило. Проверьте адрес и порты, затем сохраните список." }
                return
            }
            let draft=try JSONDecoder().decode(WorkProfile.self,from:data); guard [1,2].contains(draft.version) && !draft.sites.isEmpty && draft.sites.count<=256 else{throw RouterError.invalidConfiguration}
            sitesPanel.draft=draft;loadDraft();settingsNote.stringValue="Импортирован черновик. Проверьте область доменов и адреса до входа."
        }catch{settingsNote.stringValue="Не удалось прочитать профиль рабочих сайтов."}
    }
    @objc func undoSites() {
        let previous = paths.data.appendingPathComponent("previous-work-sites.json")
        guard let data = try? Data(contentsOf:previous), let profile = try? JSONDecoder().decode(WorkProfile.self,from:data) else {
            settingsNote.stringValue="Предыдущая версия правил отсутствует.";return
        }
        sitesPanel.draft=profile;loadDraft();settingsNote.stringValue="Предыдущие правила загружены в черновик. Проверьте и сохраните."
    }
    @objc func useSuggestion() {
        let p=sitesPanel
        guard let (host,port,text)=p.suggestion, text == p.address.stringValue else{return}
        let matches=p.draft.sites.filter { host==$0.domain || ($0.scope=="tree" && host.hasSuffix("."+$0.domain)) }
        let current=matches.max(by:{$0.domain.count<$1.domain.count})
        var existing=[Int]()
        if let current, case let .selected(ports) = current.tcp ?? .selected(p.draft.ports) { existing=ports }
        if let index=p.draft.sites.firstIndex(where:{$0.domain==host}) {
            p.list.selectItem(at:index); selectSite()
            if p.draft.sites[index].scope == "tree" {
                p.preview.stringValue="Это имя уже охватывает поддомены. Выберите охват и подтвердите порты вручную."
                return
            }
        } else { newSite(); p.domain.stringValue=host }
        p.ports.stringValue=TCPPorts.selected(Array(Set(existing+[port])).sorted()).label
        if editSite() { settingsNote.stringValue="Предложение в черновике. Для применения сохраните список." }
        p.applySuggestion.isHidden=true
    }
    @objc func previewRoute(){
        let p=sitesPanel, value=p.address.stringValue, id=UUID()
        p.requestID=id;p.applySuggestion.isHidden=true;p.suggestion=nil;p.preview.stringValue="Проверяем подключение…"
        let res=resources
        DispatchQueue.global(qos:.userInitiated).async {
            let proc=Process(), input=Pipe(), output=Pipe()
            proc.executableURL=res.appendingPathComponent("Runtime/bin/python3.13")
            proc.arguments=["-I","-B",res.appendingPathComponent("Engine/Selective/analyze.py").path]
            proc.standardInput=input;proc.standardOutput=output;proc.standardError=FileHandle.nullDevice
            var result:[String:Any]=[:]
            if value.utf8.count<=2048, (try? proc.run()) != nil {
                try? input.fileHandleForWriting.write(contentsOf:Data(value.utf8));try? input.fileHandleForWriting.close()
                let data=output.fileHandleForReading.readDataToEndOfFile();proc.waitUntilExit()
                result=(try? JSONSerialization.jsonObject(with:data) as? [String:Any]) ?? [:]
            }
            DispatchQueue.main.async {
                guard p.requestID==id, p.address.stringValue==value else{return}
                p.preview.stringValue=result["message"] as? String ?? "Не удалось проверить адрес."
                if let host=result["host"] as? String, let port=result["port"] as? Int {
                    p.suggestion=(host,port,value);p.applySuggestion.isHidden=false
                }
            }
        }
    }
    @objc func routeStatus(){
#if CVR_SELECTIVE_TUN
        sitesPanel.status.stringValue = selective.message
#else
        let r=Self.routeCommand("status")
        let state=r.output.trimmingCharacters(in:.whitespacesAndNewlines)
        if r.code==0 && state.hasPrefix("Chrome ·") {
            sitesPanel.status.stringValue = Self.routeCommand("ready").code==0
              ? (activated ? "Chrome · постоянный прокси подтверждён, маршрутизатор готов." : "Профиль установлен. Ожидается проверка из Chrome.")
              : "Профиль установлен, но маршрутизатор пока не отвечает."
        }else{sitesPanel.status.stringValue=state}
#endif
    }
    func confirmAction(_ title:String,_ msg:String,_ yes:String)->Bool{let a=NSAlert();a.messageText=title;a.informativeText=msg;a.addButton(withTitle:yes);a.addButton(withTitle:"Отмена");return a.runModal() == .alertFirstButtonReturn}
    @objc func savePolicy(){
#if CVR_SELECTIVE_TUN
        guard engine == nil && !selective.busy else { settingsNote.stringValue = "Сначала отключите туннель и остановите рабочие маршруты. Список пока не изменён."; return }
#else
        if BrowserRouter.effective() && !activated {settingsNote.stringValue="Сначала нажмите «Настроить Chrome…» для проверки маршрута в браузере.";return}
#endif
        if !sitesPanel.domain.stringValue.isEmpty && !editSite(){return}
        readLogin()
        let temp=paths.data.appendingPathComponent("draft-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        do{try JSONFile.write(sitesPanel.draft,to:temp)}catch{settingsNote.stringValue="Не удалось сохранить черновик.";return}
        #if CVR_SELECTIVE_TUN && CVR_UPDATES
        let validation=Self.routeCommand("check-draft",[temp.path])
        guard validation.code==0 else { settingsNote.stringValue=validation.output;return }
        let profile=sitesPanel.draft
        let status=SelectiveRouter.helperReply(resources:resources)
        let desktop=(status?["approvedRDPHost"] as? String).flatMap { profile.work($0) ? $0 : nil } ?? ""
        guard let enrollment=try? profile.enrollment(desktop:desktop),
              let expected=try? JSONSerialization.jsonObject(with:enrollment) as? [String:Any] else{return}
        if let old=status?["tcpRules"] as? NSArray, old.isEqual(expected["rules"]) {
            settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
        } else {
            let pending=paths.data.appendingPathComponent("pending-"+UUID().uuidString)
            do { try JSONFile.write(profile,to:pending) } catch { settingsNote.stringValue="Не удалось подготовить правила.";return }
            selective.manageHelper(resources:resources,enrollment:enrollment,reconfigure:true) { success in
                defer { try? FileManager.default.removeItem(at:pending) }
                self.settingsNote.stringValue = success ? Self.routeCommand("save",[pending.path]).output : "Изменения не применены. Проверьте состояние помощника."
            }
        }
        #else
        settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
        #endif
        routeStatus()
    }
    func closeChromeForMigration() throws -> URL? {
        let apps=NSRunningApplication.runningApplications(withBundleIdentifier:"com.google.Chrome")
        guard !apps.isEmpty else{return nil}
        guard let location=apps.first?.bundleURL,
              apps.allSatisfy({$0.bundleURL==location}),
              command("/usr/bin/codesign",["--verify","--strict=symlinks","-R=anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"",location.path],timeout:30).code==0
        else {throw ProxyFailure("Не удалось проверить основное приложение Google Chrome.")}
        guard apps.allSatisfy({$0.terminate()}) else{throw ProxyFailure("Chrome не подтвердил штатное завершение.")}
        let until=Date().addingTimeInterval(18)
        while Date()<until && apps.contains(where:{kill($0.processIdentifier,0)==0}) {RunLoop.current.run(until:Date().addingTimeInterval(0.1))}
        guard apps.allSatisfy({kill($0.processIdentifier,0) != 0}) else{throw ProxyFailure("Завершение Chrome отменено или браузер ожидает ответа. Прежний профиль сохранён.")}
        return location
    }
    func reopenChrome(_ location:URL?) throws {
        guard let location else{return}
        guard command("/usr/bin/open",["-a",location.path,"--args","--restore-last-session"],timeout:30).code==0
        else {throw ProxyFailure("macOS не смогла вновь открыть Chrome с сохранёнными вкладками.")}
    }
    func waitForProfile(){
        enrollmentTimer?.invalidate()
        let until=Date().addingTimeInterval(600)
        enrollmentTimer=Timer.scheduledTimer(withTimeInterval:1,repeats:true){[weak self] timer in
            guard let self=self else{timer.invalidate();return}
            if Date()>until {timer.invalidate();self.settingsNote.stringValue="Подтверждение macOS не обнаружено. Можно повторить настройку.";return}
            guard BrowserRouter.effective() else{return}
            timer.invalidate();self.verifyChrome()
        }
    }
    func verifyChrome(){
        do{
            guard Self.routeCommand("status").output.hasPrefix("Chrome ·") else{throw ProxyFailure("Профиль ещё не подтверждён.")}
            let location=try closeChromeForMigration() ?? URL(fileURLWithPath:"/Applications/Google Chrome.app")
            let r=Self.routeCommand("challenge")
            guard r.code==0,let url=URL(string:r.output.trimmingCharacters(in:.whitespacesAndNewlines)),url.host=="router-check.invalid" else{try reopenChrome(location);throw ProxyFailure("Маршрутизатор не подтвердил начало проверки.")}
            try reopenChrome(location)
            guard command("/usr/bin/open",["-a",location.path,url.absoluteString],timeout:30).code==0 else{throw ProxyFailure("Не удалось открыть страницу проверки в основном Chrome.")}
            let until=Date().addingTimeInterval(55)
            self.enrollmentTimer=Timer.scheduledTimer(withTimeInterval:1,repeats:true){[weak self] t in
                guard let self=self else{t.invalidate();return}
                if Self.routeCommand("observed").code==0 && BrowserRouter.effective(){
                    t.invalidate()
                    do{try JSONFile.write(true,to:self.paths.data.appendingPathComponent("chrome-fixed-verified"));self.settingsNote.stringValue="Маршрут подтверждён запросом из Chrome. Можно подключить рабочий туннель и менять список.";self.note="Chrome настроен. Выберите способ входа и нажмите «Подключить».";self.refresh()}
                    catch{self.settingsNote.stringValue="Не удалось сохранить результат проверки."}
                }else if Date()>until {t.invalidate();self.settingsNote.stringValue="Запрос Chrome не пришёл через Router. Рабочий режим не подтверждён; доступен откат."}
            }
        }catch{settingsNote.stringValue=error.localizedDescription}
    }
    @objc func appRouting(){
#if CVR_SELECTIVE_TUN
        if selective.holdingRoutes { stop("Рабочие маршруты выключены."); return }
        guard engine == nil else { settingsNote.stringValue = "Сначала отключите рабочий туннель."; return }
        if selective.process != nil { selective.stop() }
        else if selective.helperAvailability.needsInstallation || selective.helperAvailability == .desktopAvailable { installRouteHelper() }
        else if selective.helperAvailability != .ready { selective.checkHelper(resources: resources) }
        else { connect() }
#else
        if BrowserRouter.effective() && activated {
            do{try BrowserRouter.startAgent(paths);routeStatus()}catch{settingsNote.stringValue=error.localizedDescription};return
        }
        guard confirmAction("Настроить постоянный прокси Chrome?", "Сохраните незавершённые формы и загрузки. После подтверждения профиля в macOS Router один раз перезапустит обычный Chrome и откроет страницу проверки. Список сайтов останется только в приложении.", "Продолжить") else{return}
        do {
            try BrowserRouter.startAgent(paths)
            let result=Self.routeCommand("prepare")
            guard result.code==0 else{throw ProxyFailure(result.output)}
            let path=result.output.trimmingCharacters(in:.whitespacesAndNewlines)
            if path=="active" {verifyChrome()} else {
                try? FileManager.default.removeItem(at:paths.data.appendingPathComponent("chrome-fixed-verified"))
                guard path==paths.data.appendingPathComponent("Chrome Local Router.mobileconfig").path,
                      NSWorkspace.shared.open(URL(fileURLWithPath:path)) else{throw ProxyFailure("Не удалось открыть профиль Chrome.")}
                settingsNote.stringValue="Подтвердите профиль Router в настройках macOS. Приложение дождётся подтверждения."
                note=settingsNote.stringValue;refresh()
                waitForProfile()
            }
        } catch {settingsNote.stringValue=error.localizedDescription}
        note=settingsNote.stringValue;refresh()
        routeStatus()
#endif
    }

}

extension BetaMenu {
    @objc func updateLink(){NSWorkspace.shared.open(URL(string:"https://github.com/GeoKhv/corporate-vpn-router/releases")!)}
    func maintenanceError(_ text:String){let a=NSAlert();a.messageText="Corporate VPN Router";a.informativeText=text;a.runModal()}
    func canMaintain()->Bool {
        guard engine==nil else{maintenanceError("Сначала отключите туннель.");return false}
        do{try Lifecycle.verifyOwnership(paths);_ = try BetaInstall.checkedAgent(paths)}catch{maintenanceError("Приложение или login item изменены. Операция остановлена.");return false}
        return true
    }
    func releaseForMaintenance()->Bool{
        do {
            try BrowserRouter.stopAgent(paths)
            return true
        }catch{maintenanceError(error.localizedDescription);return false}
    }
    @objc func uninstallMenu(){
        guard canMaintain(),confirmAction("Удалить Corporate VPN Router?","Собственный профиль Chrome будет снят. Приложение переместится в Корзину, его автозапуск будет удалён. Приватные данные, логин и копии сохранятся.","Удалить") else{return}
        let retired=Self.routeCommand("uninstall-owned")
        guard retired.code==0 else{maintenanceError(retired.output);return}
        guard releaseForMaintenance() else{return}
        do{
            let plist=try BetaInstall.checkedAgent(paths)
            if FileManager.default.fileExists(atPath:plist.path){try FileManager.default.trashItem(at:plist,resultingItemURL:nil)}
            try FileManager.default.trashItem(at:paths.app,resultingItemURL:nil)
            let pr=Process();pr.executableURL=URL(fileURLWithPath:"/bin/launchctl");pr.arguments=["bootout",paths.domain+"/"+BetaInstall.label];try pr.run()
            NSApp.terminate(nil)
        }catch{maintenanceError("Удаление не завершено. Проверьте права на приложение и автозапуск.")}
    }
    @objc func rollbackMenu(){
        guard canMaintain() else{return}
        guard let u=BetaInstall.beta5(paths) else{maintenanceError("Резервной копии с подписью опубликованной beta.5 нет. Используйте архив beta.5 со страницы релизов.");return}
        guard confirmAction("Восстановить beta.5?","Сохраните формы и дождитесь загрузок в Chrome. После подтверждения исходного профиля в macOS Router перезапустит Chrome, восстановит прежний список сайтов и откроет проверенную копию beta.5.","Восстановить") else{return}
        let profile=Self.routeCommand("rollback-profile")
        guard profile.code==0 else{maintenanceError(profile.output);return}
        if profile.output.hasPrefix("confirm"){
            NSWorkspace.shared.open(paths.data.appendingPathComponent("Chrome Work Sites.mobileconfig"))
            maintenanceError("Подтвердите сохранённый профиль beta.5 в macOS, затем снова выберите откат.")
            return
        }
        guard BrowserRouter.restored(paths) else{maintenanceError("macOS ещё не применила исходную политику beta.5. Маршрутизатор продолжает работать.");return}
        do {let location=try closeChromeForMigration();try reopenChrome(location)} catch {maintenanceError(error.localizedDescription);return}
        try? FileManager.default.removeItem(at:paths.data.appendingPathComponent("chrome-fixed-verified"))
        guard releaseForMaintenance() else{return}
        let p=Process()
        p.executableURL=URL(fileURLWithPath:"/bin/sh")
        p.arguments=["-c","while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open -n \"$2\"","router",String(getpid()),u.path]
        do{try p.run();NSApp.terminate(nil)}catch{maintenanceError("Не удалось запустить проверенную копию beta.5.")}
    }
}
