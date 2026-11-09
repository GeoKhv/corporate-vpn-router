import AppKit

struct WorkSite: Codable { var domain: String; var scope: String }
struct WorkProfile: Codable {
    var version = 1
    var sites: [WorkSite] = []
    var beforeLogin: [String] = []
    var ports = [443]
    func work(_ h: String) -> Bool {
        !beforeLogin.contains(h) && sites.contains { h == $0.domain || ($0.scope == "tree" && h.hasSuffix("."+$0.domain)) }
    }
}
final class SitesPanel {
    var draft = WorkProfile()
    let list = NSPopUpButton(), scope = NSPopUpButton(), domain = NSTextField(), login = NSTextField(), address = NSTextField()
    let status = NSTextField(wrappingLabelWithString:""), preview = NSTextField(wrappingLabelWithString:"")
}

extension BetaMenu {
    static func routeCommand(_ op: String, _ args: [String] = []) -> CommandResult {
        guard let res = Bundle.main.resourceURL else { return CommandResult(code:1,output:"Нет встроенного runtime.") }
        let result=command(res.appendingPathComponent("Runtime/bin/python3.13").path,
                       ["-I","-B",res.appendingPathComponent("Engine/routing.py").path,op]+args,timeout:28)
        if (op=="status" || op=="retire") && result.output.hasPrefix("Системный прокси") && SystemProxy.chromeProxyForced() {
            return CommandResult(code:1,output:"macOS продолжает применять политику прокси Chrome. Переключение не подтверждено.")
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
            let w=makeWindow("Рабочие сайты",630,575)
            p.list.target=self;p.list.action=#selector(selectSite)
            p.scope.addItems(withTitles:["Только это имя","Имя и все поддомены"])
            p.domain.placeholderString="wiki.company.example"; p.address.placeholderString="Адрес сайта или URL"
            for field in [p.domain,p.address,p.login] {field.widthAnchor.constraint(equalToConstant:320).isActive=true}
            for field in [p.status,p.preview,settingsNote] {field.preferredMaxLayoutWidth=580}
            let row1=NSStackView(views:[p.list,panelButton("Добавить",#selector(newSite)),panelButton("Удалить строку",#selector(removeSite))])
            let row2=NSStackView(views:[p.domain,p.scope,panelButton("В список",#selector(editSite))])
            let row3=NSStackView(views:[p.address,panelButton("Проверить маршрут",#selector(previewRoute))])
            let row4=NSStackView(views:[panelButton("Включить системный прокси…",#selector(appRouting)),panelButton("Вернуть прежние сетевые настройки…",#selector(restoreRouting))])
            let row5=NSStackView(views:[panelButton("Импорт профиля…",#selector(importSites)),panelButton("Сохранить список",#selector(savePolicy))])
            attachColumn(makeColumn([NSTextField(labelWithString:"1. Рабочие сайты · добавьте домен или импортируйте профиль"),row1,row2,
                NSTextField(labelWithString:"Доступ до входа · точные имена шлюза и авторизации, через запятую"),p.login,
                row5,row3,p.preview,NSTextField(labelWithString:"2. Системный прокси macOS"),row4,p.status,settingsNote]),to:w)
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
        if p.draft.sites.indices.contains(i){let r=p.draft.sites[i];p.domain.stringValue=r.domain;p.scope.selectItem(at:r.scope=="tree" ? 1 : 0)}
        else {p.domain.stringValue="";p.scope.selectItem(at:0)}
    }
    @objc func newSite(){sitesPanel.list.selectItem(at:sitesPanel.draft.sites.count);selectSite();settingsWindow?.makeFirstResponder(sitesPanel.domain)}
    func readLogin(){sitesPanel.draft.beforeLogin=sitesPanel.login.stringValue.lowercased().split(whereSeparator:{$0=="," || $0.isWhitespace}).map(String.init)}
    @objc func removeSite(){let p=sitesPanel,i=p.list.indexOfSelectedItem;guard p.draft.sites.indices.contains(i) else{return};readLogin();p.draft.sites.remove(at:i);loadDraft()}
    @discardableResult @objc func editSite()->Bool {
        let p=sitesPanel,h=p.domain.stringValue.trimmingCharacters(in:.whitespacesAndNewlines).lowercased(),i=p.list.indexOfSelectedItem
        guard Configuration.validHost(h), h.contains("."), !p.draft.sites.enumerated().contains(where:{$0.offset != i && $0.element.domain==h}) else{
            settingsNote.stringValue="Введите уникальное доменное имя без пути и без *.";return false }
        let r=WorkSite(domain:h,scope:p.scope.indexOfSelectedItem==1 ? "tree":"exact");readLogin()
        if p.draft.sites.indices.contains(i){p.draft.sites[i]=r}else{p.draft.sites.append(r)}
        loadDraft(i);settingsNote.stringValue="Строка добавлена в черновик. Сохраните список.";return true
    }
    @objc func importSites(){let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        guard panel.runModal() == .OK, let u=panel.url else{return}
        do{let data=try Data(contentsOf:u);guard data.count<=131072 else{throw RouterError.invalidConfiguration}
            let draft=try JSONDecoder().decode(WorkProfile.self,from:data); guard draft.version==1 && !draft.sites.isEmpty && draft.sites.count<=256 else{throw RouterError.invalidConfiguration}
            sitesPanel.draft=draft;loadDraft();settingsNote.stringValue="Импортирован черновик. Проверьте область доменов и адреса до входа."
        }catch{settingsNote.stringValue="Не удалось прочитать профиль рабочих сайтов."}
    }
    @objc func previewRoute(){
        let p=sitesPanel;readLogin()
        let a=p.address.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
        guard let url=URLComponents(string:a.contains("://") ? a:"https://"+a),["http","https"].contains(url.scheme?.lowercased() ?? ""),
              var h=url.host?.lowercased(), !h.isEmpty, url.user==nil, url.password==nil else {p.preview.stringValue="Введите домен или полный HTTP(S)-адрес.";return}
        while h.hasSuffix("."){h.removeLast()}
        let port=url.port ?? (url.scheme=="http" ? 80:443)
        p.preview.stringValue="По списку: "+(p.draft.beforeLogin.contains(h) ? "доступ до входа · системный маршрут":p.draft.work(h) ? (p.draft.ports.contains(port) ? "рабочий · SOCKS5 внутри SSL":"рабочий · порт запрещён в SOCKS5"):"обычный · системный маршрут")
    }
    @objc func routeStatus(){
        let r=Self.routeCommand("status")
        let state=r.output.trimmingCharacters(in:.whitespacesAndNewlines)
        sitesPanel.status.stringValue=state=="Системный прокси" && !SystemProxy.effective() ? "Служба сети не публикует настройки Router. Проверьте режим перед открытием рабочих сайтов." : state
    }
    func confirmAction(_ title:String,_ msg:String,_ yes:String)->Bool{let a=NSAlert();a.messageText=title;a.informativeText=msg;a.addButton(withTitle:yes);a.addButton(withTitle:"Отмена");return a.runModal() == .alertFirstButtonReturn}
    @objc func savePolicy(){
        if !sitesPanel.domain.stringValue.isEmpty && !editSite(){return}
        readLogin()
        let temp=paths.data.appendingPathComponent("draft-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        do{try JSONFile.write(sitesPanel.draft,to:temp)}catch{settingsNote.stringValue="Не удалось сохранить черновик.";return}
        settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
        routeStatus()
    }
    func closeChromeForMigration() throws -> URL? {
        let apps=NSRunningApplication.runningApplications(withBundleIdentifier:"com.google.Chrome")
        guard !apps.isEmpty else{return nil}
        guard let location=apps.first?.bundleURL,
              apps.allSatisfy({$0.bundleURL==location}),
              command("/usr/bin/codesign",["--verify","--strict","-R=anchor apple generic and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"",location.path],timeout:30).code==0
        else {throw ProxyFailure("Не удалось проверить основное приложение Google Chrome.")}
        guard apps.allSatisfy({$0.terminate()}) else{throw ProxyFailure("Chrome не подтвердил штатное завершение.")}
        let until=Date().addingTimeInterval(18)
        while Date()<until && apps.contains(where:{!$0.isTerminated}) {Thread.sleep(forTimeInterval:0.1)}
        guard apps.allSatisfy({$0.isTerminated}) else{throw ProxyFailure("Завершение Chrome отменено или браузер ожидает ответа. Прежний профиль сохранён.")}
        return location
    }
    func reopenChrome(_ location:URL?) {
        guard let location else{return}
        let options=NSWorkspace.OpenConfiguration()
        options.arguments=["--restore-last-session"]
        NSWorkspace.shared.openApplication(at:location,configuration:options){_,_ in}
    }
    @objc func appRouting(){
        guard confirmAction("Включить системный прокси macOS?",
            "Сохраните список рабочих сайтов. Router запустит отдельный фоновый процесс и попросит macOS настроить HTTP и HTTPS для Wi-Fi и Ethernet. Программы, учитывающие системный прокси, также увидят эти настройки. Сохраните формы и загрузки в Chrome. При переходе Router один раз штатно закроет браузер и снова откроет его с восстановлением вкладок.",
            "Включить") else {return}
        let preflight=Self.routeCommand("preflight")
        guard preflight.code==0 else {settingsNote.stringValue=preflight.output;return}
        do {
            try SystemProxy.startAgent(paths)
            try SystemProxy.transact(paths,restore:false)
            for _ in 0..<30 where !SystemProxy.effective() {Thread.sleep(forTimeInterval:0.1)}
            guard SystemProxy.effective() else {
                try SystemProxy.transact(paths,restore:true)
                throw ProxyFailure("Основная сеть не применила системный прокси. Прежние настройки восстановлены.")
            }
            let chrome=try closeChromeForMigration()
            guard SystemProxy.effective() else {
                reopenChrome(chrome)
                throw ProxyFailure("Основная сеть изменилась. Переход остановлен.")
            }
            let retired=Self.routeCommand("retire")
            if SystemProxy.effective() {reopenChrome(chrome)}
            guard retired.code==0 else {throw ProxyFailure(retired.output)}
            settingsNote.stringValue="Системный режим включён."
        } catch {settingsNote.stringValue=error.localizedDescription}
        routeStatus()
    }
    @objc func restoreRouting(){
        guard confirmAction("Вернуть прежние сетевые настройки?",
            "Маршрутизация рабочих сайтов через локальный прокси прекратится. Все программы снова будут использовать настройки соответствующих служб. Чужие изменения останутся в силе.",
            "Вернуть настройки") else {return}
        do {
            try SystemProxy.transact(paths,restore:true)
            try SystemProxy.stopAgent(paths)
            settingsNote.stringValue="Прежние сетевые настройки восстановлены."
        } catch {settingsNote.stringValue=error.localizedDescription}
        routeStatus()
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
            try SystemProxy.transact(paths,restore:true)
            try SystemProxy.stopAgent(paths)
            return true
        }catch{maintenanceError(error.localizedDescription);return false}
    }
    @objc func uninstallMenu(){
        guard canMaintain(),confirmAction("Удалить Corporate VPN Router?","Прежние сетевые настройки будут восстановлены. Приложение переместится в Корзину, его автозапуск будет удалён. Приватные данные, логин и копии сохранятся.","Удалить"),releaseForMaintenance() else{return}
        let retired=Self.routeCommand("uninstall-owned")
        guard retired.code==0 else{maintenanceError(retired.output);return}
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
        guard confirmAction("Восстановить beta.5?","Для отката потребуется исходный профиль beta.5. После его подтверждения Router вернёт прежние настройки сети и откроет проверенную копию приложения.","Восстановить") else{return}
        let profile=Self.routeCommand("rollback-profile")
        guard profile.code==0 else{maintenanceError(profile.output);return}
        if profile.output.hasPrefix("confirm"){
            NSWorkspace.shared.open(paths.data.appendingPathComponent("Chrome Work Sites.mobileconfig"))
            maintenanceError("Подтвердите сохранённый профиль beta.5 в macOS, затем снова выберите откат.")
            return
        }
        guard releaseForMaintenance() else{return}
        let p=Process()
        p.executableURL=URL(fileURLWithPath:"/bin/sh")
        p.arguments=["-c","while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open -n \"$2\"","router",String(getpid()),u.path]
        do{try p.run();NSApp.terminate(nil)}catch{maintenanceError("Не удалось запустить проверенную копию beta.5.")}
    }
}
