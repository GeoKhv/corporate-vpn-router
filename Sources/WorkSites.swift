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
        if op=="status" && result.code==0 && result.output.hasPrefix("Приложение") {
            let key="ProxySettings" as CFString,id="com.google.Chrome" as CFString
            CFPreferencesAppSynchronize(id)
            let actual=CFPreferencesCopyAppValue(key,id) as? NSDictionary
            let data=ProductPaths().data.appendingPathComponent("active-proxy.json")
            let expected=(try? Data(contentsOf:data)).flatMap{try? JSONSerialization.jsonObject(with:$0) as? NSDictionary}
            guard CFPreferencesAppValueIsForced(key,id), let current=actual, let expected, current.isEqual(expected) else {
                return CommandResult(code:1,output:"macOS ещё не подтверждает обязательную политику Chrome. Проверьте профиль и chrome://policy.")
            }
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
            let row4=NSStackView(views:[panelButton("Приложение…",#selector(appRouting)),panelButton("Расширение…",#selector(extensionRouting)),panelButton("Проверить статус",#selector(routeStatus))])
            let row5=NSStackView(views:[panelButton("Импорт профиля…",#selector(importSites)),panelButton("Сохранить список",#selector(savePolicy))])
            attachColumn(makeColumn([NSTextField(labelWithString:"1. Рабочие сайты · добавьте домен или импортируйте профиль"),row1,row2,
                NSTextField(labelWithString:"Доступ до входа · точные имена шлюза и авторизации, через запятую"),p.login,
                row5,row3,p.preview,NSTextField(labelWithString:"2. Кто управляет маршрутами Chrome?"),row4,p.status,settingsNote]),to:w)
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
    @objc func routeStatus(){let r=Self.routeCommand("status");sitesPanel.status.stringValue=r.output.trimmingCharacters(in:.whitespacesAndNewlines)
        if r.code==0 && r.output.hasPrefix("Приложение"){sitesPanel.status.stringValue += ". В обычном Chrome откройте chrome://policy → обновите политики. До проверки ProxySettings не отключайте прежнее расширение."}}
    func confirmAction(_ title:String,_ msg:String,_ yes:String)->Bool{let a=NSAlert();a.messageText=title;a.informativeText=msg;a.addButton(withTitle:yes);a.addButton(withTitle:"Отмена");return a.runModal() == .alertFirstButtonReturn}
    func submitDraft(_ op:String){
        guard engine==nil else{settingsNote.stringValue="Сначала отключите туннель.";return}
        if !sitesPanel.domain.stringValue.isEmpty && !editSite(){return}
        readLogin()
        let temp=paths.data.appendingPathComponent("draft-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        do{try JSONFile.write(sitesPanel.draft,to:temp)}catch{settingsNote.stringValue="Не удалось сохранить черновик.";return}
        let r=Self.routeCommand(op,[temp.path]),message=r.output.trimmingCharacters(in:.whitespacesAndNewlines)
        if op=="prepare" && r.code==0 {
            let ok=NSWorkspace.shared.open(URL(fileURLWithPath:message))
            settingsNote.stringValue=ok ? "Подтвердите профиль Router в Системных настройках → Основные → Управление устройством. Затем нажмите «Проверить статус».":"macOS не открыла профиль."
        }else{settingsNote.stringValue=message}
        routeStatus()
    }
    @objc func appRouting(){
        guard confirmAction("Передать рабочие маршруты приложению?","Только Chrome: обязательный профиль заменит управление расширения во всех профилях этого пользователя. Настройки расширения сохраняются. Остальные сайты идут обычным путём. Ошибка PAC может заблокировать весь Chrome. macOS запросит установку.","Подготовить профиль") else{return};submitDraft("prepare")
    }
    @objc func extensionRouting(){
        guard confirmAction("Вернуть управление расширению?","Удаляется только профиль Router. Проверьте расширение и Work → SOCKS5, прежде чем открывать рабочие сайты: без контроллера Chrome может пойти напрямую.","Вернуть управление") else{return}
        let r=Self.routeCommand("extension");settingsNote.stringValue=r.output;routeStatus()
    }
    @objc func savePolicy(){if FileManager.default.fileExists(atPath:paths.data.appendingPathComponent("router-profile-receipt.json").path){appRouting()}else{submitDraft("save")}}
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
        if FileManager.default.fileExists(atPath:paths.data.appendingPathComponent("router-profile-receipt.json").path){
            let result=Self.routeCommand("extension")
            if result.code != 0 {maintenanceError(result.output);return false}
        };return true
    }
    @objc func uninstallMenu(){
        guard canMaintain(),confirmAction("Удалить Corporate VPN Router?","Профиль Chrome будет снят. Настройте расширение перед открытием рабочих сайтов. Приложение переместится в Корзину, его автозапуск будет удалён. Приватные данные, логин и копии сохранятся.","Удалить"),releaseForMaintenance() else{return}
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
        guard let u=BetaInstall.beta4(paths) else{maintenanceError("Резервной копии с подписью опубликованной beta.4 нет. Используйте архив beta.4 со страницы релизов.");return}
        guard confirmAction("Восстановить beta.4?","Будет снят профиль Router для Chrome. В beta.4 маршрутизацией управляет сохранённое расширение; проверьте его перед открытием рабочих сайтов.","Восстановить"),releaseForMaintenance() else{return}
        // beta.4 installs its verified copy synchronously. Leave the menu lock
        // only when the new app is on disk; open after this instance exits.
        let r=command(u.appendingPathComponent("Contents/MacOS/CorporateVPNRouter").path,["--install"],timeout:90)
        guard r.code==0 else{maintenanceError("Не удалось восстановить приложение.");return}
        let p=Process();p.executableURL=URL(fileURLWithPath:"/bin/sh")
        p.arguments=["-c","while kill -0 \"$1\" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open \"$2\"","router",String(getpid()),paths.app.path]
        do{try p.run();NSApp.terminate(nil)}catch{maintenanceError("beta.4 установлена. Завершите Router и откройте его ещё раз.")}
    }
}
