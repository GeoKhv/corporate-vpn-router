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
        let res = ProductPaths().app.appendingPathComponent("Contents/Resources")
#if CVR_SELECTIVE_TUN
        if op == "save" || op == "validate" {
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
            let w=makeWindow("Рабочие сайты",630,575)
            p.list.target=self;p.list.action=#selector(selectSite)
            p.scope.addItems(withTitles:["Только это имя","Имя и все поддомены"])
            p.domain.placeholderString="wiki.company.example"; p.address.placeholderString="Адрес сайта или URL"
            for field in [p.domain,p.address,p.login] {field.widthAnchor.constraint(equalToConstant:320).isActive=true}
            for field in [p.status,p.preview,settingsNote] {field.preferredMaxLayoutWidth=580}
            let row1=NSStackView(views:[p.list,panelButton("Добавить",#selector(newSite)),panelButton("Удалить строку",#selector(removeSite))])
            let row2=NSStackView(views:[p.domain,p.scope,panelButton("В список",#selector(editSite))])
            let row3=NSStackView(views:[p.address,panelButton("Проверить маршрут",#selector(previewRoute))])
#if CVR_SELECTIVE_TUN
            let routeHeading = "2. Рабочие маршруты для обычных браузеров · приватная проба"
            let row4=NSStackView(views:[panelButton("Проверить состояние",#selector(routeStatus)),panelButton("Сертификаты HTTPS…",#selector(certificates))])
#else
            let routeHeading = "2. Постоянный прокси Chrome"
            let row4=NSStackView(views:[panelButton("Настроить Chrome…",#selector(appRouting)),panelButton("Проверить состояние",#selector(routeStatus))])
#endif
            let row5=NSStackView(views:[panelButton("Импорт профиля…",#selector(importSites)),panelButton("Сохранить список",#selector(savePolicy))])
            attachColumn(makeColumn([NSTextField(labelWithString:"1. Рабочие сайты · добавьте домен или импортируйте профиль"),row1,row2,
                NSTextField(labelWithString:"Доступ до входа · точные имена шлюза и авторизации, через запятую"),p.login,
                row5,row3,p.preview,NSTextField(labelWithString:routeHeading),row4,p.status,settingsNote]),to:w)
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
        settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
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
        guard engine == nil else { settingsNote.stringValue = "Сначала отключите рабочий туннель."; return }
        if selective.process != nil { selective.stop() }
        else if selective.helperAvailability.needsInstallation { installRouteHelper() }
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
