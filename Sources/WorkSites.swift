import AppKit

enum TCPPorts: Codable, Equatable {
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
struct WorkSite: Codable, Equatable { var domain: String; var scope: String; var tcp: TCPPorts?; var alias: String? }
struct SharedTCPRule: Decodable {
    let kind: String
    let domain: String
    let ports: [Int]
    let shortName: Bool
}
struct WorkProfile: Codable, Equatable {
    var version = 1
    var sites: [WorkSite] = []
    var beforeLogin: [String] = []
    var searchDomains: [String]?
    var ports = [443]
    mutating func mergeExactRule(_ rule: SharedTCPRule) throws {
        guard rule.kind == "exact-tcp-rule", Configuration.validHost(rule.domain), rule.domain.contains("."),
              !rule.ports.isEmpty, rule.ports.count <= 32, rule.ports.allSatisfy({ (1...65535).contains($0) }),
              !beforeLogin.contains(rule.domain) else { throw RouterError.invalidConfiguration }
        let index = sites.firstIndex { $0.domain == rule.domain }
        if let index, sites[index].scope != "exact" {
            throw ProxyFailure("Для этого имени уже задано правило с поддоменами. Существующий охват сохранён.")
        }
        let inherited = sites.filter { $0.domain == rule.domain ||
            ($0.scope == "tree" && rule.domain.hasSuffix("." + $0.domain)) }.max { $0.domain.count < $1.domain.count }
        var row = WorkSite(domain:rule.domain, scope:"exact")
        if let index { row = sites[index] }
        let base = inherited.map { $0.tcp ?? .selected(ports) } ?? .selected([])
        switch base {
        case .any: row.tcp = .any
        case .selected(let existing):
            let merged = Array(Set(existing + rule.ports)).sorted()
            guard merged.count <= 32 else { throw ProxyFailure("В точном правиле получилось больше 32 TCP-портов.") }
            row.tcp = .selected(merged)
        }
        if rule.shortName {
            let alias = String(rule.domain.prefix(while: { $0 != "." }))
            guard !sites.contains(where: { $0.domain != rule.domain && $0.alias == alias }) else {
                throw ProxyFailure("Это короткое имя уже привязано к другому серверу.")
            }
            row.alias = alias
        }
        if let index { sites[index] = row } else {
            guard sites.count < 256 else { throw RouterError.invalidConfiguration }
            sites.append(row)
        }
        version = 2
    }

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
struct PortableRules: Codable {
    let kind:String
    let sites:[WorkSite]
    let ports:[Int]
    let searchDomains:[String]
}
struct PendingWork: Codable {
    let base: WorkProfile
    let profile: WorkProfile
}

final class SitesPanel: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    var draft = WorkProfile()
    var base = WorkProfile()
    var history = [WorkProfile]()
    var editing: Int?
    var applying = false
    let table = NSTableView()
    let scope = NSPopUpButton(), domain = NSTextField(), login = NSTextField(), suffixes = NSTextField()
    let address = NSTextView(), source = NSTextField(labelWithString:"")
    let ports = NSTextField(), short = NSButton(checkboxWithTitle:"Короткое имя",target:nil,action:nil)
    var gatewaySuffixes = [String]()
    let commit = NSButton()
    var requestID = UUID()
    let status = NSTextField(wrappingLabelWithString:""), preview = NSTextField(wrappingLabelWithString:"")
    func numberOfRows(in tableView: NSTableView) -> Int { draft.sites.count }
    func tableView(_ tableView: NSTableView, objectValueFor column: NSTableColumn?, row: Int) -> Any? {
        let site = draft.sites[row]
        switch column?.identifier.rawValue {
        case "host": return site.domain
        case "scope": return site.scope == "tree" ? "С поддоменами" : "Точное имя"
        case "ports": return (site.tcp ?? .selected(draft.ports)).label
        default: return site.alias ?? "—"
        }
    }
}

extension WorkProfile {
    func matching(_ host: String) -> WorkSite? {
        guard !beforeLogin.contains(host) else { return nil }
        return sites.filter { $0.domain == host || ($0.scope == "tree" && host.hasSuffix("." + $0.domain)) }
            .max { $0.domain.count < $1.domain.count }
    }
    func covers(_ row:WorkSite) -> WorkSite? {
        guard let match=matching(row.domain), row.scope=="exact" || match.scope=="tree",
              row.alias == nil || (row.domain==match.domain && row.alias==match.alias) else { return nil }
        switch (match.tcp ?? .selected(ports),row.tcp ?? .selected(ports)) {
        case (.any,_): return match
        case (.selected(let old),.selected(let new)): return Set(new).isSubset(of:old) ? match : nil
        default: return nil
        }
    }
}
extension BetaMenu {
    static func routeCommand(_ op: String, _ args: [String] = [], resources res: URL = ProductPaths().app.appendingPathComponent("Contents/Resources")) -> CommandResult {
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
    var draftURL: URL { paths.data.appendingPathComponent("work-sites-draft.json") }
    var pendingURL: URL { paths.data.appendingPathComponent("work-sites-pending.json") }
    func updateSearchSource() {
        let p=sitesPanel
        p.source.stringValue = p.gatewaySuffixes.isEmpty ? "Шлюз не передал суффиксы поиска" : "Из текущего сеанса: " + p.gatewaySuffixes.joined(separator:", ")
    }
    func scroll(_ view:NSView, width:CGFloat, height:CGFloat) -> NSScrollView {
        let scroll=NSScrollView()
        scroll.hasVerticalScroller=true; scroll.borderType = .bezelBorder
        scroll.documentView=view
        scroll.widthAnchor.constraint(equalToConstant:width).isActive=true
        scroll.heightAnchor.constraint(equalToConstant:height).isActive=true
        return scroll
    }
    @objc func settings() {
        let p=sitesPanel
        if settingsWindow == nil {
            let w=makeWindow("Рабочие ресурсы",730,685)
            w.isRestorable=false
            for (id,title,width) in [("host","Адрес",285),("scope","Охват",125),("ports","TCP",95),("alias","Алиас",135)] {
                let column=NSTableColumn(identifier:NSUserInterfaceItemIdentifier(id))
                column.title=title; column.width=CGFloat(width); p.table.addTableColumn(column)
            }
            p.table.delegate=p; p.table.dataSource=p
            p.scope.addItems(withTitles:["Точное имя","С поддоменами"])
            p.domain.placeholderString="Полное имя"; p.ports.placeholderString="443"
            p.domain.widthAnchor.constraint(equalToConstant:240).isActive=true
            p.ports.widthAnchor.constraint(equalToConstant:90).isActive=true
            p.commit.target=self; p.commit.action=#selector(editSite)
            let form=NSStackView(views:[p.domain,p.scope,p.ports,p.short,p.commit])
            p.address.isRichText=false; p.address.isAutomaticQuoteSubstitutionEnabled=false
            p.address.isAutomaticDashSubstitutionEnabled=false
            p.address.textContainer?.widthTracksTextView=true
            let pasteRow=NSStackView(views:[panelButton("Разобрать адреса…",#selector(parseAddresses)),panelButton("Проверить подключение",#selector(previewRoute))])
            let actions=NSStackView(views:[panelButton("Изменить",#selector(selectSite)),panelButton("Удалить",#selector(removeSite)),panelButton("Отменить правку",#selector(cancelDraftEdit)),panelButton("Импорт…",#selector(importSites)),panelButton("Экспорт…",#selector(exportSites))])
            p.suffixes.placeholderString="Дополнительные суффиксы поиска через запятую"
            p.login.placeholderString="Точные имена для доступа до входа"
            for field in [p.suffixes,p.login] { field.widthAnchor.constraint(equalToConstant:460).isActive=true }
            for field in [p.status,p.preview,settingsNote] {field.preferredMaxLayoutWidth=665}
            let save=NSStackView(views:[panelButton("Применить правила",#selector(savePolicy)),panelButton("Предыдущие правила",#selector(undoSites)),panelButton("Сертификаты…",#selector(certificates))])
            attachColumn(makeColumn([NSTextField(labelWithString:"Рабочие правила"),scroll(p.table,width:675,height:118),actions,form,
                NSTextField(labelWithString:"Вставьте ссылки или имена, по одному на строку"),scroll(p.address,width:675,height:50),pasteRow,p.preview,
                p.source,NSStackView(views:[NSTextField(labelWithString:"Свои суффиксы"),p.suffixes]),NSStackView(views:[NSTextField(labelWithString:"До входа"),p.login]),save,settingsNote,p.status],spacing:7),to:w)
            settingsWindow=w
            p.base=storedWork() ?? WorkProfile(); p.draft=p.base
            if let saved=try? JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:pendingURL)), saved.base==p.base { p.draft=saved.profile }
            if let saved=try? JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:draftURL)), saved.base==p.base {p.draft=saved.profile}
            loadDraft();updateSearchSource()
        } else if p.base != storedWork(), p.draft == p.base, p.editing == nil, p.domain.stringValue.isEmpty {
            p.base=storedWork() ?? WorkProfile(); p.draft=p.base; loadDraft()
        }
        routeStatus()
        NSApp.activate(ignoringOtherApps:true);settingsWindow?.makeKeyAndOrderFront(nil)
    }
    func loadDraft(_ selected:Int = -1) {
        let p=sitesPanel
        p.table.reloadData()
        if p.draft.sites.indices.contains(selected) { p.table.selectRowIndexes(IndexSet(integer:selected),byExtendingSelection:false) }
        p.login.stringValue=p.draft.beforeLogin.joined(separator:", ")
        p.suffixes.stringValue=(p.draft.searchDomains ?? []).joined(separator:", ")
        newSite()
        settingsNote.stringValue=p.base==p.draft ? "Сохранённые правила" : "Черновик • есть неприменённые изменения"
    }
    @objc func selectSite() {
        let p=sitesPanel,i=p.table.selectedRow
        guard p.draft.sites.indices.contains(i) else {settingsNote.stringValue="Выберите правило в списке.";return}
        let row=p.draft.sites[i]
        p.editing=i;p.domain.stringValue=row.domain;p.scope.selectItem(at:row.scope=="tree" ? 1:0)
        p.ports.stringValue=(row.tcp ?? .selected(p.draft.ports)).label;p.short.state=row.alias==nil ? .off:.on
        p.commit.title="Изменить"; settingsNote.stringValue="Редактируется " + row.domain
    }
    @objc func newSite(){let p=sitesPanel;p.editing=nil;p.domain.stringValue="";p.ports.stringValue=TCPPorts.selected(p.draft.ports).label;p.scope.selectItem(at:0);p.short.state = .off;p.commit.title="Добавить"}
    func readLogin(){
        let p=sitesPanel
        func names(_ text:String)->[String]{text.lowercased().split(whereSeparator:{$0=="," || $0.isWhitespace}).map(String.init)}
        p.draft.beforeLogin=names(p.login.stringValue)
        let suffixes=names(p.suffixes.stringValue);p.draft.searchDomains=suffixes.isEmpty ? nil:suffixes
    }
    func changedDraft(_ old:WorkProfile,_ selected:Int = -1) {
        let p=sitesPanel
        if old != p.draft { p.history.append(old) }
        loadDraft(selected)
        persistDraft()
    }
    func persistDraft(){
        let p=sitesPanel
        do {try JSONFile.write(PendingWork(base:p.base,profile:p.draft),to:draftURL)}
        catch {settingsNote.stringValue="Черновик в памяти. Записать его на диск не удалось."}
    }
    @objc func cancelDraftEdit(){
        let p=sitesPanel
        if p.editing != nil || !p.domain.stringValue.isEmpty {newSite();return}
        if let previous=p.history.popLast(){p.draft=previous;loadDraft();persistDraft()}
    }
    @objc func removeSite(){
        let p=sitesPanel,i=p.table.selectedRow
        guard p.draft.sites.indices.contains(i) else{return}
        readLogin();let old=p.draft;p.draft.sites.remove(at:i);changedDraft(old)
    }
    @discardableResult @objc func editSite()->Bool {
        let p=sitesPanel,h=p.domain.stringValue.trimmingCharacters(in:.whitespacesAndNewlines).lowercased()
        guard Configuration.validHost(h), h.contains(".") else{settingsNote.stringValue="Введите полное DNS-имя. Для маски используйте разбор адресов.";return false}
        let raw=p.ports.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
        let tokens=raw.split(separator:",",omittingEmptySubsequences:false)
        let ports=tokens.compactMap { Int($0.trimmingCharacters(in:.whitespaces)) }
        guard raw=="*" || (ports.count==tokens.count && (1...32).contains(ports.count) && ports.allSatisfy({(1...65535).contains($0)})) else {settingsNote.stringValue="Укажите TCP-порты через запятую или *.";return false}
        readLogin()
        var row=WorkSite(domain:h,scope:p.scope.indexOfSelectedItem==1 ? "tree":"exact",tcp:raw=="*" ? .any:.selected(Array(Set(ports)).sorted()),alias:p.short.state == .on ? h.components(separatedBy:".").first:nil)
        let old=p.draft
        if p.editing==nil, let cover=old.covers(row) {
            p.address.string=h+":" + String(ports.first ?? 443)
            settingsNote.stringValue="Уже разрешено правилом "+cover.domain+". Можно проверить подключение.";newSite();return true
        }
        guard !old.beforeLogin.contains(h), !old.sites.enumerated().contains(where:{$0.offset != p.editing && ($0.element.domain==h || (row.alias != nil && row.alias==$0.element.alias))}) else {settingsNote.stringValue="Имя или алиас уже используется. Выберите правило и нажмите «Изменить».";return false}
        if let i=p.editing {
            if old.sites[i].tcp==nil && row.tcp == .selected(old.ports.sorted()) { row.tcp=nil }
            p.draft.sites[i]=row
        } else { p.draft.sites.append(row) }
        p.draft.version=2;changedDraft(old);return true
    }
    @objc func exportSites(){
        readLogin();let panel=NSSavePanel();panel.nameFieldStringValue="work-rules.json"
        guard panel.runModal() == .OK,let url=panel.url else{return}
        do {try JSONFile.write(PortableRules(kind:"work-rules",sites:sitesPanel.draft.sites,ports:sitesPanel.draft.ports,searchDomains:sitesPanel.draft.searchDomains ?? []),to:url)} catch {settingsNote.stringValue="Не удалось записать файл."}
    }
    @objc func importSites(){let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        guard panel.runModal() == .OK, let u=panel.url else{return}
        do{let data=try Data(contentsOf:u);guard data.count<=131072 else{throw RouterError.invalidConfiguration}
            readLogin()
            let old=sitesPanel.draft
            if let portable=try? JSONDecoder().decode(PortableRules.self,from:data), portable.kind=="work-rules" {
                sitesPanel.draft=WorkProfile(version:2,sites:portable.sites,beforeLogin:old.beforeLogin,searchDomains:portable.searchDomains.isEmpty ? nil:portable.searchDomains,ports:portable.ports)
                changedDraft(old);return
            }
            if let rule = try? JSONDecoder().decode(SharedTCPRule.self, from:data) {
                readLogin()
                try sitesPanel.draft.mergeExactRule(rule)
                changedDraft(old,sitesPanel.draft.sites.firstIndex { $0.domain == rule.domain } ?? 0)
                settingsNote.stringValue="В черновике изменено одно точное правило. Проверьте адрес и порты, затем сохраните список."
                return
            }
            let draft=try JSONDecoder().decode(WorkProfile.self,from:data); guard [1,2].contains(draft.version) && !draft.sites.isEmpty && draft.sites.count<=256 else{throw RouterError.invalidConfiguration}
            sitesPanel.draft=draft;changedDraft(old);settingsNote.stringValue="Импортирован черновик. Проверьте область доменов и адреса до входа."
        }catch{settingsNote.stringValue="Не удалось прочитать профиль рабочих сайтов."}
    }
    @objc func undoSites() {
        let previous = paths.data.appendingPathComponent("previous-work-sites.json")
        guard let data = try? Data(contentsOf:previous), let profile = try? JSONDecoder().decode(WorkProfile.self,from:data) else {
            settingsNote.stringValue="Предыдущая версия правил отсутствует.";return
        }
        let old=sitesPanel.draft;sitesPanel.draft=profile;changedDraft(old);settingsNote.stringValue="Предыдущие правила загружены в черновик. Проверьте и сохраните."
    }
    func analyzeInput(_ data:Data,preview:Bool,completion:@escaping ([String:Any])->Void) {
        let res=resources
        DispatchQueue.global(qos:.userInitiated).async {
            let proc=Process(),input=Pipe(),output=Pipe()
            proc.executableURL=res.appendingPathComponent("Runtime/bin/python3.13")
            proc.arguments=["-I","-B",res.appendingPathComponent("Engine/Selective/analyze.py").path] + (preview ? ["--preview"]:[])
            proc.standardInput=input;proc.standardOutput=output;proc.standardError=FileHandle.nullDevice
            var result:[String:Any]=[:]
            if (try? proc.run()) != nil {
                try? input.fileHandleForWriting.write(contentsOf:data);try? input.fileHandleForWriting.close()
                let bytes=output.fileHandleForReading.readDataToEndOfFile();proc.waitUntilExit()
                result=(try? JSONSerialization.jsonObject(with:bytes) as? [String:Any]) ?? [:]
            }
            DispatchQueue.main.async {completion(result)}
        }
    }
    @objc func previewRoute(){
        let p=sitesPanel,text=p.address.string.trimmingCharacters(in:.whitespacesAndNewlines),id=UUID()
        guard text.utf8.count<=2048, !text.contains("\n") else {p.preview.stringValue="Для проверки выберите один адрес.";return}
        p.requestID=id;p.preview.stringValue="Проверяем соединение…"
        analyzeInput(Data(text.utf8),preview:false){ result in
            guard id==p.requestID,text==p.address.string.trimmingCharacters(in:.whitespacesAndNewlines) else{return}
            p.preview.stringValue=result["message"] as? String ?? "Проверка не завершена."
        }
    }
    @objc func parseAddresses(){
        let p=sitesPanel,text=p.address.string,id=UUID()
        readLogin()
        guard !text.isEmpty,text.utf8.count<=32768 else {p.preview.stringValue="Вставьте до 64 адресов (32 КБ).";return}
        let request:[String:Any]=["text":text,"suffixes":Array(Set(p.gatewaySuffixes+(p.draft.searchDomains ?? []))).sorted()]
        guard let data=try? JSONSerialization.data(withJSONObject:request) else{return}
        p.requestID=id;p.preview.stringValue="Разбираем адреса…"
        analyzeInput(data,preview:true){ result in
            guard id==p.requestID,text==p.address.string else{return}
            guard let rows=result["rows"] as? [[String:Any]],!rows.isEmpty else {p.preview.stringValue=result["message"] as? String ?? "Нет адресов.";return}
            self.offerRows(rows)
        }
    }
    func offerRows(_ rows:[[String:Any]]) {
        let p=sitesPanel,alert=NSAlert()
        var controls=[NSView](), choices=[(NSButton,NSPopUpButton,[WorkSite])]()
        for item in rows {
            guard let host=item["host"] as? String,let port=item["port"] as? Int else {
                controls.append(NSTextField(labelWithString:item["error"] as? String ?? "Неизвестный формат"));continue
            }
            let hosts=item["choices"] as? [String] ?? [host]
            let popup=NSPopUpButton(); popup.addItems(withTitles:hosts)
            if hosts.count>1 { popup.insertItem(withTitle:"Выберите полное имя",at:0);popup.selectItem(at:0) }
            let tree=item["tree"] as? Bool == true
            let rules=hosts.map {WorkSite(domain:$0,scope:tree ? "tree":"exact",tcp:.selected([port]),alias:item["alias"] as? String)}
            let covered=hosts.count==1 ? p.draft.covers(rules[0]):nil
            let scheme=item["scheme"] as? String ?? "tcp"
            var label="\(scheme.uppercased()) · \(port)" + (item["assumed"] as? Bool == true ? " по умолчанию":"")
            if tree { label += " · домен и поддомены" }
            if let alias=item["alias"] as? String { label += " · алиас "+alias }
            if let covered { label += " · разрешено: "+covered.domain }
            let check=NSButton(checkboxWithTitle:label,target:nil,action:nil)
            check.state=covered==nil ? .on:.off;check.isEnabled=covered==nil
            controls.append(NSStackView(views:[popup,check]));choices.append((check,popup,rules))
        }
        let stack=makeColumn(controls)
        stack.frame=NSRect(origin:.zero,size:stack.fittingSize)
        let scroll=NSScrollView(frame:NSRect(x:0,y:0,width:min(800,max(510,stack.fittingSize.width+22)),height:min(340,stack.fittingSize.height+12)))
        scroll.hasVerticalScroller=true;scroll.hasHorizontalScroller=true;scroll.documentView=stack
        alert.accessoryView=scroll;alert.messageText="Распознанные адреса"
        alert.informativeText="Выберите новые назначения. Для смены портов или охвата существующего правила используйте «Изменить»."
        alert.addButton(withTitle:"В черновик");alert.addButton(withTitle:"Отмена")
        p.preview.stringValue="Разобрано строк: \(rows.count). Доступ можно проверить отдельно."
        guard alert.runModal() == .alertFirstButtonReturn else{return}
        let old=p.draft
        var next=old
        do {
            for (check,popup,rules) in choices where check.state == .on {
                let idx=popup.indexOfSelectedItem-(rules.count>1 ? 1:0)
                guard rules.indices.contains(idx) else{throw ProxyFailure("Выберите полное имя из найденных.")}
                var row=rules[idx]
                if next.covers(row) != nil { continue }
                guard !next.beforeLogin.contains(row.domain) else{throw ProxyFailure("Имя исключено для доступа до входа.")}
                if let existing=next.sites.first(where:{$0.domain==row.domain}) {
                    // An alias selected in the preview can be attached without changing grants.
                    guard row.alias != nil,existing.alias==nil, next.covers(WorkSite(domain:row.domain,scope:row.scope,tcp:row.tcp)) != nil else {throw ProxyFailure("Для "+row.domain+" уже есть правило. Измените его явно.")}
                    row=existing;row.alias=rules[idx].alias
                    next.sites.removeAll{$0.domain==row.domain}
                } else if let parent=next.matching(row.domain) {
                    // A more specific row must retain inherited ports.
                    switch parent.tcp ?? .selected(next.ports) {
                    case .any:row.tcp = .any
                    case .selected(let ports):if case .selected(let added)=row.tcp {row.tcp = .selected(Array(Set(ports+added)).sorted())}
                    }
                }
                guard row.alias==nil || !next.sites.contains(where:{$0.alias==row.alias}) else{throw ProxyFailure("Алиас уже занят.")}
                next.sites.append(row);next.version=2
            }
            if next != old {p.draft=next;changedDraft(old)}
        } catch {settingsNote.stringValue=error.localizedDescription}
    }
    @objc func routeStatus(){
#if CVR_SELECTIVE_TUN
        sitesPanel.status.stringValue = selective.helperAvailability.explanation + " · " + selective.message
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

#else
        if BrowserRouter.effective() && !activated {settingsNote.stringValue="Сначала нажмите «Настроить Chrome…» для проверки маршрута в браузере.";return}
#endif
        guard sitesPanel.domain.stringValue.isEmpty else { settingsNote.stringValue="Завершите ввод кнопкой «Добавить» или «Изменить» либо отмените правку.";return }
        readLogin()
        persistDraft()
        let temp=paths.data.appendingPathComponent("draft-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        do{try JSONFile.write(sitesPanel.draft,to:temp)}catch{settingsNote.stringValue="Не удалось сохранить черновик.";return}
        #if CVR_SELECTIVE_TUN && CVR_UPDATES
        let validation=Self.routeCommand("check-draft",[temp.path],resources:resources)
        guard validation.code==0 else { settingsNote.stringValue=validation.output;return }
        let profile=sitesPanel.draft
        guard !sitesPanel.applying,sitesPanel.base==storedWork() else {settingsNote.stringValue="Список изменён или уже применяется. Сохраните черновик через экспорт.";return}
        do {try JSONFile.write(PendingWork(base:sitesPanel.base,profile:profile),to:pendingURL)} catch {settingsNote.stringValue="Не удалось записать черновик.";return}
        guard engine==nil && !selective.busy else {settingsNote.stringValue="Черновик сохранён до следующего подключения. Текущий сеанс продолжается.";return}
        applyPending(connectAfter:false)
        #else
        settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
        #endif
        routeStatus()
    }
    #if CVR_SELECTIVE_TUN && CVR_UPDATES
    func applyPending(connectAfter:Bool) {
        let p=sitesPanel
        guard !p.applying else{return}
        func report(_ text:String){settingsNote.stringValue=text;if connectAfter {connectionNotice=text;presentConnection()}}
        guard let saved=try? JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:pendingURL)),saved.base==storedWork() else {report("Отложенный профиль расходится с сохранённым. Проверьте рабочие правила.");return}
        let profile=saved.profile
        let temp=paths.data.appendingPathComponent("apply-"+UUID().uuidString)
        do {try JSONFile.write(profile,to:temp)} catch {report("Ошибка чтения черновика.");return}
        let validation=Self.routeCommand("check-draft",[temp.path],resources:resources)
        guard validation.code==0 else{try? FileManager.default.removeItem(at:temp);report(validation.output);return}
        let status=SelectiveRouter.helperReply(resources:resources)
        let desktop=(status?["approvedRDPHost"] as? String).flatMap { profile.work($0) ? $0:nil } ?? ""
        guard let enrollment=try? profile.enrollment(desktop:desktop),let expected=try? JSONSerialization.jsonObject(with:enrollment) as? [String:Any] else {try? FileManager.default.removeItem(at:temp);report("Не удалось подготовить разрешения.");return}
        p.applying=true
        func finish(_ success:Bool){
            defer {try? FileManager.default.removeItem(at:temp)}
            p.applying=false
            guard success else{report("Утверждение не завершено. Черновик сохранён.");return}
            let result=Self.routeCommand("save",[temp.path],resources:resources)
            guard result.code==0 else{report(result.output);return}
            try? FileManager.default.removeItem(at:pendingURL)
            p.base=profile
            if p.draft==profile {try? FileManager.default.removeItem(at:draftURL)}
            report(result.output)
            if connectAfter {connect()}
        }
        if let old=status?["tcpRules"] as? NSArray, old.isEqual(expected["rules"]) {finish(true)}
        else {selective.manageHelper(resources:resources,enrollment:enrollment,reconfigure:true,completion:finish)}
    }
    #endif
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

#if CVR_SELECTIVE_TUN && CVR_UPDATES
extension BetaMenu {
    // Keep the receipt independent of app version so later updates respect manual edits.
    func applyBundledRuleIfNeeded(connectAfterward: Bool) -> Bool {
        let resource = resources.appendingPathComponent("BundledTCPRule.json")
        let receipt = paths.data.appendingPathComponent("bundled-tcp-rule-v1.applied")
        let fm = FileManager.default
        guard !applyingBundledRule, engine == nil, !selective.busy,
              selective.helperAvailability.canConnect || selective.helperAvailability.needsInstallation,
              !fm.fileExists(atPath:receipt.path), fm.fileExists(atPath:resource.path),
              fm.fileExists(atPath:workURL.path) else { return false }
        do {
            let original = try Data(contentsOf:workURL)
            let profile = try JSONDecoder().decode(WorkProfile.self,from:original)
            let rule = try JSONDecoder().decode(SharedTCPRule.self,from:Data(contentsOf:resource))
            // Only a Mac whose existing work profile covers this destination is eligible.
            guard profile.work(rule.domain) else { return false }
            var candidate = profile
            // A conflicting user-defined tree or alias takes precedence over this preset.
            do { try candidate.mergeExactRule(rule) } catch {
                connectionNotice = "Сохранены ваши правила. " + error.localizedDescription
                return false
            }
            let status = SelectiveRouter.helperReply(resources:resources)
            let desktop = status?["approvedRDPHost"] as? String ??
                Provisioning.defaultDesktop(resources:resources,paths:paths,profile:profile) ?? ""
            let enrollment = try candidate.enrollment(desktop:desktop)
            let expected = try JSONSerialization.jsonObject(with:enrollment) as? [String:Any]
            let authorized = selective.helperAvailability.canConnect &&
                (status?["tcpRules"] as? NSArray)?.isEqual(expected?["rules"]) == true
            if authorized && candidate == profile {
                try Data("applied\n".utf8).write(to:receipt, options:.atomic)
                return false
            }
            let pending = paths.data.appendingPathComponent("pending-" + UUID().uuidString)
            try JSONFile.write(candidate,to:pending)
            let validation = Self.routeCommand("check-draft",[pending.path],resources:resources)
            guard validation.code == 0 else {
                try? fm.removeItem(at:pending)
                throw ProxyFailure(validation.output)
            }
            applyingBundledRule = true
            if connectAfterward { connectionPhase = .installingHelper; presentConnection() }
            func finish(_ success: Bool) {
                defer { try? fm.removeItem(at:pending) }
                let resume = connectAfterward && self.connectionPhase == .installingHelper
                self.applyingBundledRule = false
                do {
                    guard success else { throw ProxyFailure(self.selective.message) }
                    guard try Data(contentsOf:self.workURL) == original else {
                        throw ProxyFailure("Список рабочих сайтов изменился во время подтверждения. Повторите подключение с актуальным списком.")
                    }
                    let confirmed = SelectiveRouter.helperReply(resources:self.resources)
                    guard (confirmed?["tcpRules"] as? NSArray)?.isEqual(expected?["rules"]) == true else {
                        throw ProxyFailure("Помощник ещё не подтвердил рабочее правило. Повторите подключение.")
                    }
                    if candidate != profile {
                        let result = Self.routeCommand("save",[pending.path],resources:self.resources)
                        guard result.code == 0 else { throw ProxyFailure(result.output) }
                    }
                    try Data("applied\n".utf8).write(to:receipt, options:.atomic)
                    if resume {
                        self.connectionPhase = .checkingHelper
                        self.continueConnection()
                    }
                } catch {
                    if resume { self.failConnection(error.localizedDescription,code:"BUNDLED_RULE_PENDING") }
                    else { self.connectionNotice = error.localizedDescription }
                }
                self.presentConnection()
            }
            if authorized { finish(true) }
            else { selective.manageHelper(resources:resources,enrollment:enrollment,reconfigure:true,completion:finish) }
            return true
        } catch {
            if connectAfterward { failConnection(error.localizedDescription,code:"BUNDLED_RULE_PENDING") }
            else { connectionNotice = error.localizedDescription; presentConnection() }
            return true
        }
    }
}
#endif
