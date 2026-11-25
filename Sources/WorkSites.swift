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
        return try JSONSerialization.data(withJSONObject:["domains":sites.map{$0.domain}, "desktop":desktop, "rules":rules, "allowDNSRepair":true, "allowCheckPointStart":true])
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
    // Written before the controller's atomic profile replacement. Either side of a
    // process interruption can load the draft matching the profile actually on disk.
    var nextBase: WorkProfile? = nil
    var nextDraft: WorkProfile? = nil

    func draft(for active: WorkProfile) -> WorkProfile? {
        if base == active { return profile }
        return nextBase == active ? nextDraft : nil
    }
}

enum AccessPurpose {
    static let named:[(String,Int)]=[("Веб",443),("Веб",80),("SSH",22),("Kubernetes",6443),("Postgres",5432),("Redis",6379),("Kafka",9092)]
    // Purpose shown to the user for one TCP port; the scheme only refines nonstandard ports.
    static func label(port:Int,scheme:String="") -> String {
        if port==6443 { return "Kubernetes · 6443" }
        switch scheme {
        case "https","http": return "Веб · \(port)"
        case "ssh": return "SSH · \(port)"
        case "postgresql": return "Postgres · \(port)"
        case "redis": return "Redis · \(port)"
        default: break
        }
        if let known=named.first(where:{$0.1==port}) { return known.0+" · \(port)" }
        return "TCP · \(port)"
    }
    static func label(_ tcp:TCPPorts?,defaultPorts ports:[Int]) -> String {
        switch tcp ?? .selected(ports) {
        case .any: return "Любой TCP"
        case .selected(let list): return list.sorted().map{label(port:$0).replacingOccurrences(of:" · ",with:" ")}.joined(separator:", ")
        }
    }
}
final class PreviewItem {
    let host:String, choices:[String], tree:Bool, alias:String?, scheme:String, port:Int
    let check=NSButton(checkboxWithTitle:"",target:nil,action:nil)
    let hostPopup=NSPopUpButton(), purpose=NSPopUpButton(), aliasCheck=NSButton(checkboxWithTitle:"",target:nil,action:nil)
    var covered:WorkSite?
    init(host:String,choices:[String],tree:Bool,alias:String?,scheme:String,port:Int) {
        self.host=host;self.choices=choices;self.tree=tree;self.alias=alias;self.scheme=scheme;self.port=port
    }
}

final class MessageLabel: NSTextField {
    override var stringValue:String { didSet { isHidden=stringValue.isEmpty } }
}

final class SitesPanel: NSObject, NSTableViewDataSource, NSTableViewDelegate {
    var draft = WorkProfile()
    var base = WorkProfile()
    var editing: Int?
    var applying = false
    let table = NSTableView()
    let tree = NSButton(checkboxWithTitle:"С поддоменами",target:nil,action:nil), domain = NSTextField(), login = NSTextField(), suffixes = NSTextField()
    let address = NSTextView(), source = NSTextField(labelWithString:"")
    let ports = NSTextField(), short = NSButton(checkboxWithTitle:"Короткое имя",target:nil,action:nil)
    var gatewaySuffixes = [String]()
    let commit = NSButton()
    var requestID = UUID()
    var parsedText: String?
    var items=[PreviewItem]()
    let previewBox=NSStackView(), previewTitle=NSTextField(labelWithString:""), addButton=NSButton()
    let previewList=NSStackView(), previewScroll=NSScrollView()
    var previewHeight:NSLayoutConstraint?
    var filter=""
    let search=NSSearchField(), editBox=NSStackView(), editButton=NSButton(), deleteButton=NSButton()
    let stateLabel=NSTextField(labelWithString:""), saveButton=NSButton(), cancelButton=NSButton()
    let more=NSPopUpButton(frame:.zero,pullsDown:true), advancedToggle=NSButton(), advanced=NSStackView()
    // Draft indexes of the rows currently listed; the search field only narrows the view.
    var rowIndexes:[Int] {
        let query=filter.lowercased()
        return draft.sites.indices.filter { query.isEmpty || draft.sites[$0].domain.contains(query) || (draft.sites[$0].alias ?? "").contains(query) }
    }
    weak var column:NSStackView?
    let status = NSTextField(wrappingLabelWithString:""), preview = MessageLabel(wrappingLabelWithString:"")
    var noteObserver:NSKeyValueObservation?
    func numberOfRows(in tableView: NSTableView) -> Int { rowIndexes.count }
    func tableView(_ tableView: NSTableView, objectValueFor column: NSTableColumn?, row: Int) -> Any? {
        let indexes=rowIndexes
        guard indexes.indices.contains(row) else { return nil }
        let site = draft.sites[indexes[row]]
        switch column?.identifier.rawValue {
        case "host": return (site.scope == "tree" ? "*." : "") + site.domain
        case "purpose": return AccessPurpose.label(site.tcp,defaultPorts:draft.ports)
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
        if ["save", "validate", "check-draft", "check-enrollment", "save-enrollment"].contains(op) {
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
    func matchesStoredBase(_ base: WorkProfile) -> Bool {
        if let stored=storedWork() { return stored==base }
        // A new installation starts with an empty editor. A damaged file must
        // still be reviewed explicitly before its profile can be replaced.
        return base==WorkProfile() && !FileManager.default.fileExists(atPath:workURL.path)
    }
    func gateway() -> String? {
        let u=paths.data.appendingPathComponent("ssl-site.json")
        return (try? JSONSerialization.jsonObject(with:Data(contentsOf:u)) as? [String:String])?["site"]
    }
    func panelButton(_ title:String,_ action:Selector)->NSButton { NSButton(title:title,target:self,action:action) }
    var draftURL: URL { paths.data.appendingPathComponent("work-sites-draft.json") }
    var pendingURL: URL { paths.data.appendingPathComponent("work-sites-pending.json") }
    func queuedProfile(for base: WorkProfile) -> WorkProfile? {
        guard let data = try? Data(contentsOf: pendingURL),
              let pending = try? JSONDecoder().decode(PendingWork.self, from: data),
              pending.base == base else { return nil }
        return pending.profile
    }
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
            let w=makeWindow("Доступы",730,720)
            w.isRestorable=false
            for (id,title,width) in [("host","Адрес",262),("purpose","Для чего",245),("alias","Короткое имя",160)] {
                let column=NSTableColumn(identifier:NSUserInterfaceItemIdentifier(id))
                column.title=title; column.width=CGFloat(width); p.table.addTableColumn(column)
            }
            p.table.delegate=p; p.table.dataSource=p
            p.table.target=self; p.table.doubleAction=#selector(selectSite(_:))
            p.search.placeholderString="Поиск по адресу или короткому имени";p.search.target=self;p.search.action=#selector(searchChanged(_:))
            p.search.widthAnchor.constraint(equalToConstant:300).isActive=true;p.search.isHidden=true
            p.domain.placeholderString="Полное имя"; p.ports.placeholderString="443, 22 или *"
            p.domain.widthAnchor.constraint(equalToConstant:300).isActive=true
            p.ports.widthAnchor.constraint(equalToConstant:160).isActive=true
            p.commit.title="Готово";p.commit.target=self; p.commit.action=#selector(editSite);p.commit.bezelStyle = .rounded
            for field in [p.domain,p.ports] { field.target=self;field.action=#selector(editSite) }
            let purposes=NSPopUpButton(frame:.zero,pullsDown:true);purposes.addItem(withTitle:"Добавить назначение")
            for (name,port) in AccessPurpose.named { purposes.addItem(withTitle:name+" · \(port)");purposes.lastItem?.representedObject=port }
            purposes.addItem(withTitle:"Любой TCP");purposes.lastItem?.representedObject="*"
            purposes.target=self;purposes.action=#selector(pickPurpose(_:))
            func caption(_ text:String)->NSTextField { let l=NSTextField(labelWithString:text);l.textColor = .secondaryLabelColor;l.widthAnchor.constraint(equalToConstant:48).isActive=true;return l }
            let editTitle=NSTextField(labelWithString:"Правка доступа");editTitle.font = .systemFont(ofSize:13,weight:.semibold)
            for view in [editTitle,NSStackView(views:[caption("Имя"),p.domain,p.tree]),NSStackView(views:[caption("Порты"),p.ports,purposes]),
                         NSStackView(views:[p.short,panelButton("Отмена",#selector(cancelEdit)),p.commit])] { p.editBox.addArrangedSubview(view) }
            p.editBox.orientation = .vertical;p.editBox.alignment = .leading;p.editBox.spacing=6;p.editBox.isHidden=true
            p.address.isRichText=false; p.address.isAutomaticQuoteSubstitutionEnabled=false
            p.address.isAutomaticDashSubstitutionEnabled=false
            // Without a real frame and resizing rules the text view inside the scroll view takes no clicks.
            p.address.frame=NSRect(x:0,y:0,width:660,height:56)
            p.address.minSize=NSSize(width:0,height:56);p.address.maxSize=NSSize(width:CGFloat.greatestFiniteMagnitude,height:CGFloat.greatestFiniteMagnitude)
            p.address.isVerticallyResizable=true;p.address.isHorizontallyResizable=false;p.address.autoresizingMask = .width
            p.address.isEditable=true;p.address.isSelectable=true
            p.address.font = .systemFont(ofSize:13);p.address.textColor = .labelColor;p.address.drawsBackground=true;p.address.backgroundColor = .textBackgroundColor
            p.address.textContainerInset=NSSize(width:4,height:4)
            p.address.textContainer?.containerSize=NSSize(width:660,height:CGFloat.greatestFiniteMagnitude)
            p.address.textContainer?.widthTracksTextView=true
            NotificationCenter.default.addObserver(self,selector:#selector(addressChanged),name:NSText.didChangeNotification,object:p.address)
            let pasteRow=NSStackView(views:[panelButton("Разобрать",#selector(parseAddresses)),panelButton("Проверить",#selector(checkAddress)),panelButton("Импорт…",#selector(importSites))])
            let addTitle=NSTextField(labelWithString:"Добавить доступ");addTitle.font = .systemFont(ofSize:13,weight:.semibold)
            let hint=NSTextField(wrappingLabelWithString:"Вставьте ссылки, имена, user@host, host:порт или строку server: из kubeconfig — по одной на строку");hint.textColor = .secondaryLabelColor;hint.preferredMaxLayoutWidth=675
            p.preview.isHidden=true
            p.noteObserver=settingsNote.observe(\.stringValue,options:[.new]){ [weak self] label,_ in label.isHidden=label.stringValue.isEmpty;self?.fitSettingsWindow() }
            settingsNote.isHidden=true
            p.previewTitle.font = .systemFont(ofSize:12,weight:.medium)
            p.addButton.target=self;p.addButton.action=#selector(addPreview);p.addButton.bezelStyle = .rounded
            p.previewList.orientation = .vertical;p.previewList.alignment = .leading;p.previewList.spacing=6
            p.previewScroll.hasVerticalScroller=true;p.previewScroll.borderType = .bezelBorder;p.previewScroll.documentView=p.previewList
            p.previewScroll.widthAnchor.constraint(equalToConstant:675).isActive=true
            p.previewHeight=p.previewScroll.heightAnchor.constraint(equalToConstant:120);p.previewHeight?.isActive=true
            p.previewBox.orientation = .vertical;p.previewBox.alignment = .leading;p.previewBox.spacing=6
            for view in [p.previewTitle,p.previewScroll,NSStackView(views:[p.addButton,panelButton("Очистить",#selector(clearPreview))])] { p.previewBox.addArrangedSubview(view) }
            p.previewBox.isHidden=true
            p.editButton.title="Изменить";p.editButton.target=self;p.editButton.action=#selector(selectSite(_:))
            p.deleteButton.title="Удалить";p.deleteButton.target=self;p.deleteButton.action=#selector(removeSite)
            let actions=NSStackView(views:[p.editButton,p.deleteButton])
            p.suffixes.placeholderString="Дополнительные суффиксы поиска через запятую"
            p.login.placeholderString="Точные имена для доступа до входа"
            for field in [p.suffixes,p.login] { field.widthAnchor.constraint(equalToConstant:460).isActive=true }
            for field in [p.status,p.preview,settingsNote,p.source] {field.preferredMaxLayoutWidth=665}
            for field in [p.login,p.suffixes] { NotificationCenter.default.addObserver(self,selector:#selector(advancedChanged),name:NSControl.textDidChangeNotification,object:field) }
            func fieldCaption(_ text:String)->NSTextField { let l=NSTextField(labelWithString:text);l.widthAnchor.constraint(equalToConstant:130).isActive=true;return l }
            let loginNote=NSTextField(wrappingLabelWithString:"Эти имена идут мимо туннеля, они нужны для входа.");loginNote.textColor = .secondaryLabelColor;loginNote.preferredMaxLayoutWidth=665
            for view in [p.source,NSStackView(views:[fieldCaption("Свои суффиксы"),p.suffixes]),NSStackView(views:[fieldCaption("Доступ до входа"),p.login]),loginNote] { p.advanced.addArrangedSubview(view) }
#if CVR_SELECTIVE_TUN
            p.advanced.addArrangedSubview(panelButton("Сертификаты HTTPS…",#selector(certificates)))
#endif
            p.advanced.addArrangedSubview(p.status)
            p.advanced.orientation = .vertical;p.advanced.alignment = .leading;p.advanced.spacing=7;p.advanced.isHidden=true
            p.advancedToggle.title="Дополнительно ▸";p.advancedToggle.isBordered=false;p.advancedToggle.target=self;p.advancedToggle.action=#selector(toggleAdvanced)
            p.more.addItem(withTitle:"Ещё")
            for (title,action) in [("Экспорт…",#selector(exportSites)),("Вернуть предыдущие правила…",#selector(undoSites))] {
                p.more.addItem(withTitle:title);p.more.lastItem?.target=self;p.more.lastItem?.action=action
            }
            p.cancelButton.title="Отменить";p.cancelButton.target=self;p.cancelButton.action=#selector(cancelChanges);p.cancelButton.bezelStyle = .rounded
            p.saveButton.title="Сохранить";p.saveButton.target=self;p.saveButton.action=#selector(savePolicy);p.saveButton.bezelStyle = .rounded
            let spacer=NSView();spacer.setContentHuggingPriority(NSLayoutConstraint.Priority(1),for:.horizontal)
            let bar=NSStackView(views:[p.more,spacer,p.stateLabel,p.cancelButton,p.saveButton]);bar.widthAnchor.constraint(equalToConstant:675).isActive=true
            let column=makeColumn([addTitle,hint,scroll(p.address,width:675,height:56),pasteRow,p.preview,p.previewBox,
                NSTextField(labelWithString:"Мои доступы"),p.search,scroll(p.table,width:675,height:168),actions,p.editBox,
                p.advancedToggle,p.advanced,settingsNote,bar],spacing:8)
            p.column=column;attachColumn(column,to:w)
            settingsWindow=w
            p.base=storedWork() ?? WorkProfile(); p.draft=p.base
            if let queued=queuedProfile(for:p.base) { p.draft=queued }
            if let saved=try? JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:draftURL)), let latest=saved.draft(for:p.base) {p.draft=latest}
            loadDraft();updateSearchSource()
        } else if !matchesStoredBase(p.base), p.draft == p.base, p.editing == nil {
            p.base=storedWork() ?? WorkProfile(); p.draft=p.base; loadDraft()
        }
        routeStatus()
        NSApp.activate(ignoringOtherApps:true);settingsWindow?.makeKeyAndOrderFront(nil)
    }
    func loadDraft(_ selected:Int = -1) {
        let p=sitesPanel
        p.table.reloadData()
        if let row=p.rowIndexes.firstIndex(of:selected) { p.table.selectRowIndexes(IndexSet(integer:row),byExtendingSelection:false) }
        p.login.stringValue=p.draft.beforeLogin.joined(separator:", ")
        p.suffixes.stringValue=(p.draft.searchDomains ?? []).joined(separator:", ")
        p.search.isHidden = p.draft.sites.count<=10 && p.filter.isEmpty
        newSite()
        settingsNote.stringValue=""
        refreshState()
    }
    func changeCount() -> Int {
        let p=sitesPanel
        var n=p.draft.sites.filter{!p.base.sites.contains($0)}.count+p.base.sites.filter{old in !p.draft.sites.contains{$0.domain==old.domain}}.count
        if p.draft.beforeLogin != p.base.beforeLogin {n+=1}
        if p.draft.searchDomains != p.base.searchDomains {n+=1}
        return n==0 && p.draft != p.base ? 1:n
    }
    func refreshState() {
        let p=sitesPanel,n=changeCount()
        let queued=queuedProfile(for:p.base)
        let saved=queued ?? p.base
        if p.applying { p.stateLabel.stringValue="Применяем правила…";p.stateLabel.textColor = .secondaryLabelColor }
        else if queued != nil && p.draft == saved { p.stateLabel.stringValue="Правила отложены";p.stateLabel.textColor = .secondaryLabelColor }
        else if queued != nil { p.stateLabel.stringValue="Есть черновик и отложенные правила";p.stateLabel.textColor = .systemOrange }
        else if n==0 { p.stateLabel.stringValue="Все изменения сохранены";p.stateLabel.textColor = .secondaryLabelColor }
        else {
            let word=n%10==1 && n%100 != 11 ? "изменение не сохранено" : ((2...4).contains(n%10) && !(12...14).contains(n%100) ? "изменения не сохранены":"изменений не сохранено")
            p.stateLabel.stringValue="\(n) "+word;p.stateLabel.textColor = .systemOrange
        }
        p.cancelButton.isEnabled=p.draft != saved || p.editing != nil
        p.saveButton.isEnabled=(n>0 || p.draft != saved) && p.editing==nil && !p.applying
#if !(CVR_SELECTIVE_TUN && CVR_UPDATES)
        p.saveButton.isEnabled=p.editing==nil
#endif
    }
    @objc func advancedChanged() { readLogin();refreshState() }
    @objc func toggleAdvanced() {
        let p=sitesPanel
        p.advanced.isHidden.toggle()
        p.advancedToggle.title=p.advanced.isHidden ? "Дополнительно ▸":"Дополнительно ▾"
        fitSettingsWindow()
    }
    @objc func cancelChanges() {
        let p=sitesPanel
        if p.editing != nil {cancelEdit();return}
        let saved=queuedProfile(for:p.base) ?? p.base
        guard p.draft != saved else{return}
        p.draft=saved;changedDraft()
        settingsNote.stringValue="Изменения черновика отменены."
    }
    func selectedSiteIndex() -> Int? {
        let p=sitesPanel,row=p.table.selectedRow,indexes=p.rowIndexes
        return indexes.indices.contains(row) ? indexes[row]:nil
    }
    @objc func searchChanged(_ sender:NSSearchField) { sitesPanel.filter=sender.stringValue;sitesPanel.table.reloadData() }
    @objc func selectSite(_ sender:Any? = nil) {
        let p=sitesPanel
        if sender is NSTableView, p.table.clickedRow<0 { return }
        guard let i=selectedSiteIndex() else {settingsNote.stringValue="Выберите доступ в списке.";return}
        let row=p.draft.sites[i]
        p.editing=i;p.domain.stringValue=row.domain;p.tree.state=row.scope=="tree" ? .on:.off
        p.ports.stringValue=(row.tcp ?? .selected(p.draft.ports)).label;p.short.state=row.alias==nil ? .off:.on
        p.editBox.isHidden=false;p.table.isEnabled=false;p.editButton.isEnabled=false;p.deleteButton.isEnabled=false
        settingsNote.stringValue="";fitSettingsWindow();refreshState()
        settingsWindow?.makeFirstResponder(p.domain)
    }
    @objc func newSite(){
        let p=sitesPanel;p.editing=nil;p.domain.stringValue="";p.ports.stringValue=TCPPorts.selected(p.draft.ports).label;p.tree.state = .off;p.short.state = .off
        p.editBox.isHidden=true;p.table.isEnabled=true;p.editButton.isEnabled=true;p.deleteButton.isEnabled=true
        fitSettingsWindow();if p.stateLabel.superview != nil {refreshState()}
    }
    @objc func cancelEdit(){ newSite();settingsNote.stringValue="Правка отменена." }
    @objc func pickPurpose(_ sender:NSPopUpButton) {
        let p=sitesPanel
        guard let value=sender.selectedItem?.representedObject else{return}
        if let port=value as? Int {
            let current=p.ports.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
            let list=current=="*" || current.isEmpty ? []:current.split(separator:",").map{$0.trimmingCharacters(in:.whitespaces)}
            if !list.contains(String(port)) { p.ports.stringValue=(list+[String(port)]).joined(separator:", ") }
        } else { p.ports.stringValue="*" }
    }
    func readLogin(){
        let p=sitesPanel
        func names(_ text:String)->[String]{text.lowercased().split(whereSeparator:{$0=="," || $0.isWhitespace}).map(String.init)}
        p.draft.beforeLogin=names(p.login.stringValue)
        let suffixes=names(p.suffixes.stringValue);p.draft.searchDomains=suffixes.isEmpty ? nil:suffixes
    }
    func changedDraft(_ selected:Int = -1) {
        loadDraft(selected)
        persistDraft()
    }
    func persistDraft(){
        let p=sitesPanel
        do {try JSONFile.write(PendingWork(base:p.base,profile:p.draft),to:draftURL)}
        catch {settingsNote.stringValue="Черновик в памяти. Записать его на диск не удалось."}
    }
    @objc func removeSite(){
        let p=sitesPanel
        guard p.editing==nil,let i=selectedSiteIndex() else{return}
        readLogin();p.draft.sites.remove(at:i);changedDraft()
    }
    @discardableResult @objc func editSite()->Bool {
        let p=sitesPanel
        guard let editing=p.editing,p.draft.sites.indices.contains(editing) else{return false}
        let h=p.domain.stringValue.trimmingCharacters(in:.whitespacesAndNewlines).lowercased()
        guard Configuration.validHost(h), h.contains(".") else{settingsNote.stringValue="Введите полное DNS-имя. Маску задайте флажком «С поддоменами».";return false}
        let raw=p.ports.stringValue.trimmingCharacters(in:.whitespacesAndNewlines)
        let tokens=raw.split(separator:",",omittingEmptySubsequences:false)
        let ports=tokens.compactMap { Int($0.trimmingCharacters(in:.whitespaces)) }
        guard raw=="*" || (ports.count==tokens.count && (1...32).contains(ports.count) && ports.allSatisfy({(1...65535).contains($0)})) else {settingsNote.stringValue="Укажите TCP-порты через запятую или *.";return false}
        readLogin()
        let old=p.draft
        let previous=old.sites[editing]
        let alias=p.short.state == .on ? (h==previous.domain ? previous.alias ?? firstLabel(h) : firstLabel(h)) : nil
        var row=WorkSite(domain:h,scope:p.tree.state == .on ? "tree":"exact",tcp:raw=="*" ? .any:.selected(Array(Set(ports)).sorted()),alias:alias)
        guard !old.beforeLogin.contains(h), !old.sites.enumerated().contains(where:{$0.offset != editing && ($0.element.domain==h || (row.alias != nil && row.alias==$0.element.alias))}) else {settingsNote.stringValue="Имя или короткое имя уже используется в другом доступе.";return false}
        if old.sites[editing].tcp==nil && row.tcp == .selected(old.ports.sorted()) { row.tcp=nil }
        p.draft.sites[editing]=row
        p.draft.version=2;changedDraft(editing);return true
    }
    @objc func exportSites(){
        readLogin();let panel=NSSavePanel();panel.nameFieldStringValue="work-rules.json"
        guard panel.runModal() == .OK,let url=panel.url else{return}
        do {try JSONFile.write(PortableRules(kind:"work-rules",sites:sitesPanel.draft.sites,ports:sitesPanel.draft.ports,searchDomains:sitesPanel.draft.searchDomains ?? []),to:url)} catch {settingsNote.stringValue="Не удалось записать файл."}
    }
    @objc func importSites(){
        guard sitesPanel.editing==nil else {settingsNote.stringValue="Сначала завершите правку доступа.";return}
        let panel=NSOpenPanel();panel.allowsMultipleSelection=false
        guard panel.runModal() == .OK, let u=panel.url else{return}
        do{let data=try Data(contentsOf:u);guard data.count<=131072 else{throw RouterError.invalidConfiguration}
            readLogin()
            let old=sitesPanel.draft
            if let portable=try? JSONDecoder().decode(PortableRules.self,from:data), portable.kind=="work-rules" {
                sitesPanel.draft=WorkProfile(version:2,sites:portable.sites,beforeLogin:old.beforeLogin,searchDomains:portable.searchDomains.isEmpty ? nil:portable.searchDomains,ports:portable.ports)
                changedDraft();return
            }
            if let rule = try? JSONDecoder().decode(SharedTCPRule.self, from:data) {
                readLogin()
                try sitesPanel.draft.mergeExactRule(rule)
                changedDraft(sitesPanel.draft.sites.firstIndex { $0.domain == rule.domain } ?? 0)
                settingsNote.stringValue="В черновике изменено одно точное правило. Проверьте адрес и порты, затем сохраните список."
                return
            }
            let draft=try JSONDecoder().decode(WorkProfile.self,from:data); guard [1,2].contains(draft.version) && !draft.sites.isEmpty && draft.sites.count<=256 else{throw RouterError.invalidConfiguration}
            sitesPanel.draft=draft;changedDraft();settingsNote.stringValue="Импортирован черновик. Проверьте область доменов и адреса до входа."
        }catch{settingsNote.stringValue="Не удалось прочитать профиль рабочих сайтов."}
    }
    @objc func undoSites() {
        guard sitesPanel.editing==nil else {settingsNote.stringValue="Сначала завершите правку доступа.";return}
        let previous = paths.data.appendingPathComponent("previous-work-sites.json")
        guard let data = try? Data(contentsOf:previous), let profile = try? JSONDecoder().decode(WorkProfile.self,from:data) else {
            settingsNote.stringValue="Предыдущая версия правил отсутствует.";return
        }
        sitesPanel.draft=profile;changedDraft();settingsNote.stringValue="Предыдущие правила загружены в черновик. Проверьте и сохраните."
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
    func fitSettingsWindow() {
        guard let w=settingsWindow,let column=sitesPanel.column else{return}
        w.contentView?.layoutSubtreeIfNeeded()
        if let scroll=sitesPanel.address.enclosingScrollView { sitesPanel.address.setFrameSize(NSSize(width:scroll.contentSize.width,height:max(scroll.contentSize.height,sitesPanel.address.frame.height))) }
        let height=column.fittingSize.height+38
        var frame=w.frame
        let target=w.frameRect(forContentRect:NSRect(x:0,y:0,width:frame.width,height:height)).height
        frame.origin.y+=frame.height-target;frame.size.height=target
        w.setFrame(frame,display:true,animate:false)
    }
    func checkRoute(_ text:String){
        let p=sitesPanel,id=UUID()
        guard !text.isEmpty, text.utf8.count<=2048, !text.contains("\n") else {p.preview.stringValue="Для проверки укажите один адрес.";return}
        p.requestID=id;p.preview.stringValue="Проверяем соединение…"
        analyzeInput(Data(text.utf8),preview:false){ result in
            guard id==p.requestID else{return}
            p.preview.stringValue=result["message"] as? String ?? "Проверка не завершена."
        }
    }
    @objc func checkAddress(){ checkRoute(sitesPanel.address.string.trimmingCharacters(in:.whitespacesAndNewlines)) }
    @objc func addressChanged(){ clearPreview() }
    @objc func checkCoveredRow(_ sender:NSButton){ if let text=sender.identifier?.rawValue {checkRoute(text)} }
    @objc func parseAddresses(){
        let p=sitesPanel,text=p.address.string,id=UUID()
        clearPreview()
        readLogin()
        guard !text.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,text.utf8.count<=32768 else {p.preview.stringValue="Вставьте до 64 адресов (32 КБ).";return}
        let request:[String:Any]=["text":text,"suffixes":Array(Set(p.gatewaySuffixes+(p.draft.searchDomains ?? []))).sorted()]
        guard let data=try? JSONSerialization.data(withJSONObject:request) else{return}
        p.requestID=id;p.preview.stringValue="Разбираем адреса…"
        analyzeInput(data,preview:true){ result in
            guard id==p.requestID,text==p.address.string else{return}
            guard let rows=result["rows"] as? [[String:Any]],!rows.isEmpty else {p.preview.stringValue=result["message"] as? String ?? "Нет адресов.";return}
            p.parsedText=text;self.showPreview(rows)
        }
    }
    func firstLabel(_ host:String)->String { String(host.prefix(while:{$0 != "."})) }
    func previewRow(_ item:PreviewItem,note:String?)->NSView {
        let hostView:NSView
        if item.choices.count>1 {
            item.hostPopup.addItems(withTitles:["Выберите полное имя"]+item.choices);item.hostPopup.selectItem(at:0)
            item.hostPopup.target=self;item.hostPopup.action=#selector(previewChoice(_:))
            hostView=item.hostPopup
        } else {
            let label=NSTextField(labelWithString:(item.tree ? "*.":"")+item.host);label.lineBreakMode = .byTruncatingMiddle
            hostView=label
        }
        var options=AccessPurpose.named.map{(AccessPurpose.label(port:$0.1),$0.1)}
        let detected=(AccessPurpose.label(port:item.port,scheme:item.scheme),item.port)
        if let index=options.firstIndex(where:{$0.1==item.port}) { options[index]=detected }
        else { options.insert(detected,at:0) }
        for (title,port) in options { item.purpose.addItem(withTitle:title);item.purpose.lastItem?.representedObject=port }
        item.purpose.selectItem(at:options.firstIndex{$0.1==item.port} ?? 0)
        let main=NSStackView(views:[item.check,hostView,item.purpose])
        if item.covered==nil && (!item.tree && item.host.contains(".") || item.alias != nil) {
            item.aliasCheck.title="Короткое имя: "+(item.alias ?? firstLabel(item.host))
            item.aliasCheck.state=item.alias==nil ? .off:.on
            main.addArrangedSubview(item.aliasCheck)
        }
        item.check.target=self;item.check.action=#selector(previewToggled)
        hostView.widthAnchor.constraint(equalToConstant:250).isActive=true
        item.purpose.widthAnchor.constraint(equalToConstant:150).isActive=true
        guard let note else {return main}
        let text=NSTextField(labelWithString:note);text.textColor = .secondaryLabelColor
        var views:[NSView]=[text]
        if item.covered != nil {
            let check=NSButton(title:"Проверить подключение",target:self,action:#selector(checkCoveredRow(_:)))
            check.identifier=NSUserInterfaceItemIdentifier(item.host+":"+String(item.port));check.controlSize = .small;check.bezelStyle = .rounded
            views.append(check)
        }
        let detail=NSStackView(views:views);detail.edgeInsets=NSEdgeInsets(top:0,left:26,bottom:0,right:0)
        return makeColumn([main,detail],spacing:2)
    }
    @objc func previewChoice(_ sender:NSPopUpButton) {
        sitesPanel.items.first{$0.hostPopup===sender}?.check.state = sender.indexOfSelectedItem>0 ? .on:.off
        updatePreviewCount()
    }
    @objc func previewToggled(){updatePreviewCount()}
    func updatePreviewCount() {
        let p=sitesPanel,count=p.items.filter{$0.check.state == .on && $0.check.isEnabled}.count
        p.addButton.title="Добавить \(count)";p.addButton.isEnabled=count>0
    }
    func showPreview(_ rows:[[String:Any]]) {
        let p=sitesPanel
        p.items=[];p.previewList.arrangedSubviews.forEach{$0.removeFromSuperview()}
        var covered=0
        for row in rows {
            guard let host=row["host"] as? String,let port=row["port"] as? Int else {
                let label=NSTextField(wrappingLabelWithString:"✕ "+(row["error"] as? String ?? "Неизвестный формат"))
                label.textColor = .systemRed;label.preferredMaxLayoutWidth=640;p.previewList.addArrangedSubview(label);continue
            }
            let item=PreviewItem(host:host,choices:row["choices"] as? [String] ?? [host],tree:row["tree"] as? Bool==true,alias:row["alias"] as? String,
                                 scheme:row["scheme"] as? String ?? "tcp",port:port)
            let rule=WorkSite(domain:host,scope:item.tree ? "tree":"exact",tcp:.selected([port]),alias:item.alias)
            item.covered=item.choices.count==1 ? p.draft.covers(rule):nil
            item.check.state=item.covered==nil && item.choices.count==1 ? .on:.off
            var note:String?
            if let cover=item.covered {
                item.check.isEnabled=false;item.purpose.isEnabled=false;item.aliasCheck.isEnabled=false;covered+=1
                note="уже есть: "+(cover.scope=="tree" ? "*.":"")+cover.domain
            }
            p.items.append(item);p.previewList.addArrangedSubview(previewRow(item,note:note))
        }
        p.previewTitle.stringValue="Найдено: \(rows.count)"+(covered>0 ? " · уже разрешено: \(covered)":"")
        p.previewList.frame=NSRect(origin:.zero,size:p.previewList.fittingSize)
        p.previewHeight?.constant=min(190,p.previewList.fittingSize.height+8)
        p.previewBox.isHidden=false;p.preview.stringValue=""
        updatePreviewCount();fitSettingsWindow()
    }
    @objc func clearPreview(){
        let p=sitesPanel
        p.requestID=UUID();p.parsedText=nil
        p.items=[];p.previewList.arrangedSubviews.forEach{$0.removeFromSuperview()}
        p.previewBox.isHidden=true;p.preview.stringValue="";fitSettingsWindow()
    }
    @objc func addPreview(){
        let p=sitesPanel,old=p.draft
        guard p.parsedText==p.address.string else {clearPreview();return}
        guard p.editing==nil else {settingsNote.stringValue="Сначала завершите правку: «Готово» или «Отмена».";return}
        var next=old,added=[String]()
        do {
            for item in p.items where item.check.state == .on && item.check.isEnabled {
                var host=item.host
                if item.choices.count>1 {
                    guard item.hostPopup.indexOfSelectedItem>0 else{throw ProxyFailure("Выберите полное имя из найденных.")}
                    host=item.choices[item.hostPopup.indexOfSelectedItem-1]
                }
                let port=item.purpose.selectedItem?.representedObject as? Int ?? item.port
                let alias=item.aliasCheck.superview != nil && item.aliasCheck.state == .on ? (item.alias ?? firstLabel(host)):nil
                var row=WorkSite(domain:host,scope:item.tree ? "tree":"exact",tcp:.selected([port]),alias:alias)
                if next.covers(row) != nil { continue }
                guard !next.beforeLogin.contains(row.domain) else{throw ProxyFailure("Имя исключено для доступа до входа.")}
                if let existing=next.sites.first(where:{$0.domain==row.domain}) {
                    // An alias selected in the preview can be attached without changing grants.
                    guard row.alias != nil,existing.alias==nil, next.covers(WorkSite(domain:row.domain,scope:row.scope,tcp:row.tcp)) != nil else {throw ProxyFailure("Для "+row.domain+" уже есть правило. Измените его явно.")}
                    row=existing;row.alias=alias
                    next.sites.removeAll{$0.domain==row.domain}
                } else if let parent=next.matching(row.domain) {
                    // A more specific row must retain inherited ports.
                    switch parent.tcp ?? .selected(next.ports) {
                    case .any:row.tcp = .any
                    case .selected(let ports):if case .selected(let more)=row.tcp {row.tcp = .selected(Array(Set(ports+more)).sorted())}
                    }
                }
                guard row.alias==nil || !next.sites.contains(where:{$0.alias==row.alias}) else{throw ProxyFailure("Алиас уже занят.")}
                next.sites.append(row);next.version=2;added.append(row.domain)
            }
        } catch {settingsNote.stringValue=error.localizedDescription;return}
        if next != old {p.draft=next;changedDraft()}
        p.address.string="";clearPreview()
        settingsNote.stringValue=added.isEmpty ? "Новых правил нет." : "Добавлено: "+String(added.count)
        if let last=added.last,let i=p.draft.sites.firstIndex(where:{$0.domain==last}) {p.table.scrollRowToVisible(i)}
        settingsWindow?.makeFirstResponder(p.address)
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
        guard sitesPanel.editing==nil else { settingsNote.stringValue="Завершите правку кнопкой «Готово» или отмените её.";return }
        readLogin()
        persistDraft()
        let temp=paths.data.appendingPathComponent("draft-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        do{try JSONFile.write(sitesPanel.draft,to:temp)}catch{settingsNote.stringValue="Не удалось сохранить черновик.";return}
        #if CVR_SELECTIVE_TUN && CVR_UPDATES
        let validation=Self.routeCommand("check-draft",[temp.path],resources:resources)
        guard validation.code==0 else { settingsNote.stringValue="Не сохранено: "+validation.output;return }
        let profile=sitesPanel.draft
        guard !sitesPanel.applying,!applyingBundledRule,matchesStoredBase(sitesPanel.base) else {settingsNote.stringValue="Список изменён или уже применяется. Сохраните черновик через «Ещё → Экспорт…».";return}
        guard profile != sitesPanel.base else {
            if queuedProfile(for:profile) != nil {
                do {try FileManager.default.removeItem(at:pendingURL)}
                catch {settingsNote.stringValue="Не удалось отменить отложенные правила.";return}
                settingsNote.stringValue="Отложенные правила отменены."
            }
            refreshState();return
        }
        do {try JSONFile.write(PendingWork(base:sitesPanel.base,profile:profile),to:pendingURL)} catch {settingsNote.stringValue="Не сохранено: не удалось записать черновик.";return}
        if let first=profile.sites.firstIndex(where:{!sitesPanel.base.sites.contains($0)}) { sitesPanel.table.scrollRowToVisible(first) }
        guard engine==nil && !selective.busy else {settingsNote.stringValue="Сохранено. Правила применятся при следующем подключении, текущий сеанс продолжается.";refreshState();return}
        applyPending(connectAfter:false)
        #else
        settingsNote.stringValue=Self.routeCommand("save",[temp.path]).output
        #endif
        routeStatus();refreshState()
    }
    #if CVR_SELECTIVE_TUN && CVR_UPDATES
    func saveAppliedProfile(_ file:URL, from old:WorkProfile, to new:WorkProfile, bundled:Bool, firstEnrollment:Bool = false) throws {
        guard matchesStoredBase(old) else {throw ProxyFailure("Профиль изменился. Проверьте текущие правила.")}
        let p=sitesPanel
        let open=settingsWindow != nil && p.base==old
        var edited:WorkProfile?
        if open {
            readLogin()
            edited=p.draft
        } else if FileManager.default.fileExists(atPath:draftURL.path) {
            let disk=try JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:draftURL))
            edited=disk.draft(for:old)
        }
        var rebased=edited
        if var draft=edited, bundled {
            // Add migration changes only to rows the user has not independently edited.
            for row in new.sites {
                let previous=old.sites.first { $0.domain==row.domain }
                if row==previous {continue}
                if let i=draft.sites.firstIndex(where:{$0.domain==row.domain}) {
                    if draft.sites[i]==previous {draft.sites[i]=row}
                } else if previous==nil && draft.covers(row)==nil {draft.sites.append(row)}
            }
            draft.version=max(draft.version,new.version)
            rebased=draft
        }
        if let edited, let rebased {
            try JSONFile.write(PendingWork(base:old,profile:edited,nextBase:new,nextDraft:rebased),to:draftURL)
        }
        let result=Self.routeCommand(firstEnrollment ? "save-enrollment" : "save",[file.path],resources:resources)
        guard result.code==0 else {throw ProxyFailure(result.output)}
        if open {
            p.base=new;p.draft=rebased ?? new;p.table.reloadData();refreshState()
        }
        if rebased==new {try? FileManager.default.removeItem(at:draftURL)}
    }

    func applyPending(connectAfter:Bool) {
        let p=sitesPanel
        guard !p.applying else{return}
        func report(_ text:String) {
            settingsNote.stringValue=text;refreshState()
            if connectAfter {
                connectionNotice=text
                if connectionPhase == .failed {connectionFailure=text}
                presentConnection()
            }
        }
        guard let saved=try? JSONDecoder().decode(PendingWork.self,from:Data(contentsOf:pendingURL)) else {report("Не удалось прочитать отложенный профиль.");return}
        func completePending() {
            do { try FileManager.default.removeItem(at:pendingURL) }
            catch {report("Правила записаны. Не удалось убрать отметку отложенного применения.");return}
            report(settingsWindow != nil && p.draft != saved.profile
                ? "Отложенные правила применены. В черновике остались неприменённые изменения."
                : "Правила применены и сверены с помощником.")
            if connectAfter {connect()}
        }
        if storedWork()==saved.profile && saved.profile != saved.base {
            // A previous save succeeded but the process exited before clearing pending.
            completePending();return
        }
        guard matchesStoredBase(saved.base) else {report("Отложенный профиль расходится с сохранённым. Проверьте рабочие правила.");return}
        let profile=saved.profile
        let temp=paths.data.appendingPathComponent("apply-"+UUID().uuidString)
        do {try JSONFile.write(profile,to:temp)} catch {report("Ошибка чтения черновика.");return}
        let validation=Self.routeCommand("check-draft",[temp.path],resources:resources)
        guard validation.code==0 else{try? FileManager.default.removeItem(at:temp);report(validation.output);return}
        let status=SelectiveRouter.helperReply(resources:resources)
        let desktop=(status?["approvedRDPHost"] as? String).flatMap { profile.work($0) ? $0:nil } ?? ""
        guard let enrollment=try? profile.enrollment(desktop:desktop),let expected=try? JSONSerialization.jsonObject(with:enrollment) as? [String:Any] else {try? FileManager.default.removeItem(at:temp);report("Не удалось подготовить разрешения.");return}
        p.applying=true;refreshState()
        func finish(_ success:Bool){
            defer {try? FileManager.default.removeItem(at:temp)}
            p.applying=false
            guard success else{report("Утверждение не завершено. Черновик сохранён.");return}
            do {try saveAppliedProfile(temp,from:saved.base,to:profile,bundled:false)}
            catch {report(error.localizedDescription);return}
            completePending()
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
struct StarterHTTPSAliases: Decodable {
    static let filename = "StarterHTTPSAliases.json"
    static let receipt = "starter-https-aliases-v1.applied"
    static let httpEntryReceipt = "starter-http-entry-v1.applied"
    let hosts: [String]
    let httpEntryHost: String?
    let additionalHTTPEntryHost: String?

    var httpEntries: [(host: String, receipt: String)] {
        var entries: [(String, String)] = []
        if let host = httpEntryHost { entries.append((host, Self.httpEntryReceipt)) }
        if let host = additionalHTTPEntryHost { entries.append((host, "starter-http-entry-v2.applied")) }
        return entries
    }

    static func load(_ url: URL) throws -> Self {
        let bundle = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
        let httpHosts = bundle.httpEntries.map { $0.host }
        guard Set(httpHosts).count == httpHosts.count, httpHosts.allSatisfy(bundle.hosts.contains),
              (1...16).contains(bundle.hosts.count), Set(bundle.hosts).count == bundle.hosts.count,
              Set(bundle.hosts.map { $0.split(separator: ".").first }).count == bundle.hosts.count,
              bundle.hosts.allSatisfy({ $0.contains(".") && Configuration.validHost($0) }) else {
            throw RouterError.invalidConfiguration
        }
        return bundle
    }

    // Only extend an existing exact starter alias that still grants HTTPS.
    func addHTTPEntry(_ host: String, to profile: inout WorkProfile) throws {
        guard let site = profile.sites.first(where: { $0.domain == host }),
              site.scope == "exact", site.alias == String(host.prefix(while: { $0 != "." })),
              !profile.beforeLogin.contains(host),
              case .selected(let ports) = site.tcp ?? .selected(profile.ports),
              ports.contains(443), !ports.contains(80) else { return }
        try profile.mergeExactRule(SharedTCPRule(kind: "exact-tcp-rule", domain: host, ports: [80], shortName: false))
    }

    func add(to profile: inout WorkProfile) -> [String] {
        var conflicts: [String] = []
        for host in hosts {
            let alias = String(host.prefix(while: { $0 != "." }))
            let row = WorkSite(domain: host, scope: "exact", tcp: .selected([443]), alias: alias)
            if profile.covers(row) != nil { continue }
            do {
                try profile.mergeExactRule(SharedTCPRule(kind: "exact-tcp-rule", domain: host, ports: [443], shortName: true))
            } catch {
                conflicts.append(host)
            }
        }
        return conflicts
    }
}

extension BetaMenu {
    // Keep the receipt independent of app version so later updates respect manual edits.
    func applyBundledRuleIfNeeded(connectAfterward: Bool) -> Bool {
        let resource = resources.appendingPathComponent("BundledTCPRule.json")
        let legacyReceipt = paths.data.appendingPathComponent("bundled-tcp-rule-v1.applied")
        let httpsReceipt = paths.data.appendingPathComponent("bundled-https-v1.applied")
        let fm = FileManager.default
        let starterAliases = resources.appendingPathComponent(StarterHTTPSAliases.filename)
        let starterReceipt = paths.data.appendingPathComponent(StarterHTTPSAliases.receipt)
        guard !applyingBundledRule, engine == nil, !selective.busy,
              selective.helperAvailability.canConnect || selective.helperAvailability.needsInstallation,
              fm.fileExists(atPath:resource.path), fm.fileExists(atPath:workURL.path) else { return false }
        do {
            let aliases = fm.fileExists(atPath:starterAliases.path) ? try StarterHTTPSAliases.load(starterAliases) : nil
            let needsStarterAliases = aliases != nil && !fm.fileExists(atPath:starterReceipt.path)
            let pendingHTTP = (aliases?.httpEntries ?? []).filter { entry in
                !fm.fileExists(atPath:paths.data.appendingPathComponent(entry.receipt).path)
            }
            guard needsStarterAliases || !pendingHTTP.isEmpty ||
                  !fm.fileExists(atPath:legacyReceipt.path) || !fm.fileExists(atPath:httpsReceipt.path) else { return false }
            let original = try Data(contentsOf:workURL)
            let profile = try JSONDecoder().decode(WorkProfile.self,from:original)
            let bytes=try Data(contentsOf:resource)
            let rule = try JSONDecoder().decode(SharedTCPRule.self,from:bytes)
            struct HTTPSDelivery: Decodable { let httpsSites:[String] }
            let delivery=try JSONDecoder().decode(HTTPSDelivery.self,from:bytes)
            var candidate=profile
            var receipts=[URL]()
            if !fm.fileExists(atPath:legacyReceipt.path), profile.work(rule.domain) {
                do {
                    try candidate.mergeExactRule(rule)
                    receipts.append(legacyReceipt)
                } catch { connectionNotice="Сохранены ваши правила. " + error.localizedDescription }
            }
            if !fm.fileExists(atPath:httpsReceipt.path) {
                var conflict=false
                for host in delivery.httpsSites {
                    let row=WorkSite(domain:host,scope:"exact",tcp:.selected([443]))
                    if candidate.covers(row) != nil {continue}
                    // A tree on this exact name without 443 cannot be widened silently.
                    if candidate.beforeLogin.contains(host) || candidate.sites.contains(where:{$0.domain==host && $0.scope=="tree"}) {
                        conflict=true;connectionNotice="Сохранено конфликтующее правило для " + host
                        continue
                    }
                    try candidate.mergeExactRule(SharedTCPRule(kind:"exact-tcp-rule",domain:host,ports:[443],shortName:false))
                }
                if !conflict || candidate != profile {receipts.append(httpsReceipt)}
            }
            if let aliases {
                if needsStarterAliases {
                    let conflicts = aliases.add(to: &candidate)
                    if !conflicts.isEmpty {
                        connectionNotice = "Сохранены ваши правила для: " + conflicts.joined(separator: ", ")
                    }
                    receipts.append(starterReceipt)
                }
                for entry in pendingHTTP {
                    do { try aliases.addHTTPEntry(entry.host, to: &candidate) }
                    catch { connectionNotice = "Сохранено ваше правило для " + entry.host }
                    receipts.append(paths.data.appendingPathComponent(entry.receipt))
                }
            }
            guard !receipts.isEmpty else {return false}
            func markApplied() throws {
                for receipt in receipts {try Data("applied\n".utf8).write(to:receipt,options:.atomic)}
            }
            let status = SelectiveRouter.helperReply(resources:resources)
            let desktop = status?["approvedRDPHost"] as? String ??
                Provisioning.defaultDesktop(resources:resources,paths:paths,profile:profile) ?? ""
            let enrollment = try candidate.enrollment(desktop:desktop)
            let expected = try JSONSerialization.jsonObject(with:enrollment) as? [String:Any]
            let authorized = selective.helperAvailability.canConnect &&
                (status?["tcpRules"] as? NSArray)?.isEqual(expected?["rules"]) == true
            if authorized && candidate == profile {
                try markApplied()
                return false
            }
            let pending = paths.data.appendingPathComponent("pending-" + UUID().uuidString)
            try JSONFile.write(candidate,to:pending)
            // An earlier installation may already have enrolled the idle helper before the first VPN login.
            let firstEnrollment = !fm.fileExists(atPath:paths.data.appendingPathComponent("ssl-site.json").path)
            let validation = Self.routeCommand(firstEnrollment ? "check-enrollment" : "check-draft",[pending.path],resources:resources)
            guard validation.code == 0 else {
                try? fm.removeItem(at:pending)
                let reason = validation.output.trimmingCharacters(in:.whitespacesAndNewlines)
                if connectAfterward, let message = gatewaySetupMessage(reason) {
                    journal("routes", "bundled_rule_validation", code: reason)
                    failConnection(message, code: reason)
                    return true
                }
                throw ProxyFailure(gatewaySetupMessage(reason) ?? validation.output)
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
                        try self.saveAppliedProfile(pending,from:profile,to:candidate,bundled:true,firstEnrollment:firstEnrollment)
                    }
                    try markApplied()
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
