import AppKit
import Foundation

func require(_ condition: Bool, _ label: String) {
    if !condition { fputs("FAIL: \(label)\n", stderr); exit(1) }
}
func waitFor(_ message: String, _ test: () -> Bool) {
    let end = Date().addingTimeInterval(15)
    while !test() && Date() < end { RunLoop.current.run(until:Date().addingTimeInterval(0.03)) }
    require(test(),message)
}
func run() throws {
    let fm = FileManager.default
    let payload = URL(fileURLWithPath:CommandLine.arguments[1])
    let root = fm.temporaryDirectory.appendingPathComponent("cvr-rule-" + UUID().uuidString)
    defer { try? fm.removeItem(at:root) }
    let paths = ProductPaths(root:root.path,systemApplications:root.appendingPathComponent("SystemApps"))
    try paths.createData()
    let firstProfile = CommandLine.arguments.contains("--first-profile")
    let menu = BetaMenu(paths:paths), resources=menu.resources
    for dir in ["Runtime/bin","RouteHelper","Engine"] {
        try fm.createDirectory(at:resources.appendingPathComponent(dir),withIntermediateDirectories:true)
    }
    let engine = resources.appendingPathComponent("Engine")
    try fm.removeItem(at:engine)
    try fm.copyItem(at:payload.appendingPathComponent("Engine"),to:engine)
    for file in firstProfile ? ["RouteHelper/RouteHelper"] : ["BundledTCPRule.json","RouteHelper/RouteHelper"] {
        try fm.copyItem(at:payload.appendingPathComponent(file),to:resources.appendingPathComponent(file))
    }
    func executable(_ name:String, _ source:String) throws {
        let file=resources.appendingPathComponent(name)
        try Data(source.utf8).write(to:file)
        try fm.setAttributes([.posixPermissions:0o700],ofItemAtPath:file.path)
    }
    let state=paths.data.appendingPathComponent("test-helper.json")
    // No XPC or administrator access. Exercise the packaged controller with a disposable home.
    try executable("RouteHelper/RouteClient","#!/bin/sh\nwhile read line; do /bin/cat '\(state.path)'; echo; done\n")
    let started=root.appendingPathComponent("started")
    try executable("Runtime/bin/python3.13","""
    #!/bin/sh
    export HOME='\(root.path)'
    case " $* " in *" check-draft "*|*" save "*) if [ '\(firstProfile)' = 'true' ]; then echo OFFICIAL_SERVICE_NOT_STARTED; exit 1; fi;; esac
    case " $* " in *" start "*) /usr/bin/touch '\(started.path)'; /bin/cat >/dev/null; exit 0;; esac
    exec '\(payload.appendingPathComponent("Runtime/bin/python3.13").path)' "$@"
    """+"\n")
    let suffix="fixture.example"
    let original=WorkProfile(sites:[WorkSite(domain:suffix,scope:"tree"),WorkSite(domain:"mail.example",scope:"exact",tcp:.selected([8443]))], beforeLogin:["vpn.example"],ports:[443])
    var old=original; old.version=2
    if !firstProfile {
        try JSONFile.write(old,to:menu.workURL)
        try JSONFile.write(["site":"vpn.example"],to:paths.data.appendingPathComponent("ssl-site.json"))
    }
    let desktop=firstProfile ? "" : "desktop."+suffix
    let oldRules=(try JSONSerialization.jsonObject(with:old.enrollment(desktop:desktop)) as! [String:Any])["rules"]!
    func reply(_ rules:Any, reportedDesktop: String? = nil) throws {
        try JSONSerialization.data(withJSONObject:["ok":true,"active":false,"cleanupPending":false,"approvedRDPHost":reportedDesktop ?? desktop,"tcpRules":rules]).write(to:state)
    }
    try reply(oldRules)
    let app=NSApplication.shared
    app.setActivationPolicy(.accessory)
    menu.window=menu.makeWindow("fixture",510,362);menu.diagnostics=menu.makeWindow("fixture diagnostics",520,306)
    menu.item=NSStatusBar.system.statusItem(withLength:0)
    menu.updates = RouterUpdates(owner:menu)
    menu.setupMain();menu.setupDiagnostics();menu.method.selectedSegment=0
    var approved = !firstProfile
    menu.selective.inspectHelper = { _ in approved ? .ready : .missing }
    menu.selective.inspectCleanup = { _ in true }
    menu.selective.changed = { menu.selectiveChanged() }
    var prompts=0
    var cancel=true
    var wrongDesktop=false
    menu.selective.authorizeHelper = { args in
        prompts+=1
        if cancel { return "cancelled (-128)" }
        let encoded=args[2].components(separatedBy:"'").dropLast().last!
        let object=try! JSONSerialization.jsonObject(with:Data(base64Encoded:encoded)!) as! [String:Any]
        require(object["desktop"] as? String==desktop,"existing RDP host preserved")
        try! reply(object["rules"]!, reportedDesktop:wrongDesktop ? "other.fixture.example" : desktop)
        approved=true
        return nil
    }
    if firstProfile {
        menu.selective.helperAvailability = .missing
        menu.settings()
        require(menu.storedWork()==nil && menu.sitesPanel.draft.sites.isEmpty,"fresh profile is empty")
        menu.sitesPanel.address.string="https://first.example"
        menu.parseAddresses()
        waitFor("first address parsed"){!menu.sitesPanel.previewBox.isHidden}
        menu.addPreview()
        let draft=menu.sitesPanel.draft
        menu.savePolicy()
        waitFor("approval cancelled"){!menu.sitesPanel.applying}
        require(menu.storedWork()==nil && menu.queuedProfile(for:WorkProfile())==draft,"first profile is retryable after cancellation")
        cancel=false
        wrongDesktop=true
        menu.savePolicy()
        waitFor("missing desktop confirmation"){!menu.sitesPanel.applying}
        require(menu.storedWork()==nil && fm.fileExists(atPath:menu.pendingURL.path),"incomplete helper confirmation retains the draft")
        wrongDesktop=false
        try reply(oldRules)
        menu.savePolicy()
        waitFor("approval completed"){!menu.sitesPanel.applying}
        require(menu.storedWork()==draft,"first profile saved: \(menu.settingsNote.stringValue)")
        require(prompts==3 && !fm.fileExists(atPath:menu.pendingURL.path),"first profile installed with approved rules")
        print("PASS empty editor, first policy, cancelled approval, successful retry")
        return
    }
    func button(_ title:String,_ view:NSView)->NSButton? {
        if let b=view as? NSButton,b.title==title {return b}
        return view.subviews.compactMap{button(title,$0)}.first
    }
    var initial=old
    initial.sites.append(WorkSite(domain:"test.example",scope:"tree",tcp:.any))
    initial.sites.append(WorkSite(domain:"any.example",scope:"exact",tcp:.any,alias:"any"))
    try JSONFile.write(initial,to:menu.workURL)
    try Data().write(to:menu.allPortsMarker) // the one-time widening is checked below
    menu.settings()
    let panel=menu.sitesPanel,window=menu.settingsWindow!
    let press:(String)->Void={title in
        guard let b=button(title,window.contentView!) else {fatalError("Missing button "+title)}
        b.performClick(nil)
    }
    try fm.removeItem(at:menu.allPortsMarker)
    menu.widenSavedRules()
    require(panel.draft.sites.allSatisfy{$0.tcp == .any} && menu.storedWork()==initial,"saved rules widened in the draft only")
    require(menu.settingsNote.stringValue.contains("все порты"),"widening is announced")
    press("Отменить")
    require(panel.draft==initial,"widening can be discarded")
    try Data().write(to:menu.allPortsMarker)
    menu.widenSavedRules()
    require(panel.draft==initial,"never widened again after a save")
    // One path to add: paste, parse into the in-window preview, add the checked lines.
    func paste(_ text:String) {
        panel.address.string=text
        press("Разобрать")
        waitFor("preview shown for "+text){!panel.previewBox.isHidden && !panel.items.isEmpty}
    }
    panel.table.selectRowIndexes(IndexSet(integer:2),byExtendingSelection:false)
    paste("administrator.test.example")
    require(panel.items[0].covered?.domain=="test.example" && !panel.items[0].check.isEnabled,"covered child is inactive and names its rule")
    require(panel.previewTitle.stringValue.contains("уже разрешено") && !panel.addButton.isEnabled,"nothing to add")
    require(panel.draft==initial && panel.table.selectedRow==2,"covered child leaves selected parent intact")
    press("Очистить")
    require(panel.previewBox.isHidden && panel.items.isEmpty,"preview cleared")
    paste("stale.example")
    panel.address.string="replacement.example"
    menu.addPreview()
    require(panel.draft==initial && panel.previewBox.isHidden,"changing paste text invalidates an earlier preview")
    paste("first.example");panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+1 && panel.address.string.isEmpty && panel.previewBox.isHidden,"add clears the paste field")
    require(panel.table.selectedRow==2,"adding never replaces the selected row")
    paste("second.example");panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+2,"two additions in a row")
    require(panel.stateLabel.stringValue.contains("не сохранен"),"state shows unsaved changes")
    panel.table.selectRowIndexes(IndexSet(integer:4),byExtendingSelection:false)
    press("Изменить")
    require(!panel.editBox.isHidden && panel.domain.stringValue=="first.example","edit opens in place")
    panel.domain.stringValue="discarded.example";press("Отмена")
    require(panel.editBox.isHidden && panel.draft.sites[4].domain=="first.example","cancelled edit changes nothing")
    press("Изменить")
    panel.domain.stringValue="renamed.example";panel.commit.performClick(nil)
    require(panel.draft.sites[4].domain=="renamed.example","explicit rename")
    press("Отменить")
    require(panel.draft==initial && panel.stateLabel.stringValue=="Все изменения сохранены","Cancel rolls the draft back to the saved rules")
    func onlyDetectedPorts() {
        for item in panel.items {
            item.purpose.selectItem(at:item.purpose.itemArray.firstIndex{($0.representedObject as? Int)==item.port}!)
        }
    }
    // Several ports of one server, and a new port for a saved rule.
    paste("node.example:9094\nnode.example:9092");onlyDetectedPorts();panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+1 && panel.draft.sites.last?.tcp == .selected([9092,9094]),"two lines of one host make one rule: \(menu.settingsNote.stringValue)")
    paste("node.example:6445")
    require(panel.items[0].covered==nil && panel.addButton.isEnabled,"a new port of a saved host can be added")
    onlyDetectedPorts();panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+1 && panel.draft.sites.last?.tcp == .selected([6445,9092,9094]),"port appended to the rule")
    require(menu.settingsNote.stringValue.contains("дополнены порты: 1"),"extension is reported")
    paste("*.node.example");panel.addButton.performClick(nil)
    require(panel.draft.sites.last?.scope=="exact" && menu.settingsNote.stringValue.contains("другим охватом"),"coverage never widens silently")
    press("Очистить")
    paste("node.example")
    require(panel.items[0].purpose.titleOfSelectedItem=="Все порты (*)","all ports preselected")
    panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+1 && panel.draft.sites.last?.tcp == .any,"a saved rule widens to all ports")
    press("Отменить")
    require(panel.draft==initial,"rolled back")
    paste("first.example\nsecond.example");panel.addButton.performClick(nil)
    require(panel.draft.sites.count==initial.sites.count+2,"both lines added at once")
    panel.table.selectRowIndexes(IndexSet(integer:4),byExtendingSelection:false)
    press("Изменить")
    panel.domain.stringValue="unfinished.example"
    press("Сохранить")
    require(panel.draft.sites.count==initial.sites.count+2 && panel.domain.stringValue=="unfinished.example" && panel.editing != nil,"save never commits an edit in progress")
    window.performClose(nil);menu.settings()
    require(panel.domain.stringValue=="unfinished.example" && !panel.editBox.isHidden,"close preserves the unfinished edit")
    press("Отмена")
    paste("any.example:22\nhttps://third.example:8443/secret?a=private")
    require(panel.items[0].covered != nil && panel.items[1].purpose.itemTitles.contains("Веб · 8443"),"covered line inactive, port detected")
    panel.addButton.performClick(nil)
    require(panel.draft.sites[3]==initial.sites[3],"paste preserves any TCP and alias")
    require(panel.draft.sites.last?.tcp == .any,"all ports by default, even with a port in the line")
    paste("service.example")
    panel.items[0].purpose.selectItem(withTitle:"Kubernetes · 6443");panel.addButton.performClick(nil)
    require(panel.draft.sites.last?.tcp == .selected([6443]),"purpose can be changed without retyping")
    menu.selective.helperAvailability = .ready
    press("Сохранить")
    waitFor("cancelled approval"){!panel.applying}
    require(menu.storedWork()==initial,"cancel preserves applied rules")
    require(fm.fileExists(atPath:menu.pendingURL.path),"pending draft persisted")
    let queued=panel.draft
    require(panel.stateLabel.stringValue=="Правила отложены","cancelled approval still shows queued rules")
    paste("newer.example");panel.addButton.performClick(nil)
    require(panel.stateLabel.stringValue=="Есть черновик и отложенные правила","newer draft is distinct from queued rules")
    press("Отменить")
    require(panel.draft==queued && menu.queuedProfile(for:initial)==queued,"discarding the newer draft returns to queued rules")
    cancel=false;press("Сохранить")
    waitFor("successful apply"){menu.storedWork()==panel.draft}
    waitFor("saved state shown"){panel.stateLabel.stringValue=="Все изменения сохранены"}
    require(!fm.fileExists(atPath:menu.pendingURL.path),"clear pending on success")
    window.performClose(nil)
    menu.menuConnect=NSMenuItem(title:"Подключить",action:#selector(BetaMenu.menuToggle),keyEquivalent:"")
    menu.menuConnect.target=menu;let bar=NSMenu();bar.addItem(menu.menuConnect)
    menu.loginDraft.stringValue="fixture-user"
    for mini in [false,true] {
        menu.window.makeKeyAndOrderFront(nil)
        if mini {menu.window.miniaturize(nil)} else {_=menu.windowShouldClose(menu.window)}
        menu.menuConnect.title="Подключить"
        bar.performActionForItem(at:0)
        require(menu.window.isVisible && !menu.window.isMiniaturized && !menu.hiddenByUser,"explicit menu connect restores main window")
        require(!window.isVisible,"editor stays closed")
        if menu.connectionPhase.pending {menu.stop("test")}
        waitFor("stopped"){!menu.connectionPhase.pending && menu.selective.process==nil}
    }
    print("PASS inline add preview, covered child, two adds, in-place rename and cancel, unfinished edit kept, anyTCP, purposes, pending, cancel/retry, closed/minimized window")
}
do { try run() } catch { fputs("FAIL: \(error)\n",stderr);exit(1) }
