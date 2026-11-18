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
    let menu = BetaMenu(paths:paths), resources=menu.resources
    for dir in ["Runtime/bin","RouteHelper","Engine"] {
        try fm.createDirectory(at:resources.appendingPathComponent(dir),withIntermediateDirectories:true)
    }
    let engine = resources.appendingPathComponent("Engine")
    try fm.removeItem(at:engine)
    try fm.copyItem(at:payload.appendingPathComponent("Engine"),to:engine)
    for file in ["BundledTCPRule.json","RouteHelper/RouteHelper"] {
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
    case " $* " in *" start "*) /usr/bin/touch '\(started.path)'; /bin/cat >/dev/null; exit 0;; esac
    exec '\(payload.appendingPathComponent("Runtime/bin/python3.13").path)' "$@"
    """+"\n")
    let rule = try JSONDecoder().decode(SharedTCPRule.self,from:Data(contentsOf:resources.appendingPathComponent("BundledTCPRule.json")))
    let suffix=rule.domain.split(separator:".").dropFirst().joined(separator:".")
    let original=WorkProfile(sites:[WorkSite(domain:suffix,scope:"tree"),WorkSite(domain:"mail.example",scope:"exact",tcp:.selected([8443]))], beforeLogin:["vpn.example"],ports:[443])
    var old=original; old.version=2
    try JSONFile.write(old,to:menu.workURL)
    try JSONFile.write(["site":"vpn.example"],to:paths.data.appendingPathComponent("ssl-site.json"))
    let desktop="desktop."+suffix
    let oldRules=(try JSONSerialization.jsonObject(with:old.enrollment(desktop:desktop)) as! [String:Any])["rules"]!
    func reply(_ rules:Any) throws {
        try JSONSerialization.data(withJSONObject:["ok":true,"active":false,"cleanupPending":false,"approvedRDPHost":desktop,"tcpRules":rules]).write(to:state)
    }
    try reply(oldRules)
    let app=NSApplication.shared
    app.setActivationPolicy(.accessory)
    menu.window=menu.makeWindow("fixture",510,362);menu.diagnostics=menu.makeWindow("fixture diagnostics",520,306)
    menu.item=NSStatusBar.system.statusItem(withLength:0)
    menu.updates = RouterUpdates(owner:menu)
    menu.setupMain();menu.setupDiagnostics();menu.method.selectedSegment=0
    menu.selective.inspectHelper = { _ in .ready }
    menu.selective.inspectCleanup = { _ in true }
    menu.selective.changed = { menu.selectiveChanged() }
    var prompts=0
    var cancel=true
    menu.selective.authorizeHelper = { args in
        prompts+=1
        if cancel { return "cancelled (-128)" }
        let encoded=args[2].components(separatedBy:"'").dropLast().last!
        let object=try! JSONSerialization.jsonObject(with:Data(base64Encoded:encoded)!) as! [String:Any]
        require(object["desktop"] as? String==desktop,"existing RDP host preserved")
        try! reply(object["rules"]!)
        return nil
    }
    func button(_ title:String,_ view:NSView)->NSButton? {
        if let b=view as? NSButton,b.title==title {return b}
        return view.subviews.compactMap{button(title,$0)}.first
    }
    var initial=old
    initial.sites.append(WorkSite(domain:"test.example",scope:"tree",tcp:.selected([443])))
    initial.sites.append(WorkSite(domain:"any.example",scope:"exact",tcp:.any,alias:"any"))
    try JSONFile.write(initial,to:menu.workURL)
    menu.settings()
    let panel=menu.sitesPanel,window=menu.settingsWindow!
    let press:(String)->Void={title in
        guard let b=button(title,window.contentView!) else {fatalError("Missing button "+title)}
        b.performClick(nil)
    }
    panel.table.selectRowIndexes(IndexSet(integer:2),byExtendingSelection:false)
    panel.domain.stringValue="administrator.test.example"
    press("Добавить")
    require(panel.draft==initial && menu.settingsNote.stringValue.contains("test.example"),"covered child leaves selected parent intact")
    panel.domain.stringValue="first.example";press("Добавить")
    panel.domain.stringValue="second.example";press("Добавить")
    require(panel.draft.sites.count==initial.sites.count+2,"two additions")
    panel.table.selectRowIndexes(IndexSet(integer:4),byExtendingSelection:false)
    press("Изменить")
    panel.domain.stringValue="renamed.example";panel.commit.performClick(nil)
    require(panel.draft.sites[4].domain=="renamed.example","explicit rename")
    press("Отменить правку")
    require(panel.draft.sites[4].domain=="first.example","undo rename")
    panel.domain.stringValue="unfinished.example"
    press("Применить правила")
    require(panel.draft.sites.count==initial.sites.count+2 && panel.domain.stringValue=="unfinished.example","apply never commits input")
    window.performClose(nil);menu.settings()
    require(panel.domain.stringValue=="unfinished.example","close preserves input")
    press("Отменить правку")
    panel.address.string="any.example:22\nhttps://third.example:8443/secret?a=private"
    func approvePreview(){
        let timer=Timer(timeInterval:0.05,repeats:true){ t in
            if let modal=NSApp.modalWindow,let b=button("В черновик",modal.contentView!) {t.invalidate();b.performClick(nil)}
        }
        RunLoop.main.add(timer,forMode:.modalPanel)
        press("Разобрать адреса…")
        waitFor("preview added"){panel.draft.sites.contains{$0.domain=="third.example"}}
    }
    approvePreview()
    require(panel.draft.sites[3]==initial.sites[3],"paste preserves any TCP and alias")
    require(panel.draft.sites.last?.tcp == .selected([8443]),"explicit nonstandard port")
    menu.selective.helperAvailability = .ready
    press("Применить правила")
    waitFor("cancelled approval"){!panel.applying}
    require(menu.storedWork()==initial,"cancel preserves applied rules")
    require(fm.fileExists(atPath:menu.pendingURL.path),"pending draft persisted")
    cancel=false;press("Применить правила")
    waitFor("successful apply"){menu.storedWork()==panel.draft}
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
    print("PASS AppKit table selection, two adds, covered child, explicit rename and undo, batch, anyTCP, pending, cancel/retry, closed/minimized window")
}
do { try run() } catch { fputs("FAIL: \(error)\n",stderr);exit(1) }
