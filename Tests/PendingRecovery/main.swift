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
    app.setActivationPolicy(.prohibited)
    menu.window=menu.makeWindow("fixture",510,362);menu.diagnostics=menu.makeWindow("fixture diagnostics",520,306)
    menu.item=NSStatusBar.system.statusItem(withLength:0)
    menu.updates = RouterUpdates(owner:menu)
    menu.setupMain();menu.setupDiagnostics();menu.method.selectedSegment=0
    menu.selective.inspectHelper = { _ in .ready }
    menu.selective.inspectCleanup = { _ in true }
    menu.selective.changed = { menu.selectiveChanged() }
    let baseline = CommandLine.arguments.contains("--baseline")
    var b=old;b.sites.append(WorkSite(domain:"b.example",scope:"exact"))
    var c=b;c.sites.append(WorkSite(domain:"c.example",scope:"exact"))
    let panel=menu.sitesPanel
    menu.settings()
    // The session and controller pipes are local children. No gateway or root helper is used.
    try executable("Runtime/bin/python3.13","""
    #!/bin/sh
    export HOME='\(root.path)'
    case "$*" in *session.py*|*" start "*) exec /bin/cat >/dev/null;; esac
    exec '\(payload.appendingPathComponent("Runtime/bin/python3.13").path)' "$@"
    """+"\n")
    let controller=Process(), pipe=Pipe()
    controller.executableURL=URL(fileURLWithPath:"/bin/cat");controller.standardInput=pipe
    controller.standardOutput=FileHandle.nullDevice;try controller.run()
    menu.selective.process=controller;menu.selective.input=pipe.fileHandleForWriting
    menu.selective.helperAvailability = .ready;menu.selective.attemptGateway="vpn.example";menu.selective.state="ready";menu.connectionPhase = .connected
    panel.draft=b;menu.loadDraft();menu.savePolicy()
    require(fm.fileExists(atPath:menu.pendingURL.path),"B deferred during session")
    menu.failConnection("fixture transport lost",code:"TEST_LOSS")
    require(menu.selective.holdingRoutes,"same controller holds routes")
    menu.loginDraft.stringValue="fixture-user";menu.connect()
    if baseline {
        menu.connect()
        require(menu.engine==nil && menu.connectionPhase == .failed,"3022 repeat connect blocked")
        print("REPRO 3022: two reconnect clicks blocked while same controller holds routes")
    } else {
        require(menu.engine?.isRunning==true && menu.connectionPhase == .authenticating,"recover authentication with pending B")
    }
    require(controller.isRunning && menu.selective.holdingRoutes && menu.storedWork()==old && fm.fileExists(atPath:menu.pendingURL.path),"hold and deferred B preserved")
    if let worker=menu.engine {menu.generation+=1;worker.terminationHandler=nil;worker.terminate();worker.waitUntilExit();menu.engine=nil}
    pipe.fileHandleForWriting.closeFile();controller.waitUntilExit()
    menu.selective.process=nil;menu.selective.input=nil;menu.selective.state="stopped";menu.connectionPhase = .idle
    var mode="cancel"
    let finishApproval=DispatchSemaphore(value:0)
    menu.selective.authorizeHelper = { args in
        if mode=="cancel" {return "cancelled (-128)"}
        if mode=="accept" {
            guard finishApproval.wait(timeout:.now()+20) == .success else { return "Fixture approval timed out" }
            let encoded=args[2].components(separatedBy:"'").dropLast().last!
            let obj=try! JSONSerialization.jsonObject(with:Data(base64Encoded:encoded)!) as! [String:Any]
            try! reply(obj["rules"]!)
        }
        return nil
    }
    for setting in ["cancel","error"] {
        mode=setting;menu.applyPending(connectAfter:false)
        waitFor("cancel/error completed"){!panel.applying}
        require(menu.storedWork()==old && fm.fileExists(atPath:menu.pendingURL.path),"retryable after "+setting)
    }
    mode="accept";menu.applyPending(connectAfter:false)
    require(panel.applying,"authorization in flight")
    panel.address.string="c.example"
    menu.parseAddresses()
    waitFor("preview available during approval"){!panel.previewBox.isHidden}
    menu.addPreview()
    require(panel.draft.sites.contains{$0.domain=="c.example"},"edit C during approval")
    c=panel.draft
    finishApproval.signal()
    waitFor("B applied"){!panel.applying}
    require(menu.storedWork()==b && !fm.fileExists(atPath:menu.pendingURL.path),"B applied once")
    let restarted=BetaMenu(paths:paths);restarted.settings()
    if baseline {
        require(restarted.sitesPanel.draft==b && c != b,"3022 loses C on reconstruction")
        print("REPRO 3022: newer C present on disk but ignored after reopening from B")
    } else {
        require(restarted.sitesPanel.draft==c && restarted.sitesPanel.base==b,"C restored against B")
        require(restarted.sitesPanel.stateLabel.stringValue.contains("не сохранен"),"draft status visible")
        // Repeat with no open editor at the time of application.
        try JSONFile.write(old,to:menu.workURL)
        try JSONFile.write(PendingWork(base:old,profile:c),to:menu.draftURL)
        try JSONFile.write(PendingWork(base:old,profile:b),to:menu.pendingURL)
        let headless=BetaMenu(paths:paths);headless.applyPending(connectAfter:false)
        let next=BetaMenu(paths:paths);next.settings()
        require(next.sitesPanel.base==b && next.sitesPanel.draft==c,"unopened editor restored C")
        print("PASS recover, retain controller and B, cancel/error/retry, C during authorization and across relaunch")
    }
}
do {try run()} catch {fputs("FAIL: \(error)\n",stderr);exit(1)}
