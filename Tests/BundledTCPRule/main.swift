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
    func connect() { menu.loginDraft.stringValue="fixture-user";menu.connect() }
    connect()
    waitFor("cancel ends attempt") { menu.connectionPhase == .failed && !menu.applyingBundledRule }
    require(try JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:menu.workURL))==old,"cancel preserves old profile")
    cancel=false;connect()
    waitFor("same click continues to route startup") { fm.fileExists(atPath:started.path) }
    let stored=try JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:menu.workURL))
    require(stored.sites.dropLast().elementsEqual(old.sites),"other sites intact")
    require(stored.sites.last==WorkSite(domain:rule.domain,scope:"exact",tcp:.selected([22,443,6443]),alias:String(rule.domain.prefix(while:{$0 != "."}))),"narrow rule with inherited HTTPS")
    require(try JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:paths.data.appendingPathComponent("previous-work-sites.json")))==old,"previous profile backed up")
    menu.stop("done");waitFor("fixture stopped") { menu.selective.process==nil }
    try JSONFile.write(old,to:menu.workURL)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false),"user removal respected")
    let receipt=paths.data.appendingPathComponent("bundled-tcp-rule-v1.applied")
    try fm.removeItem(at:receipt)
    try JSONFile.write(stored,to:menu.workURL)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && fm.fileExists(atPath:receipt.path),"already installed and approved, no prompt")
    require(prompts==2,"one cancelled authorization plus one accepted authorization")
    var legacy=WorkProfile(sites:[WorkSite(domain:suffix,scope:"tree")])
    try legacy.mergeExactRule(rule)
    require(legacy.version==2 && legacy.sites.last==stored.sites.last,"v1 scope and ports retained")
    print("PASS packaged rule, cancel/retry, verified save, same-click continuation, existing settings, no reapplication after deletion, unchanged v1 and v2 grants")
}
do { try run() } catch { fputs("FAIL: \(error)\n",stderr);exit(1) }
