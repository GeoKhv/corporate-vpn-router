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
    var original=WorkProfile(sites:[WorkSite(domain:suffix,scope:"tree"),WorkSite(domain:"mail.example",scope:"exact",tcp:.selected([8443]))], beforeLogin:["vpn.example"],ports:[443])
    // Exercise a previous installed profile on a disposable copy if supplied.
    if CommandLine.arguments.count>2 {
        original=try JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2])))
    } else {
        original.sites.append(WorkSite(domain:"unrelated.example",scope:"exact",tcp:.any,alias:"unrelated"))
    }
    var old=original;old.version=2
    let payloadObject=try JSONSerialization.jsonObject(with:Data(contentsOf:resources.appendingPathComponent("BundledTCPRule.json"))) as! [String:Any]
    let https=payloadObject["httpsSites"] as! [String]
    require(https==["testrwa.alfabank.ru","administrator.testrwa.alfabank.ru"],"approved HTTPS payload")
    let fromPrevious=CommandLine.arguments.count>2
    if fromPrevious {
        try JSONFile.write(true,to:paths.data.appendingPathComponent("bundled-tcp-rule-v1.applied"))
    }
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
    for row in old.sites where row.domain != rule.domain || fromPrevious {
        require(stored.sites.contains(row),"prior row, alias and ports unchanged")
    }
    require(stored.beforeLogin==old.beforeLogin && stored.searchDomains==old.searchDomains && stored.ports==old.ports,"profile settings intact")
    if !fromPrevious {
        require(stored.sites.contains(WorkSite(domain:rule.domain,scope:"exact",tcp:.selected([22,443,6443]),alias:String(rule.domain.prefix(while:{$0 != "."})))),"legacy delivery")
    }
    for host in https {
        require(stored.covers(WorkSite(domain:host,scope:"exact",tcp:.selected([443]))) != nil,"delivered HTTPS")
        require(stored.sites.filter{$0.domain==host}.count<=1,"no duplicate")
    }
    require(!stored.sites.contains{$0.domain=="alfabank.ru" && !old.sites.contains($0)},"no parent expansion")
    require(try JSONDecoder().decode(WorkProfile.self,from:Data(contentsOf:paths.data.appendingPathComponent("previous-work-sites.json")))==old,"previous profile backed up")
    menu.stop("done");waitFor("fixture stopped") { !menu.selective.busy }
    try JSONFile.write(old,to:menu.workURL)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false),"user removal respected")
    let receipt=paths.data.appendingPathComponent("bundled-tcp-rule-v1.applied")
    if !fromPrevious {try fm.removeItem(at:receipt)}
    try JSONFile.write(stored,to:menu.workURL)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && fm.fileExists(atPath:receipt.path),"already installed and approved, no prompt")
    require(prompts==2,"one cancelled authorization plus one accepted authorization")
    let httpsReceipt=paths.data.appendingPathComponent("bundled-https-v1.applied")
    try fm.removeItem(at:httpsReceipt)
    var covered=old
    covered.sites.removeAll {https.contains($0.domain)}
    covered.sites.append(WorkSite(domain:https[0],scope:"tree",tcp:.any))
    try JSONFile.write(covered,to:menu.workURL)
    try reply((try JSONSerialization.jsonObject(with:covered.enrollment(desktop:desktop)) as! [String:Any])["rules"]!)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && menu.storedWork()==covered && fm.fileExists(atPath:httpsReceipt.path),"anyTCP tree covers both; no duplicate or prompt")
    try JSONFile.write(old,to:menu.workURL)
    require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && menu.storedWork()==old,"subsequent user change respected")
    var legacy=WorkProfile(sites:[WorkSite(domain:suffix,scope:"tree")])
    try legacy.mergeExactRule(rule)
    require(legacy.version==2 && legacy.sites.last?.tcp == .selected([22,443,6443]),"v1 scope and ports retained")
    let starterSource=payload.appendingPathComponent(StarterHTTPSAliases.filename)
    if fm.fileExists(atPath:starterSource.path) {
        try fm.copyItem(at:starterSource,to:resources.appendingPathComponent(StarterHTTPSAliases.filename))
        let aliases=try StarterHTTPSAliases.load(starterSource)
        let receipt=paths.data.appendingPathComponent(StarterHTTPSAliases.receipt)
        let prior=menu.storedWork()!
        try reply((try JSONSerialization.jsonObject(with:prior.enrollment(desktop:desktop)) as! [String:Any])["rules"]!)
        cancel=true
        require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"existing starter requests approval with old receipts present")
        waitFor("starter approval cancelled"){!menu.applyingBundledRule}
        require(menu.storedWork()==prior && !fm.fileExists(atPath:receipt.path),"cancel preserves starter profile and permits retry")
        cancel=false
        require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"starter retries")
        waitFor("starter aliases applied"){!menu.applyingBundledRule && fm.fileExists(atPath:receipt.path)}
        let updated=menu.storedWork()!
        var baseline = prior
        if let host = aliases.retiredTreeHost { baseline.sites.removeAll { $0 == WorkSite(domain:host,scope:"tree") } }
        require(Array(updated.sites.prefix(baseline.sites.count))==baseline.sites,"only the retired starter tree may disappear")
        for host in aliases.hosts {
            let alias=String(host.prefix(while:{$0 != "."}))
            let ports = aliases.httpEntries.contains(where: { $0.host == host }) ? [80,443] : [443]
            require(updated.sites.contains(WorkSite(domain:host,scope:"exact",tcp:.selected(ports),alias:alias)),"starter delivers exact HTTPS alias")
        }
        try JSONFile.write(prior,to:menu.workURL)
        require(!menu.applyBundledRuleIfNeeded(connectAfterward:false),"starter respects manual removal")

        let host=aliases.hosts[0]
        let alias=String(host.prefix(while:{$0 != "."}))
        let unrelated=WorkSite(domain:alias+".example.org",scope:"exact",tcp:.any,alias:alias)
        var edited=prior
        edited.sites.append(unrelated)
        require(aliases.add(to:&edited)==[host] && edited.sites.contains(unrelated),"existing alias owner and any TCP preserved")
        if let host = aliases.httpEntryHost {
            let httpReceipt = paths.data.appendingPathComponent(StarterHTTPSAliases.httpEntryReceipt)
            var v40 = baseline
            _ = aliases.add(to: &v40)
            try JSONFile.write(v40,to:menu.workURL)
            try reply((try JSONSerialization.jsonObject(with:v40.enrollment(desktop:desktop)) as! [String:Any])["rules"]!)
            for entry in aliases.httpEntries { try fm.removeItem(at:paths.data.appendingPathComponent(entry.receipt)) }
            cancel=true
            require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"HTTP-only migration requests authorization")
            waitFor("HTTP authorization cancelled"){!menu.applyingBundledRule}
            require(menu.storedWork()==v40 && !fm.fileExists(atPath:httpReceipt.path),"HTTP cancel preserves state")
            cancel=false
            require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"HTTP migration retries")
            waitFor("HTTP migration saved"){!menu.applyingBundledRule && fm.fileExists(atPath:httpReceipt.path)}
            require(menu.storedWork()==updated,"direct HTTPS-only upgrade matches fresh rules")
            try JSONFile.write(v40,to:menu.workURL)
            require(!menu.applyBundledRuleIfNeeded(connectAfterward:false),"removing HTTP after upgrade is respected")
            var removed = v40
            removed.sites.removeAll { $0.domain == host }
            let snapshot = removed
            try aliases.addHTTPEntry(host, to:&removed)
            require(removed == snapshot,"deleted starter alias stays deleted during upgrade")
            if let additional = aliases.additionalHTTPEntryHost {
                // Superset was already delivered and the user removed TCP 80.
                let entry = aliases.httpEntries.first { $0.host == additional }!
                let additionalReceipt = paths.data.appendingPathComponent(entry.receipt)
                try fm.removeItem(at:additionalReceipt)
                try reply((try JSONSerialization.jsonObject(with:v40.enrollment(desktop:desktop)) as! [String:Any])["rules"]!)
                require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"second HTTP migration runs independently")
                waitFor("second HTTP migration saved"){!menu.applyingBundledRule && fm.fileExists(atPath:additionalReceipt.path)}
                var expected = v40
                try aliases.addHTTPEntry(additional, to:&expected)
                require(menu.storedWork()==expected && expected != v40,"only the newly delivered host changes")
            }
        }
        if let retired = aliases.retiredTreeHost {
            let marker = paths.data.appendingPathComponent(StarterHTTPSAliases.retiredTreeReceipt)
            let legacy = WorkSite(domain:retired,scope:"tree")
            var old = updated
            old.sites.append(legacy)
            try JSONFile.write(old,to:menu.workURL)
            try reply((try JSONSerialization.jsonObject(with:old.enrollment(desktop:desktop)) as! [String:Any])["rules"]!)
            try fm.removeItem(at:marker)
            cancel=true
            require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"retirement asks to update helper rules")
            waitFor("retirement cancelled"){!menu.applyingBundledRule}
            require(menu.storedWork()==old && !fm.fileExists(atPath:marker.path),"cancel preserves legacy workflow")
            cancel=false
            require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"retirement retries")
            waitFor("starter retirement saved"){!menu.applyingBundledRule && fm.fileExists(atPath:marker.path)}
            require(menu.storedWork()==updated,"removes only the unchanged legacy tree")
            try JSONFile.write(old,to:menu.workURL)
            require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && menu.storedWork()==old,"manual re-addition respected")
            try fm.removeItem(at:marker)
            old.sites[old.sites.count-1].tcp = .selected([8443])
            try JSONFile.write(old,to:menu.workURL)
            require(!menu.applyBundledRuleIfNeeded(connectAfterward:false) && menu.storedWork()==old && fm.fileExists(atPath:marker.path),"custom rule retained")
            print("PASS starter tree retirement, cancel, retry, custom ports and manual re-addition")
        }
        print("PASS starter alias migration with prior receipts, cancelled approval, retry, conflict and manual removal")
    }
    // Fresh helper installation must finish even when no live site is readable.
    for name in ["ssl-site.json", "bundled-tcp-rule-v1.applied", "bundled-https-v1.applied", StarterHTTPSAliases.receipt] {
        let path=paths.data.appendingPathComponent(name)
        if fm.fileExists(atPath:path.path) { try fm.removeItem(at:path) }
    }
    try fm.removeItem(at:state)
    try JSONFile.write(old,to:menu.workURL)
    try executable("Runtime/bin/python3.13", """
    #!/bin/sh
    export HOME='\(root.path)'
    case " $* " in *" check-draft "*|*" save "*|*" start "*) exit 87;; esac
    exec '\(payload.appendingPathComponent("Runtime/bin/python3.13").path)' "$@"
    """+"\n")
    menu.selective.helperAvailability = .missing
    menu.selective.inspectHelper = { _ in fm.fileExists(atPath:state.path) ? .ready : .missing }
    var firstApprovals = 0
    menu.selective.authorizeHelper = { args in
        firstApprovals += 1
        let encoded=args[2].components(separatedBy:"'").dropLast().last!
        let policy=try! JSONSerialization.jsonObject(with:Data(base64Encoded:encoded)!) as! [String:Any]
        try! reply(policy["rules"]!)
        return nil
    }
    menu.appRouting()
    waitFor("first setup finishes offline") { fm.fileExists(atPath:httpsReceipt.path) && !menu.applyingBundledRule }
    require(firstApprovals==1 && menu.engine==nil && menu.selective.process==nil, "one authorization, no network session")
    // A colleague who installed the old helper first still has no site binding.
    for name in ["bundled-tcp-rule-v1.applied","bundled-https-v1.applied",StarterHTTPSAliases.receipt] {
        let path=paths.data.appendingPathComponent(name)
        if fm.fileExists(atPath:path.path) {try fm.removeItem(at:path)}
    }
    try JSONFile.write(old,to:menu.workURL)
    try reply(oldRules)
    menu.selective.helperAvailability = .ready
    require(menu.applyBundledRuleIfNeeded(connectAfterward:false),"already installed helper enrolls without a site binding")
    waitFor("ready helper completes offline migration"){fm.fileExists(atPath:httpsReceipt.path) && !menu.applyingBundledRule}
    require(firstApprovals==2 && menu.engine==nil && menu.selective.process==nil,"no VPN session during enrollment")
    print("PASS first-install button enrolls and saves fresh rules with no live Check Point command")
    print("PASS packaged rule, cancel/retry, verified save, same-click continuation, existing settings, no reapplication after deletion, unchanged v1 and v2 grants")
}
do { try run() } catch { fputs("FAIL: \(error)\n",stderr);exit(1) }
