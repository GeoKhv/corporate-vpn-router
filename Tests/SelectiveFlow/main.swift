import AppKit

func check(_ condition: @autoclosure () -> Bool, _ message: String, line: UInt = #line) {
    if !condition() { fputs("FAIL line \(line): \(message)\n", stderr); exit(1) }
}
func until(line: UInt = #line, _ predicate: () -> Bool) {
    let end = Date().addingTimeInterval(12)
    while !predicate() && Date() < end { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    check(predicate(), "operation timed out at caller \(line)")
}
func run() throws {
    let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cvr-flow-"+UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let paths = ProductPaths(root: root.path), app = NSApplication.shared
    app.setActivationPolicy(.prohibited)
    let menu = BetaMenu(paths: paths)
    menu.selective.inspectHelper = { _ in .ready }
    menu.selective.inspectCleanup = { _ in true }
    let res = menu.resources, fm = FileManager.default
    try fm.createDirectory(at: res.appendingPathComponent("Runtime/bin"), withIntermediateDirectories: true)
    try fm.createDirectory(at: res.appendingPathComponent("Engine/Selective"), withIntermediateDirectories: true)
    let runtime = res.appendingPathComponent("Runtime/bin/python3.13")
    try "#!/bin/sh\nexec /usr/bin/python3 \"$@\"\n".write(to: runtime, atomically: true, encoding: .utf8)
    try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runtime.path)
    try #"""
import json,sys,time
from pathlib import Path
base=Path(__file__).resolve().parent.parent
mode=(base/'scenario').read_text()
def emit(**v):print(json.dumps(v),flush=True)
if mode=='slow':time.sleep(.4)
if mode=='route_failure':
 emit(state='error',message='FIXTURE_ROUTE_REJECTED',code='FIXTURE_ROUTE_REJECTED',cleanupConfirmed=True)
else:
 if mode=='site_choice':
  emit(state='selectingSite',message='choose',sites=['gateway.invalid','other.invalid'])
  assert json.loads(sys.stdin.readline())=={'site':'gateway.invalid'}
 emit(state='awaitingTunnel',message='fixture waiting for tunnel',gateway='gateway.invalid@192.0.2.1')
 if sys.stdin.readline()=='activate\n':
  with (base/'activations').open('a') as f:f.write(mode+'\n')
  if mode=='stopped_during_activation':
   emit(state='stopped',message='fixture stopped',cleanupConfirmed=True);sys.exit(0)
  elif mode=='activation_failure':emit(state='error',message='FIXTURE_PUBLISH_FAILED',code='FIXTURE_PUBLISH_FAILED',cleanupConfirmed=False)
  else:emit(state='ready',message='fixture routes ready')
sys.stdin.read()
emit(state='stopped',message='Рабочие маршруты удалены.',cleanupConfirmed=True)
"""#.write(to: res.appendingPathComponent("Engine/Selective/controller.py"), atomically: true, encoding: .utf8)
    try #"""
import json,sys,time
from pathlib import Path
base=Path(__file__).resolve().parent
mode=(base/'scenario').read_text()
import os
assert os.environ['CVR_ATTEMPT_GATEWAY']=='gateway.invalid@192.0.2.1'
with (base/'starts').open('a') as f:f.write('start\n')
def emit(**v):print(json.dumps(v),flush=True)
def ask(kind,**fields):
 emit(request=kind,prompt='fixture',**fields)
 return json.loads(sys.stdin.readline())
emit(stage='verifying_gateway')
if mode=='first':assert ask('trust')=='accept'
if mode=='alternate':assert ask('gateway_fingerprint')=='fixture-fingerprint'
if mode=='gateway_failure':
 emit(stage='failed',code='SSLCertVerificationError');sys.exit(1)
if mode=='dns_timeout':
 emit(stage='gateway_dns_lookup');emit(stage='gateway_dns_retry',errno=8)
 emit(stage='failed',code='GATEWAY_DNS_TIMEOUT');sys.exit(1)
emit(stage='gateway_verified')
assert ask('username',site='gateway.invalid',pin='fixture',realm='otp')=='fixture-user'
assert ask('challenge')=='fixture-code'
emit(stage='authenticated')
if mode=='server_refusal':
 emit(stage='server_disconnect',server_code=-123)
 emit(stage='failed',code='SSL_SESSION_REFUSED',failed_phase='server_disconnect',server_code=-123)
 sys.exit(1)
emit(stage='connected')
sys.stdin.read()
"""#.write(to: res.appendingPathComponent("Engine/session.py"), atomically: true, encoding: .utf8)
    app.delegate = menu; app.finishLaunching()
    if menu.window == nil { menu.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification)) }
    check(menu.logsButton.window === menu.diagnostics && menu.logsButton.isEnabled &&
          menu.logsButton.target === menu && menu.logsButton.action == #selector(BetaMenu.exportLogs),
          "offline diagnostics must expose the log export button")
    menu.hiddenByUser = true; menu.window.orderOut(nil)
    until { menu.selective.helperAvailability == .ready }
    try JSONFile.write(WorkProfile(sites: [WorkSite(domain: "work.example.invalid", scope: "tree")]), to: menu.workURL)
    try JSONFile.write(["hosts":["owa.work.example.invalid"]], to: paths.data.appendingPathComponent("certificate-endpoints.json"))
    try "import sys\nassert sys.flags.dont_write_bytecode\nfrom pathlib import Path\nprint({'owa.work.example.invalid':('ok' if Path(__file__).resolve().parents[1].joinpath('repaired').exists() else 'missing'), 'wiki.work.example.invalid':'ok'}[sys.argv[1]])".write(
        to: res.appendingPathComponent("Engine/Selective/system_dns_check.py"), atomically: true, encoding: .utf8)
    menu.method.selectedSegment = 0; menu.changeMethod()
    func begin(_ scenario: String) throws {
        try scenario.write(to: res.appendingPathComponent("Engine/scenario"), atomically: true, encoding: .utf8)
        menu.loginDraft.stringValue = "fixture-user"; menu.toggle()
    }
    var testedSiteLink = false
    func finishMFA() {
        until { menu.requestKind == "challenge" }
        menu.secret.stringValue = "fixture-code"; menu.answer()
        until { menu.connectionPhase == .connected }
        until { menu.findings["DNS macOS"]?.health == .error }
        check(menu.detail.stringValue.contains("macOS не находит owa.work.example.invalid"), "confirmed DNS failure must be visible while connected")
        check(!menu.siteHelpButton.isHidden && menu.siteHelpButton.action == #selector(BetaMenu.checkSiteAddress), "site troubleshooting is available from the connected window")
        if !testedSiteLink {
            var calls = 0
            let repaired = res.appendingPathComponent("Engine/repaired")
            menu.refreshMacDNS = { false }
            menu.repairDNSButton.performClick(nil)
            until { menu.findings["DNS macOS"]?.text.contains("Обновление DNS не выполнено") == true }
            check(menu.repairDNSButton.isEnabled && !menu.repairDNSButton.isHidden, "cancelled authorization offers retry")
            menu.refreshMacDNS = { calls += 1; return FileManager.default.createFile(atPath: repaired.path, contents: nil) }
            check(!menu.repairDNSButton.isHidden, "confirmed mismatch offers repair")
            menu.repairDNSButton.performClick(nil)
            until { menu.findings["DNS macOS"]?.health == .ready }
            check(calls == 1 && menu.repairDNSButton.isHidden, "repair requires one authorization and rechecks the same host")
            try! FileManager.default.removeItem(at: repaired)
            testedSiteLink = true
            let input = Timer(timeInterval: 0.1, repeats: false) { _ in
                guard let modal = NSApp.modalWindow,
                      let editor = modal.firstResponder as? NSTextView else {
                    NSApp.stopModal(withCode: .alertSecondButtonReturn)
                    return
                }
                editor.string = "https://wiki.work.example.invalid/project?private=ignored"
                modal.makeFirstResponder(nil)
                NSApp.stopModal(withCode: .alertFirstButtonReturn)
            }
            RunLoop.main.add(input, forMode: .modalPanel)
            menu.siteHelpButton.performClick(nil)
            until { menu.findings["DNS macOS"]?.health == .ready }
            check(menu.diagRows["DNS macOS"]!.1.stringValue.contains("wiki.work.example.invalid"), "manual check uses the site from the pasted URL")
            menu.diagnostics.orderOut(nil)
        }
        check(menu.settingsWindow == nil, "connection must apply the saved profile without opening work sites")
        check(menu.health == .ready && menu.setupBrowser.isHidden, "one action must reach MFA and hide separate route control")
        menu.toggle(); until { menu.connectionPhase == .idle && menu.engine == nil && menu.selective.process == nil }
        check(menu.selective.cleanupConfirmed, "cleanup must complete before retry")
    }
    let idle = "Conn a.invalid:\n  gw: 192.0.2.1\n  status: Idle\n"
    let other = idle.replacingOccurrences(of:"a.invalid",with:"b.invalid")
    check(OfficialGUI.allSitesIdle(idle+other), "all idle sites can hand off")
    check(!OfficialGUI.allSitesIdle(idle+other.replacingOccurrences(of:"Idle",with:"Connected")), "preserve another active connection")
    check(!OfficialGUI.allSitesIdle(idle+other.replacingOccurrences(of:"Conn ",with:"CONN\t").replacingOccurrences(of:"status: Idle",with:"STATUS: Connected")), "alternate spelling must not hide an active site")
    check(!OfficialGUI.allSitesIdle("Conn incomplete.invalid:\n"+other), "missing status is not idle")
    var authorizations = 0
    menu.selective.authorizeHelper = { _ in authorizations += 1; return "unexpected authorization" }
    for availability: RouteHelperAvailability in [.missing, .updateRequired, .repairRequired, .unavailable, .checkFailed] {
        menu.selective.inspectHelper = { _ in availability }
        try begin("repeat")
        until { menu.connectionPhase == .failed }
        check(authorizations == 0 && menu.engine == nil && menu.selective.process == nil,
              "Connect must never install/repair on \(availability)")
        check(menu.selective.cleanupConfirmed, "failed probe leaves network untouched")
    }
    for availability: RouteHelperAvailability in [.unavailable, .checkFailed, .ready] {
        menu.selective.inspectHelper = { _ in availability }
        menu.selective.helperAvailability = .missing // stale UI must not authorize an install
        menu.selective.manageHelper(resources: res)
        check(authorizations == 0, "maintenance rechecks evidence before elevation")
    }
    let healthy: [String: Any] = ["ok":true, "version":"0.3.0-alpha.3", "build":"0.3.10", "active":false, "cleanupPending":false]
    check(SelectiveRouter.classifyReply(healthy) == .ready, "compatible broker build and protocol")
    var legacy = healthy; legacy.removeValue(forKey:"build")
    check(SelectiveRouter.classifyReply(legacy) == .updateRequired, "an idle legacy broker must be upgraded")
    legacy["active"] = true
    check(SelectiveRouter.classifyReply(legacy) == .previousSession, "an active legacy broker must be left alone")
    var pending = healthy; pending["cleanupPending"] = true
    check(SelectiveRouter.classifyReply(pending) == .previousSession, "pending cleanup blocks a new session")
    var mismatch = healthy; mismatch["version"] = "0.4.0"
    check(SelectiveRouter.classifyReply(mismatch) == .updateRequired, "positive protocol mismatch")
    check(SelectiveRouter.classifyReply(["ok":true]) == .checkFailed, "missing version is not an upgrade")
    check(SelectiveRouter.classifyReply(["ok":false,"error":"CALLER_REJECTED"]) == .checkFailed, "caller rejection is not absence")
    check(SelectiveRouter.classifyReply(["ok":false,"error":"HELPER_UNAVAILABLE"]) == .unavailable, "XPC loss is temporary")
    menu.selective.inspectHelper = { _ in .ready }
    try begin("first")
    until { menu.requestKind == "trust" }
    let activations = res.appendingPathComponent("Engine/activations")
    check(!fm.fileExists(atPath: activations.path), "gateway verification must precede all routing")
    menu.answer(); finishMFA()
    try begin("alternate"); until { menu.requestKind == "gateway_fingerprint" }
    menu.secret.stringValue = "fixture-fingerprint"; menu.answer(); finishMFA()
    try begin("repeat"); finishMFA()
    var choices = 0
    menu.selective.chooseSite = { sites, reply in
        check(sites == ["gateway.invalid","other.invalid"], "choice contains configured sites")
        choices += 1; reply("gateway.invalid")
    }
    try begin("site_choice"); finishMFA()
    check(choices == 1, "ambiguous selection resumes the same connection attempt")
    let completed = try String(contentsOf: activations)
    try begin("server_refusal")
    until { menu.requestKind == "challenge" }
    menu.secret.stringValue = "fixture-code"; menu.answer()
    until { menu.connectionPhase == .failed && menu.engine == nil && menu.selective.process == nil }
    check(menu.connectionFailure?.contains("-123") == true, "preserve the gateway refusal code through cleanup")
    check(try! String(contentsOf: activations) == completed, "server refusal must not activate routes")
    let events = try String(contentsOf: paths.data.appendingPathComponent("Selective/connection-events.jsonl"))
    check(events.contains("\"server_code\":-123"), "numeric server reason must survive into the journal")
    try begin("cancel_mfa"); until { menu.requestKind == "challenge" }; menu.toggle()
    until { menu.connectionPhase == .idle && menu.engine == nil && menu.selective.process == nil }
    check(try! String(contentsOf: activations) == completed, "cancelled MFA must never activate routes")
    try begin("gateway_failure")
    until { menu.connectionPhase == .failed && menu.engine == nil && menu.selective.process == nil }
    check(menu.connectionPhase == .failed && menu.health == .error, "gateway failure must remain an error after cleanup")
    check(menu.note.contains("сертификата шлюза") && !menu.note.contains("маршруты удалены"), "cleanup must not overwrite TLS failure")
    check(menu.connectionFailureCode == "SSLCertVerificationError" && menu.selective.cleanupConfirmed, "precise failure and verified cleanup")
    check(try! String(contentsOf: activations) == completed, "failed authentication must never activate routes")
    try begin("dns_timeout")
    until { menu.connectionPhase == .failed && menu.engine == nil && menu.selective.process == nil }
    check(menu.detail.stringValue.contains("ожидания DNS") && menu.primary.isEnabled, "DNS cause and retry must remain visible after cleanup")
    check(try! String(contentsOf: activations) == completed, "DNS failure must stop before route activation")
    try begin("activation_failure"); until { menu.requestKind == "challenge" }
    menu.secret.stringValue = "fixture-code"; menu.answer()
    until { menu.connectionPhase == .failed && menu.engine == nil && menu.selective.process == nil }
    check(menu.connectionFailureCode == "FIXTURE_PUBLISH_FAILED", "post-MFA route failure must stop both processes")
    try begin("stopped_during_activation"); until { menu.requestKind == "challenge" }
    menu.secret.stringValue = "fixture-code"; menu.answer()
    until { menu.connectionPhase == .failed && menu.engine == nil && menu.selective.process == nil }
    check(menu.connectionFailureCode == "ROUTES_LOST", "unexpected controller stop during activation must close tunnel")
    try begin("repeat"); finishMFA()
    try begin("route_failure")
    until { menu.connectionPhase == .failed && menu.selective.process == nil }
    check(menu.connectionPhase == .failed && menu.connectionFailureCode == "FIXTURE_ROUTE_REJECTED", "route startup failure must survive cleanup")
    let before = try String(contentsOf: res.appendingPathComponent("Engine/starts"))
    try begin("slow"); until { menu.connectionPhase == .preparingRoutes }; menu.toggle()
    until { menu.connectionPhase == .idle && menu.selective.process == nil }
    check(try! String(contentsOf: res.appendingPathComponent("Engine/starts")) == before, "cancel before readiness must not start late MFA")
    let log = try String(contentsOf: paths.data.appendingPathComponent("Selective/connection-events.jsonl"))
    check(log.contains("SSLCertVerificationError") && log.contains("FIXTURE_ROUTE_REJECTED"), "failure codes are journaled")
    check(!log.contains("fixture-user") && !log.contains("fixture-code") && !log.contains("fixture-fingerprint") && !log.contains("gateway.invalid"), "journal excludes secrets and identity")
    check(authorizations == 0, "all normal connections are independent of cached admin authorization")
    print("PASS one-click first trust/MFA and repeat; gateway failure; preserved error through cleanup; retry; route failure; cancellation race; private journal")
}
do { try run() } catch { fputs("FAIL \(error)\n", stderr); exit(1) }
