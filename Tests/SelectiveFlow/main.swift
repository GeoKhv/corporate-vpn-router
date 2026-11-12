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
else:emit(state='ready',message='fixture routes ready')
sys.stdin.read()
emit(state='stopped',message='Рабочие маршруты удалены.',cleanupConfirmed=True)
"""#.write(to: res.appendingPathComponent("Engine/Selective/controller.py"), atomically: true, encoding: .utf8)
    try #"""
import json,sys,time
from pathlib import Path
base=Path(__file__).resolve().parent
mode=(base/'scenario').read_text()
with (base/'starts').open('a') as f:f.write('start\n')
def emit(**v):print(json.dumps(v),flush=True)
def ask(kind,**fields):
 emit(request=kind,prompt='fixture',**fields)
 return json.loads(sys.stdin.readline())
emit(stage='verifying_gateway')
if mode=='first':assert ask('trust')=='accept'
if mode=='gateway_failure':
 emit(stage='failed',code='SSLCertVerificationError');sys.exit(1)
emit(stage='gateway_verified')
assert ask('username',site='gateway.invalid',pin='fixture',realm='otp')=='fixture-user'
assert ask('challenge')=='fixture-code'
emit(stage='authenticated');emit(stage='connected')
sys.stdin.read()
"""#.write(to: res.appendingPathComponent("Engine/session.py"), atomically: true, encoding: .utf8)
    app.delegate = menu; app.finishLaunching()
    if menu.window == nil { menu.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification)) }
    menu.hiddenByUser = true; menu.window.orderOut(nil)
    until { menu.selective.helperAvailability == .ready }
    try JSONFile.write(WorkProfile(sites: [WorkSite(domain: "work.example.invalid", scope: "tree")]), to: menu.workURL)
    menu.method.selectedSegment = 0; menu.changeMethod()
    func begin(_ scenario: String) throws {
        try scenario.write(to: res.appendingPathComponent("Engine/scenario"), atomically: true, encoding: .utf8)
        menu.loginDraft.stringValue = "fixture-user"; menu.toggle()
    }
    func finishMFA() {
        until { menu.requestKind == "challenge" }
        menu.secret.stringValue = "fixture-code"; menu.answer()
        until { menu.connectionPhase == .connected }
        check(menu.health == .ready && menu.setupBrowser.isHidden, "one action must reach MFA and hide separate route control")
        menu.toggle(); until { menu.connectionPhase == .idle && menu.engine == nil && menu.selective.process == nil }
        check(menu.selective.cleanupConfirmed, "cleanup must complete before retry")
    }
    try begin("first")
    until { menu.requestKind == "trust" }
    menu.answer(); finishMFA()
    try begin("repeat"); finishMFA()
    try begin("gateway_failure")
    until { menu.engine == nil && menu.selective.process == nil }
    check(menu.connectionPhase == .failed && menu.health == .error, "gateway failure must remain an error after cleanup")
    check(menu.note.contains("сертификата шлюза") && !menu.note.contains("маршруты удалены"), "cleanup must not overwrite TLS failure")
    check(menu.connectionFailureCode == "SSLCertVerificationError" && menu.selective.cleanupConfirmed, "precise failure and verified cleanup")
    try begin("repeat"); finishMFA()
    try begin("route_failure")
    until { menu.selective.process == nil }
    check(menu.connectionPhase == .failed && menu.connectionFailureCode == "FIXTURE_ROUTE_REJECTED", "route startup failure must survive cleanup")
    let before = try String(contentsOf: res.appendingPathComponent("Engine/starts"))
    try begin("slow"); menu.toggle()
    until { menu.connectionPhase == .idle && menu.selective.process == nil }
    check(try! String(contentsOf: res.appendingPathComponent("Engine/starts")) == before, "cancel before readiness must not start late MFA")
    let log = try String(contentsOf: paths.data.appendingPathComponent("Selective/connection-events.jsonl"))
    check(log.contains("SSLCertVerificationError") && log.contains("FIXTURE_ROUTE_REJECTED"), "failure codes are journaled")
    check(!log.contains("fixture-user") && !log.contains("fixture-code") && !log.contains("gateway.invalid"), "journal excludes secrets and identity")
    print("PASS one-click first trust/MFA and repeat; gateway failure; preserved error through cleanup; retry; route failure; cancellation race; private journal")
}
do { try run() } catch { fputs("FAIL \(error)\n", stderr); exit(1) }
