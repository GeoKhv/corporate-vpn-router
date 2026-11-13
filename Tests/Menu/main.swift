import AppKit

func check(_ condition: @autoclosure () -> Bool, _ message: @autoclosure () -> String = "", line: UInt = #line) {
    if !condition() { fputs("FAIL Tests/Menu/main.swift:\(line): \(message())\n", stderr); exit(1) }
}

func runTests() throws {

let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
let paths = ProductPaths(root: root.path)
defer { try? FileManager.default.removeItem(at: root) }
let application = NSApplication.shared
application.setActivationPolicy(.prohibited)
let menu = BetaMenu(paths: paths)
#if CVR_SELECTIVE_TUN
// Exercise first use without touching the real system helper or asking for admin.
menu.selective.inspectHelper = { _ in .missing }
#endif
application.delegate = menu
application.finishLaunching()
if menu.window == nil { menu.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification)) }
#if CVR_SELECTIVE_TUN
func until(_ predicate: () -> Bool) {
    let deadline = Date().addingTimeInterval(8)
    while !predicate() && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    check(predicate(), "asynchronous UI operation did not finish")
}
until { menu.selective.helperAvailability == .missing }
check(menu.setupBrowser.title == "Установить помощник маршрутов…" && menu.setupBrowser.isEnabled && menu.primary.isEnabled)
check(menu.window.isVisible && menu.detail.stringValue.contains("не установлен"))
var authorizationCalls = 0
let releaseAuthorization = DispatchSemaphore(value: 0)
menu.selective.authorizeHelper = { arguments in
    authorizationCalls += 1
    check(arguments[1] == SelectiveRouter.authorizationScript && arguments[2].contains(" --install "))
    _ = releaseAuthorization.wait(timeout: .now() + 8)
    return "User canceled. (-128)"
}
menu.selective.manageHelper(resources: menu.resources)
check(!menu.setupBrowser.isEnabled && !menu.primary.isEnabled && menu.stage == "Настройка маршрутов", "Standalone helper maintenance must prevent a concurrent connection")
menu.selective.manageHelper(resources: menu.resources) // A double click must not launch a second request.
menu.window.orderOut(nil)
releaseAuthorization.signal()
until { menu.selective.state == "error" }
check(authorizationCalls == 1 && menu.window.isVisible && menu.note.contains("отменены"))
check(menu.setupBrowser.title == "Установить помощник маршрутов…" && menu.setupBrowser.isEnabled)
menu.selective.authorizeHelper = { _ in "Fixture install failure" }
menu.selective.manageHelper(resources: menu.resources)
until { menu.selective.state == "error" }
check(menu.note.contains("Fixture install failure") && menu.window.isVisible)
menu.selective.authorizeHelper = { _ in authorizationCalls += 1; return nil }
for availability: RouteHelperAvailability in [.unavailable, .checkFailed, .ready] {
    menu.selective.inspectHelper = { _ in availability }
    menu.selective.manageHelper(resources: menu.resources)
    check(authorizationCalls == 1, "Failed or unnecessary maintenance must not elevate")
}
menu.selective.inspectHelper = { _ in .unavailable }
menu.selective.checkHelper(resources: menu.resources)
until { menu.selective.helperAvailability == .unavailable }
check(menu.setupBrowser.title == "Повторить проверку помощника" && menu.primary.isEnabled)
menu.selective.inspectHelper = { _ in .ready }
menu.appRouting()
until { menu.selective.helperAvailability == .ready }
check(authorizationCalls == 1 && menu.note.contains("Всё готово"))
menu.selective.inspectHelper = { _ in .updateRequired }
menu.selective.checkHelper(resources: menu.resources)
until { menu.selective.helperAvailability == .updateRequired }
check(menu.setupBrowser.title == "Обновить помощник маршрутов…" && menu.primary.isEnabled)
menu.selective.inspectHelper = { _ in .ready }
menu.selective.manageHelper(resources: menu.resources)
check(authorizationCalls == 1 && menu.primary.isEnabled)

// Compile the exact privileged script, then execute its argv/shell handoff
// without the privilege clause against a harmless executable with a hostile path.
let scriptURL = root.appendingPathComponent("authorization.applescript")
try SelectiveRouter.authorizationScript.write(to: scriptURL, atomically: true, encoding: .utf8)
let compiled = command("/usr/bin/osacompile", ["-o", root.appendingPathComponent("authorization.scpt").path, scriptURL.path])
check(compiled.code == 0, compiled.output)
let strangeResources = root.appendingPathComponent("Тест ' \" \\ $() `echo bad` /Resources")
let helperURL = strangeResources.appendingPathComponent("RouteHelper/RouteHelper")
try FileManager.default.createDirectory(at: helperURL.deletingLastPathComponent(), withIntermediateDirectories: true)
try "#!/bin/sh\nprintf '%s\\n' \"$@\"\n".write(to: helperURL, atomically: true, encoding: .utf8)
try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helperURL.path)
for remove in [false, true] {
    var args = SelectiveRouter.authorizationArguments(resources: strangeResources, remove: remove)
    args[1] = args[1].replacingOccurrences(of: " with administrator privileges with prompt (item 2 of argv)", with: "")
    let result = command("/usr/bin/osascript", args, timeout: 10)
    check(result.code == 0 && result.output.replacingOccurrences(of: "\r", with: "\n").trimmingCharacters(in: .whitespacesAndNewlines) == (remove ? "--uninstall" : "--install\n\(getuid())"), result.output)
}
print("PASS first-use helper button, cancel/retry, errors, failed verification, update, successful verification, visible window, duplicate-action guard; actual AppleScript compilation and safe argv/shell handoff.")
#endif
let scope = LoginScope(site:"gateway.invalid",pin:"fixture",realm:"otp")
let other = LoginScope(site:"gateway.invalid",pin:"fixture",realm:"other")
// First use must expose entry before gateway/network setup, without persisting
// a draft or sending it until a verified, scoped engine request arrives.
menu.method.selectedSegment = 0; menu.changeMethod()
check(!menu.loginDraft.isHidden && menu.engine == nil)
menu.connect()
check(menu.engine == nil && !menu.loginDraft.isHidden && menu.attemptLogin == nil)
menu.loginDraft.stringValue = "  first-draft  "
let firstPrepared = menu.prepareLogin()
check(firstPrepared && menu.book.accounts.isEmpty)
let draftStatus = try String(contentsOf:menu.runtimeState)
check(!draftStatus.contains("first-draft"))
let waiting = Process(); waiting.executableURL = URL(fileURLWithPath:"/bin/sleep"); waiting.arguments = ["30"]
try waiting.run()
let channel = Pipe(); menu.engine = waiting; menu.input = channel.fileHandleForWriting
menu.event(["request":"username", "site":scope.site, "pin":scope.pin, "realm":scope.realm],waiting)
try channel.fileHandleForWriting.close(); menu.input=nil
let response = try channel.fileHandleForReading.readToEnd()!
let sentLogin = try JSONDecoder().decode(String.self,from:response)
check(sentLogin == "first-draft")
check(menu.book.accounts.isEmpty && menu.pendingLogin == "first-draft")
menu.event(["stage":"authenticated"],waiting)
check(menu.book.accounts.first?.scope == scope && menu.book.accounts.first?.username == "first-draft")
check(menu.loginDraft.stringValue.isEmpty)
waiting.terminate(); waiting.waitUntilExit(); menu.engine=nil; menu.input=nil
try menu.book.set(nil,for:scope); menu.activeScope=nil; menu.refresh()
check(!menu.loginDraft.isHidden)
menu.method.selectedSegment=1; menu.changeMethod()
let browserPrepared = menu.prepareLogin()
check(menu.loginDraft.isHidden && browserPrepared && menu.attemptLogin == nil)
menu.method.selectedSegment=0; menu.changeMethod()
try menu.book.set("first-user", for:scope)
try menu.book.set("second-user", for:other)
check(menu.book.accounts.count == 2)
try menu.book.set("updated-user",for:scope)
check(menu.book.accounts.first(where:{$0.scope == scope})?.username == "updated-user")
check(menu.book.accounts.first(where:{$0.scope == other})?.username == "second-user")
menu.activeScope=scope; menu.refresh(); menu.changeLogin()
check(!menu.loginDraft.isHidden && menu.loginDraft.stringValue == "updated-user")
menu.loginDraft.stringValue="replacement-user"; let editedPrepared = menu.prepareLogin(); check(editedPrepared)
check(menu.book.accounts.first(where:{$0.scope == scope})?.username == "updated-user")
menu.event(["stage":"failed","code":"OFFICIAL_SERVICE_NOT_STARTED"],Process())
check(menu.note.contains("Check Point сообщил") && menu.attemptLogin == nil)
check(menu.book.accounts.first(where:{$0.scope == scope})?.username == "updated-user")
menu.editingLogin=false; menu.loginDraft.stringValue=""
check(try! FileManager.default.attributesOfItem(atPath:menu.book.url.path)[.posixPermissions] as? Int == 0o600)
menu.show()
menu.diagnose()
menu.diagnostics.performClose(nil)
check(menu.window.isVisible && !menu.diagnostics.isVisible)
menu.window.performClose(nil)
check(!menu.window.isVisible)
menu.show()
let event = NSEvent.keyEvent(with:.keyDown,location:.zero,modifierFlags:.command,timestamp:0,windowNumber:menu.window.windowNumber,
    context:nil,characters:"w",charactersIgnoringModifiers:"w",isARepeat:false,keyCode:13)!
check(menu.window.performKeyEquivalent(with:event) && !menu.window.isVisible)
menu.show()
menu.requestKind = "secret"; menu.username.isHidden = true; menu.secretRow.isHidden = false
menu.promptLabel.stringValue = "Введите одноразовый код"; menu.stage = "Ожидание входа"; menu.health = .waiting; menu.refresh()
menu.secret.stringValue = "synthetic-paste"
menu.secret.hideEcho()
menu.clearPrompt()
check(menu.secret.stringValue == "")
menu.windowDidResignKey(Notification(name:NSWindow.didResignKeyNotification))
let status = try String(contentsOf:menu.runtimeState)
check(!status.contains("synthetic-paste") && !status.contains("updated-user"))
menu.engine = Process() // Represent an active worker in the appearance fixture.
var hashes = [Data]()
for theme in [NSAppearance.Name.aqua, .darkAqua] {
    menu.window.appearance = NSAppearance(named:theme)
    menu.health = .ready; menu.stage = "Подключено"; menu.note = "SOCKS5h доступен на 127.0.0.1:1090."; menu.refresh()
    menu.window.displayIfNeeded()
    let v = menu.window.contentView!
    let rep = v.bitmapImageRepForCachingDisplay(in:v.bounds)!
    v.cacheDisplay(in:v.bounds,to:rep)
    let composite = NSImage(size:v.bounds.size, flipped:false) { bounds in
        menu.window.effectiveAppearance.performAsCurrentDrawingAppearance {
            NSColor.windowBackgroundColor.setFill()
            bounds.fill()
            rep.draw(in:bounds)
        }
        return true
    }
    let png = NSBitmapImageRep(data:composite.tiffRepresentation!)!.representation(using:.png,properties:[:])!
    hashes.append(png)
    if let dir = ProcessInfo.processInfo.environment["CVR_TEST_PREVIEWS"] {
        // Capture this fixture window only, including AppKit materials.
        menu.show()
        RunLoop.current.run(until:Date().addingTimeInterval(0.25))
        let name = theme == .aqua ? "light.png" : "dark.png"
        let path = URL(fileURLWithPath:dir).appendingPathComponent(name).path
        let capture = Process()
        capture.executableURL = URL(fileURLWithPath:"/usr/sbin/screencapture")
        capture.arguments = ["-x", "-o", "-l", String(menu.window.windowNumber), path]
        try capture.run(); capture.waitUntilExit()
        check(capture.terminationStatus == 0)
    }
}
check(hashes.count == 2 && hashes[0] != hashes[1])
print("PASS first-use login entry, scoped submission, post-auth-only persistence, method isolation, editable saved login, service error, private diagnostics, existing menu behavior and light/dark rendering.")

}
do { try runTests() } catch { fputs("FAIL menu tests: \(error)\n", stderr); exit(1) }
