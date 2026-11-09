import AppKit

let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
let paths = ProductPaths(root: root.path)
defer { try? FileManager.default.removeItem(at: root) }
let application = NSApplication.shared
application.setActivationPolicy(.accessory)
let menu = BetaMenu(paths: paths)
application.delegate = menu
application.finishLaunching()
if menu.window == nil { menu.applicationDidFinishLaunching(Notification(name: NSApplication.didFinishLaunchingNotification)) }
let scope = LoginScope(site:"gateway.invalid",pin:"fixture",realm:"otp")
let other = LoginScope(site:"gateway.invalid",pin:"fixture",realm:"other")
try menu.book.set("first-user", for:scope)
try menu.book.set("second-user", for:other)
assert(menu.book.accounts.count == 2)
try menu.book.set("updated-user",for:scope)
assert(menu.book.accounts.first(where:{$0.scope == scope})?.username == "updated-user")
assert(menu.book.accounts.first(where:{$0.scope == other})?.username == "second-user")
assert(try! FileManager.default.attributesOfItem(atPath:menu.book.url.path)[.posixPermissions] as? Int == 0o600)
menu.show()
menu.diagnose()
menu.diagnostics.performClose(nil)
assert(menu.window.isVisible && !menu.diagnostics.isVisible)
menu.window.performClose(nil)
assert(!menu.window.isVisible)
menu.show()
let event = NSEvent.keyEvent(with:.keyDown,location:.zero,modifierFlags:.command,timestamp:0,windowNumber:menu.window.windowNumber,
    context:nil,characters:"w",charactersIgnoringModifiers:"w",isARepeat:false,keyCode:13)!
assert(menu.window.performKeyEquivalent(with:event) && !menu.window.isVisible)
menu.show()
menu.requestKind = "secret"; menu.username.isHidden = true; menu.secretRow.isHidden = false
menu.promptLabel.stringValue = "Введите одноразовый код"; menu.stage = "Ожидание входа"; menu.health = .waiting; menu.refresh()
menu.secret.stringValue = "synthetic-paste"
menu.glyph.typed("x"); assert(menu.glyph.character == "x")
RunLoop.current.run(until:Date().addingTimeInterval(1.08))
assert(menu.glyph.character == nil)
menu.glyph.typed("z"); menu.clearPrompt()
assert(menu.secret.stringValue == "" && menu.glyph.character == nil)
menu.glyph.typed("x"); menu.windowDidResignKey(Notification(name:NSWindow.didResignKeyNotification))
assert(menu.glyph.character == nil)
let status = try String(contentsOf:menu.runtimeState)
assert(!status.contains("synthetic-paste") && !status.contains("updated-user"))
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
        assert(capture.terminationStatus == 0)
    }
}
assert(hashes.count == 2 && hashes[0] != hashes[1])
print("PASS scoped visible login store, mode 0600, independent windows, Cmd+W, reopen, timed echo, clearing, safe diagnostics, light/dark rendering.")
