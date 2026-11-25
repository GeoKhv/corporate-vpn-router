import AppKit
import CryptoKit
import Sparkle

func require(_ condition: Bool, _ label: String) {
    guard condition else { fputs("FAIL: \(label)\n", stderr); exit(1) }
}

func waitFor(_ label: String, _ predicate: () -> Bool) {
    let deadline = Date().addingTimeInterval(10)
    while !predicate() && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
    require(predicate(), label)
}

let args = Array(CommandLine.arguments.dropFirst())
let folder = URL(fileURLWithPath: args[1], isDirectory: true)
let current = folder.appendingPathComponent("appcast.xml")
if args[0] == "generate" {
    let key = Curve25519.Signing.PrivateKey()
    try key.publicKey.rawRepresentation.base64EncodedString().write(to: folder.appendingPathComponent("public-key.txt"), atomically: true, encoding: .utf8)
    for version in [25, 26, 27, 28] {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?><rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Recheck fixture</title><item><title>0.3.\(version)</title><sparkle:version>30\(version)</sparkle:version><sparkle:shortVersionString>0.3.\(version)</sparkle:shortVersionString><enclosure url="http://127.0.0.1:\(args[2])/must-not-download.zip" length="2" type="application/octet-stream"/></item></channel></rss>
        """
        let bytes = Data(xml.utf8)
        let signature = try key.signature(for: bytes).base64EncodedString()
        try (bytes + Data("<!-- sparkle-signatures:\nedSignature: \(signature)\nlength: \(bytes.count)\n-->\n".utf8))
            .write(to: folder.appendingPathComponent("\(version).xml"))
    }
    exit(0)
}

func offer(_ number: Int) throws {
    try Data(contentsOf: folder.appendingPathComponent("\(number).xml")).write(to: current, options: .atomic)
}

func button(_ title: String, in view: NSView) -> NSButton? {
    if let candidate = view as? NSButton, candidate.title == title { return candidate }
    return view.subviews.compactMap { button(title, in: $0) }.first
}

func choose(_ title: String, in driver: RouterUpdates) {
    let deadline = Date().addingTimeInterval(5)
    let timer = Timer(timeInterval: 0.05, repeats: true) { timer in
        if let view = NSApp.modalWindow?.contentView, let option = button(title, in: view) {
            timer.invalidate()
            option.performClick(nil)
        } else if Date() > deadline {
            timer.invalidate()
            fputs("FAIL: missing button \(title)\n", stderr)
            exit(1)
        }
    }
    RunLoop.main.add(timer, forMode: .modalPanel)
    driver.installButton.performClick(nil)
    timer.invalidate()
}

var calendar = Calendar(identifier: .gregorian)
calendar.timeZone = TimeZone(secondsFromGMT: 10800)!
let checked = calendar.date(from: DateComponents(year: 2026, month: 11, day: 25, hour: 23, minute: 59))!
for (minutes, day) in [(0, "сегодня"), (1, "вчера"), (1442, "25.11.2026")] {
    let text = RouterUpdates.noUpdateMessage(checked: checked, now: checked.addingTimeInterval(Double(minutes * 60)), calendar: calendar)
    require(text.hasSuffix(day + " в 23:59"), "calendar-day boundary and original check time")
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let paths = ProductPaths(root: folder.appendingPathComponent("Home").path, systemApplications: folder.appendingPathComponent("SystemApps"))
try paths.createData()
let owner = BetaMenu(paths: paths)
let driver = RouterUpdates(owner: owner)
let background = args[0] == "background"
if background { try offer(25) }
driver.start(menu: NSMenu())

if background {
    require(driver.updater.automaticallyChecksForUpdates, "automatic checks enabled for the fixture")
    require(!driver.button.isEnabled, "button disabled while startup check runs")
    waitFor("Sparkle finishes startup check on the current version") {
        driver.updater.lastUpdateCheckDate != nil && driver.updater.canCheckForUpdates && !driver.updater.sessionInProgress
    }
    waitFor("button and menu become enabled after a background check") {
        driver.button.isEnabled && driver.checkItem.isEnabled
    }
    require(driver.button.title == "Проверить обновления", "idle button names its action")
    require(driver.resultLabel.stringValue.contains("проверено сегодня в "), "background success dates the result")
    try offer(26)
    driver.button.performClick(nil)
} else {
    try offer(25)
    driver.button.performClick(nil)
    require(driver.button.title == "Проверяем…", "immediate feedback on manual check")
    waitFor("dated result and available retry") {
        driver.button.title == "Проверить обновления" && driver.button.isEnabled &&
        driver.resultLabel.stringValue.contains("Обновлений нет · проверено сегодня в ")
    }
    try offer(26)
    driver.button.performClick(nil)
}
waitFor("initial 0.3.26 offer") { driver.version == "0.3.26" && driver.foundReply != nil }
require(driver.button.title == "Проверить обновления" && !driver.installButton.isHidden, "check and install remain distinct")
try offer(27)
choose("Проверить снова", in: driver)
waitFor("dialog replaces stale offer with 0.3.27") { driver.version == "0.3.27" && driver.foundReply != nil }
try offer(28)
driver.check()
waitFor("menu check offers 0.3.28") { driver.version == "0.3.28" && driver.foundReply != nil }
choose("Отмена", in: driver)
waitFor("Cancel clears the offer and restores the check button") {
    driver.foundReply == nil && !driver.updater.sessionInProgress && driver.button.isEnabled
}
driver.button.performClick(nil)
waitFor("cancelled version can still be offered") { driver.version == "0.3.28" && driver.foundReply != nil }
require(!driver.installationRequested && !driver.preparing && !driver.cleanupReady, "no installation authorized")
driver.cancelForQuit()
print("PASS \(args[0]): button and menu can check again, held offers refresh, no installation")
