import AppKit
import Darwin

func check(_ condition: @autoclosure () throws -> Bool) rethrows {
    let passed = try condition(); assert(passed)
}

let fm = FileManager.default
let root = fm.temporaryDirectory.appendingPathComponent("cvr-locations-" + UUID().uuidString)
let home = root.appendingPathComponent("home")
let shared = root.appendingPathComponent("Applications")
let source = URL(fileURLWithPath: CommandLine.arguments[1])
let original = URL(fileURLWithPath: CommandLine.arguments[2])
try fm.createDirectory(at: home, withIntermediateDirectories: true)
try fm.createDirectory(at: shared, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: root) }
let sharedApp = shared.appendingPathComponent(AppInstallation.appName)
let userApp = home.appendingPathComponent("Applications/" + AppInstallation.appName)
assert(AppInstallation.destination(home: home, systemApplications: shared).path == userApp.path)
try fm.copyItem(at: original, to: sharedApp)
let paths = ProductPaths(root: home.path, systemApplications: shared)
assert(paths.app.standardizedFileURL.path == sharedApp.standardizedFileURL.path)
try check(try BetaInstall.isInstalledCopy(sharedApp, paths))
try paths.createData()
try BetaInstall.registerLogin(paths)
let agent = try BetaInstall.checkedAgent(paths)
let bytes = try Data(contentsOf: agent)
let plist = try PropertyListSerialization.propertyList(from: bytes, format: nil) as! [String:Any]
assert(plist["ProgramArguments"] as! [String] == [sharedApp.appendingPathComponent("Contents/MacOS/CorporateVPNRouter").path,"--login"])
assert((BrowserRouter.agentSpec(paths)["ProgramArguments"] as! [String]).first!.hasPrefix(sharedApp.path + "/Contents/Resources/"))
assert(!fm.fileExists(atPath: userApp.path))
print("PASS system-folder app recognizes itself; menu and HTTP login paths target that same app; no duplicate user app")

let policy = paths.data.appendingPathComponent("work-sites.json")
try Data("preserve-existing-private-data".utf8).write(to: policy)
let lockFD = try AppInstallation.lock(paths.data.appendingPathComponent("menu.lock"), busy: "test")
do {
    _ = try AppInstallation.install(source: source, home: home, systemApplications: shared)
    assertionFailure("running app update must refuse")
} catch {
    assert(error.localizedDescription.contains("VPN-сеанс сохранён"))
}
close(lockFD)
let before = try Data(contentsOf: sharedApp.appendingPathComponent("Contents/_CodeSignature/CodeResources"))
_ = try AppInstallation.install(source: source, home: home, systemApplications: shared)
try check(try Data(contentsOf: agent) == bytes)
try check(try String(contentsOf: policy) == "preserve-existing-private-data")
assert(!fm.fileExists(atPath: userApp.path))
let backups = try fm.contentsOfDirectory(at: paths.data, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("rollback-") }
assert(backups.count == 1)
try check(try Data(contentsOf: backups[0].appendingPathComponent("Contents/_CodeSignature/CodeResources")) == before)
try AppInstallation.verify(backups[0])
try AppInstallation.verify(sharedApp)
try check(try BetaInstall.isInstalledCopy(source, ProductPaths(root: home.path, systemApplications: shared)))
print("PASS shared-location busy refusal, transactional update, exact original signed backup and settings/login preservation")

// Gatekeeper may execute a translocated copy with the same signed resources.
let translocated = root.appendingPathComponent("relocated.app")
try fm.copyItem(at: sharedApp, to: translocated)
try check(try BetaInstall.isInstalledCopy(translocated, ProductPaths(root: home.path, systemApplications: shared)))
print("PASS signed relocated copy resolves to the existing shared installation")

try fm.createDirectory(at: userApp.deletingLastPathComponent(), withIntermediateDirectories: true)
try fm.copyItem(at: source, to: userApp)
do {
    _ = try AppInstallation.install(source: source, home: home, systemApplications: shared)
    assertionFailure("two real destinations must not silently replace either")
} catch {}
assert(fm.fileExists(atPath: userApp.path) && fm.fileExists(atPath: sharedApp.path))
try check(try Data(contentsOf: agent) == bytes)
try check(try String(contentsOf: policy) == "preserve-existing-private-data")
print("PASS two actual locations refuse without deleting either app or changing settings")
