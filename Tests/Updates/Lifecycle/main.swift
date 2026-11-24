import AppKit
import Sparkle
let application=NSApplication.shared
let root=FileManager.default.temporaryDirectory.appendingPathComponent("cvr-update-lifecycle-"+UUID().uuidString)
let owner=BetaMenu(paths:ProductPaths(root:root.path))
let driver=RouterUpdates(owner:owner);owner.updates=driver
// A failed/aborted installer must revoke its cleanup authorization before a later session.
driver.cleanupReady=true;driver.preparing=true;driver.installationRequested=true
owner.terminationPending=true
driver.dismissUpdateInstallation()
assert(!driver.cleanupReady && !driver.preparing && !driver.installationRequested)
assert(owner.applicationShouldTerminate(application) == .terminateLater)
owner.terminationPending=false
assert(owner.applicationShouldTerminate(application) == .terminateNow)
print("PASS cancelled/failed installer revokes termination bypass for subsequent sessions")
// Runtime preference API used by the menu persists disabled checks, without auto downloading.
driver.updater.automaticallyChecksForUpdates=true
driver.toggleAutomatic();assert(!driver.updater.automaticallyChecksForUpdates)
let second=RouterUpdates(owner:owner)
assert(!second.updater.automaticallyChecksForUpdates)
assert(!second.updater.automaticallyDownloadsUpdates)
print("PASS disabled automatic checks persist across updater instances; automatic downloads remain disabled")

// Absence must be independently confirmed by both launchd and persistent state.
let jobLabel = "com.example.router-cleanup-test"
let absentJob = CommandResult(code:113, output:"Could not find service \"" + jobLabel + "\" in domain for system")
let file = root.appendingPathComponent("state")
let absentPaths = [file.path]
assert(SelectiveRouter.absentInstallation(paths:absentPaths, job:absentJob, label:jobLabel))
for job in [CommandResult(code:0,output:"loaded"), CommandResult(code:1,output:"denied"), CommandResult(code:113,output:"unknown")] {
    assert(!SelectiveRouter.absentInstallation(paths:absentPaths, job:job, label:jobLabel))
}
try FileManager.default.createDirectory(at: file,withIntermediateDirectories:true)
assert(!SelectiveRouter.absentInstallation(paths:absentPaths, job:absentJob, label:jobLabel))
print("PASS fresh installation evidence, partial installation and unavailable launchd")

owner.window = owner.makeWindow("fixture",510,362)
owner.item = NSStatusBar.system.statusItem(withLength:0)
owner.setupMain()
owner.selective.helperAvailability = .missing
owner.selective.inspectCleanup = { _ in false }
owner.selective.confirmAbsent = { true }
var completed = false
owner.stopAndConfirmCleanup { result in
    if case .success = result { completed = true }
}
let deadline = Date().addingTimeInterval(3)
while !completed && Date() < deadline { RunLoop.main.run(until:Date().addingTimeInterval(0.02)) }
assert(completed)
try FileManager.default.removeItem(at:root)
print("PASS first-use update completes without an XPC reply")
