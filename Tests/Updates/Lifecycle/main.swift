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
