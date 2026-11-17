import AppKit
import Sparkle
import Darwin

func require(_ value: @autoclosure () throws -> Bool, _ message: String) {
    do { if try !value() { fatalError(message) } }
    catch { fatalError("\(message): \(error)") }
}
func wait(_ predicate: () -> Bool) {
    let end=Date().addingTimeInterval(45)
    while !predicate() && Date()<end { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
    require(predicate(), "timeout")
}
let fm=FileManager.default, app=NSApplication.shared
app.setActivationPolicy(.prohibited)
let source=URL(fileURLWithPath:CommandLine.arguments[1]), old=URL(fileURLWithPath:CommandLine.arguments[2])
let root=fm.temporaryDirectory.appendingPathComponent("cvr-first-launch-tests-"+UUID().uuidString)
try fm.createDirectory(at:root,withIntermediateDirectories:true)
defer { try? fm.removeItem(at:root) }
let shared=root.appendingPathComponent("Applications"), home=root.appendingPathComponent("home")
try fm.createDirectory(at:shared,withIntermediateDirectories:true)
try fm.createDirectory(at:home,withIntermediateDirectories:true)
let paths=ProductPaths(root:home.path,systemApplications:shared)
StartupDiagnostics.shared.begin(home:home,source:source)
if CommandLine.arguments.contains("--preview") || CommandLine.arguments.contains("--preview-error") {
    app.setActivationPolicy(.regular)
    let failure: Error? = CommandLine.arguments.contains("--preview-error") ? InstallationError(step:"Установка проверена, но открытие не подтверждено",detail:"macOS могла остановить запуск до появления окна. Прежняя копия сохранена для отката. Сохраните отчёт; если macOS не даёт открыть Router, используйте сборщик из комплекта.") : nil
    let preview=FirstLaunchWindow(source:source,paths:paths,plan:try FirstLaunchPlan.make(source:source,paths:paths),error:failure)
    preview.install={_,_ in throw InstallationError(step:"Проверка интерфейса",detail:"Это локальный тестовый экран; приложение не устанавливается.")}
    app.delegate=preview; app.run(); withExtendedLifetime(preview) {}; exit(0)
}
let first=try FirstLaunchPlan.make(source:source,paths:paths)
require(first.action == .install,"fresh Downloads begins installation")
require(first.destination == home.appendingPathComponent("Applications/"+AppInstallation.appName),"fresh user destination")
let cancelled=FirstLaunchWindow(source:source,paths:paths,plan:first)
var finished=false, installed=false
cancelled.finish={finished=true}; cancelled.install={_,_ in installed=true; return paths.app}
cancelled.cancelInstall()
require(finished && !installed && !fm.fileExists(atPath:paths.app.path),"cancel must not install")
print("PASS explicit initial plan and cancellation with no application/data installation")

let target=try AppInstallation.install(source:source,home:home,systemApplications:shared)
try AppInstallation.verify(target)
require(try FirstLaunchPlan.make(source:target,paths:paths).action == .runInstalled,"installed runs directly")
require(try FirstLaunchPlan.make(source:source,paths:paths).action == .openExisting,"same-version download opens existing")
require(try FirstLaunchPlan.make(source:old,paths:paths).action == .openExisting,"older download opens newer existing")
do { _=try AppInstallation.install(source:old,home:home,systemApplications:shared); fatalError("CLI downgrade accepted") }
catch { require(error.localizedDescription.contains("устаревшая"),"newer installed copy is protected at the transaction boundary") }
try BetaInstall.registerLogin(paths)
let agent=try BetaInstall.checkedAgent(paths), agentBytes=try Data(contentsOf:agent)
require(String(decoding:agentBytes,as:UTF8.self).contains(target.path),"login targets installed app")
var relocated = try PropertyListSerialization.propertyList(from:agentBytes,format:nil) as! [String:Any]
relocated["ProgramArguments"]=[home.appendingPathComponent("Downloads/"+AppInstallation.appName+"/Contents/MacOS/CorporateVPNRouter").path,"--login"]
try PropertyListSerialization.data(fromPropertyList:relocated,format:.xml,options:0).write(to:agent)
try AppInstallation.relocateLogin(home:home,systemApplications:shared)
require(try Data(contentsOf:agent)==agentBytes,"recognised login entry repaired without enabling a new one")
let driver=RouterUpdates(owner:BetaMenu(paths:paths))
require(AppInstallation.sameLocation(driver.updater.hostBundle.bundleURL,target),"Sparkle must target installed path")
print("PASS repeat/older source, installed startup, persistent login and Sparkle host")
try StartupHandoff.openInstalled(target,paths:paths,timeout:0.2,request:{_,token in
    try Data("ready\n".utf8).write(to:StartupHandoff.receipt(token,paths:paths))
})
do {
    try StartupHandoff.openInstalled(target,paths:paths,timeout:0.1,request:{_,_ in })
    fatalError("open without a ready receipt treated as success")
} catch { require(error.localizedDescription.contains("не подтверждено"),"missing main receipt reported") }
print("PASS ready handshake and failure when open returns without a main-window receipt")

let oldHome=root.appendingPathComponent("old-home")
try fm.createDirectory(at:oldHome,withIntermediateDirectories:true)
let systemApp=shared.appendingPathComponent(AppInstallation.appName)
try fm.copyItem(at:old,to:systemApp)
let existing=ProductPaths(root:oldHome.path,systemApplications:shared)
try existing.createData()
let settings=existing.data.appendingPathComponent("work-sites.json")
try Data("preserve-test-settings".utf8).write(to:settings)
let oldSignature=try Data(contentsOf:systemApp.appendingPathComponent("Contents/_CodeSignature/CodeResources"))
require(try FirstLaunchPlan.make(source:source,paths:existing).action == .install,"explicit older-copy upgrade")
require(try FirstLaunchPlan.make(source:source,paths:existing,running:true).action == .openExisting,"running old copy is never silently replaced")
let fd=try AppInstallation.lock(existing.data.appendingPathComponent("menu.lock"),busy:"fixture")
do { _=try AppInstallation.install(source:source,home:oldHome,systemApplications:shared); fatalError("busy replaced") }
catch { require(error.localizedDescription.contains("VPN-сеанс сохранён"),"busy reason") }; close(fd)
do {
    _=try AppInstallation.install(source:source,home:oldHome,systemApplications:shared,validatePlaced:{_ in throw RouterError.io})
    fatalError("injected validation failure accepted")
} catch {}
require(try Data(contentsOf:systemApp.appendingPathComponent("Contents/_CodeSignature/CodeResources"))==oldSignature,"rollback restores original")
try AppInstallation.verify(systemApp)
require(try String(contentsOf:settings)=="preserve-test-settings","failure preserves settings")
let upgraded=try AppInstallation.install(source:source,home:oldHome,systemApplications:shared)
require(AppInstallation.sameLocation(upgraded,systemApp),"preserve system folder")
require(!fm.fileExists(atPath:oldHome.appendingPathComponent("Applications/"+AppInstallation.appName).path),"no duplicate")
require(try String(contentsOf:settings)=="preserve-test-settings","upgrade preserves settings")
let backups=try fm.contentsOfDirectory(at:existing.data,includingPropertiesForKeys:nil).filter{$0.lastPathComponent.hasPrefix("rollback-")}
require(backups.count==1,"one successful upgrade backup")
require(try Data(contentsOf:backups[0].appendingPathComponent("Contents/_CodeSignature/CodeResources"))==oldSignature,"exact backup")
print("PASS system folder, busy old copy, post-placement failure rollback, backup and settings")

let conflict=oldHome.appendingPathComponent("Applications/"+AppInstallation.appName)
try fm.createDirectory(at:conflict.deletingLastPathComponent(),withIntermediateDirectories:true)
try fm.copyItem(at:source,to:conflict)
do { _=try FirstLaunchPlan.make(source:source,paths:existing); fatalError("duplicate destinations accepted") } catch {}
require(fm.fileExists(atPath:conflict.path) && fm.fileExists(atPath:systemApp.path),"duplicates preserved")
let failed=FirstLaunchWindow(source:source,paths:paths,error:InstallationError(step:"Fixture startup failure",detail:"no network"))
failed.show()
require(!failed.report.isHidden && failed.primary.isHidden,"failure report button")
failed.window.orderOut(nil)
let flowHome=root.appendingPathComponent("flow-home"), flowShared=root.appendingPathComponent("flow-system")
try fm.createDirectory(at:flowHome,withIntermediateDirectories:true)
let flowPaths=ProductPaths(root:flowHome.path,systemApplications:flowShared)
let flow=FirstLaunchWindow(source:source,paths:flowPaths,plan:try FirstLaunchPlan.make(source:source,paths:flowPaths))
var launched:URL?, completed=false
flow.launch={launched=$0}; flow.finish={completed=true}
flow.show(); flow.proceed(); wait {completed || !flow.busy}
require(completed && launched.map { AppInstallation.sameLocation($0,flowPaths.app) } == true,"confirmed UI installs then opens verified destination")
flow.window.orderOut(nil)
print("PASS duplicate protection, error report button, confirmed installation UI transaction")
require(!StartupDiagnostics.shared.report().contains("preserve-test-settings"),"no settings in startup report")
let savedReport=try StartupDiagnostics.shared.exportReport()
require(try String(contentsOf:savedReport)==StartupDiagnostics.shared.report(),"one-click report writes full startup metadata")
let attributes=try fm.attributesOfItem(atPath:savedReport.path)
require((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,"report is private")
print("PASS startup report excludes settings; these are isolated macOS host tests, not a clean recipient OS")
