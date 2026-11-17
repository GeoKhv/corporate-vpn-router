import AppKit
import Foundation
func check(_ condition: @autoclosure () -> Bool) { precondition(condition()) }
check(HTTPSProbeResult(exitCode:0,output:"200 0\n").reachable)
check(HTTPSProbeResult(exitCode:0,output:"401 0").reachable)
check(HTTPSProbeResult(exitCode:63,output:"200 0").reachable)
check(!HTTPSProbeResult(exitCode:60,output:"200 20").reachable)
check(!HTTPSProbeResult(exitCode:28,output:"200 0").reachable)
check(!HTTPSProbeResult(exitCode:0,output:"invalid").reachable)
check(HTTPSProbeResult(exitCode:6,output:"000 0").reason.contains("имя"))
check(HTTPSProbeResult(exitCode:97,output:"000 0").reason.contains("SOCKS"))
let board = NSPasteboard(name:NSPasteboard.Name("com.geokhv.router.report-test."+UUID().uuidString))
defer { board.releaseGlobally() }
board.setString("existing clipboard fixture",forType:.string)
check(!copyReportFile(URL(fileURLWithPath:"/does/not/exist"),to:board))
check(board.string(forType:.string)=="existing clipboard fixture")
let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
defer { try? FileManager.default.removeItem(at:dir) }
let file=dir.appendingPathComponent("Отчёт с пробелами.txt")
try Data("fixture".utf8).write(to:file)
check(copyReportFile(file,to:board))
let urls=board.readObjects(forClasses:[NSURL.self],options:[.urlReadingFileURLsOnly:true]) as? [URL]
check(urls?.first?.standardizedFileURL==file.standardizedFileURL)
check(board.string(forType:.string)==nil) // Copy an attachment, not its contents.
print("PASS scoped HTTPS outcomes; named pasteboard file URL; failed export preserves clipboard")
