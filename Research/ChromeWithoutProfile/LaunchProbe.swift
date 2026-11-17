// Disposable laboratory only. LaunchServices, no AppleScript or Accessibility.
import AppKit
import Foundation
let a=CommandLine.arguments
 guard a.count>=4 else { exit(2) }
let app=URL(fileURLWithPath:a[1]), result=URL(fileURLWithPath:a[2])
let config=NSWorkspace.OpenConfiguration()
config.arguments=Array(a.dropFirst(3))
config.activates=false
// Every trial uses a disposable user-data-dir, never the user's Chrome.
config.createsNewApplicationInstance=true
NSWorkspace.shared.openApplication(at:app,configuration:config){ running,error in
    let value:[String:Any] = ["pid":running?.processIdentifier ?? 0,"error":error?.localizedDescription ?? ""]
    try? JSONSerialization.data(withJSONObject:value).write(to:result,options:.atomic)
    exit(error == nil && running != nil ? 0 : 3)
}
RunLoop.main.run()
