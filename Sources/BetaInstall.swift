import Foundation
import Darwin
import AppKit
enum BetaInstall {
    static let label="com.geokhv.corporate-vpn-router.menu"
    static func checkedAgent(_ paths:ProductPaths)throws -> URL {
        let fm=FileManager.default
        let url=paths.home.appendingPathComponent("Library/LaunchAgents/\(label).plist")
        if fm.fileExists(atPath:url.path){
            guard (try? url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink) != true,
                  let data=try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any],
                  data["Label"] as? String == label,(data["ProgramArguments"] as? [String])==[paths.executable.path,"--login"] else{throw RouterError.destinationDenied}
        }
        return url
    }
    static func idle(_ paths:ProductPaths)throws{
        let fd=open(paths.data.appendingPathComponent("menu.lock").path,O_RDWR|O_CREAT|O_NOFOLLOW,0o600)
        guard fd >= 0 else{throw RouterError.io};defer{close(fd)}
        guard flock(fd,LOCK_EX|LOCK_NB)==0 else{throw RouterError.staleNetwork}
    }
    static func beta4(_ paths:ProductPaths)->URL?{
        let fm=FileManager.default
        return (try? fm.contentsOfDirectory(at:paths.data,includingPropertiesForKeys:nil))?.first{ url in
            url.lastPathComponent.hasPrefix("rollback-") &&
            (try? String(contentsOf:url.appendingPathComponent("Contents/Resources/VERSION")).trimmingCharacters(in:.whitespacesAndNewlines))=="0.2.0-beta.4" &&
            command("/usr/bin/codesign",["--verify","--deep","--strict","-R=cdhash H\"9f36b474a132a4cc2603b321b734d426916f8784\"",url.path],timeout:30).code==0
        }
    }
    static func install(_ paths:ProductPaths)throws{
        let fm=FileManager.default, source=try Lifecycle.sourceApp()
        try Lifecycle.verifyOwnership(paths);try paths.createData();_ = try checkedAgent(paths); try idle(paths)
        if source.standardizedFileURL != paths.app.standardizedFileURL {
            try fm.createDirectory(at:paths.app.deletingLastPathComponent(),withIntermediateDirectories:true)
            let stage=paths.app.deletingLastPathComponent().appendingPathComponent(".CVR-\(UUID().uuidString).app")
            defer{try? fm.removeItem(at:stage)}
            guard command("/usr/bin/ditto",[source.path,stage.path],timeout:60).code==0,
                  command("/usr/bin/codesign",["--verify","--deep","--strict",stage.path],timeout:30).code==0 else{throw RouterError.io}
            let old=paths.data.appendingPathComponent("rollback-\(UUID().uuidString).app")
            let exists=fm.fileExists(atPath:paths.app.path)
            if exists{try fm.moveItem(at:paths.app,to:old)}
            do{try fm.moveItem(at:stage,to:paths.app)}catch{if exists{try? fm.moveItem(at:old,to:paths.app)};throw error}
        }
        let url=try checkedAgent(paths)
        try fm.createDirectory(at:url.deletingLastPathComponent(),withIntermediateDirectories:true)
        let spec:[String:Any]=["Label":label,"ProgramArguments":[paths.executable.path,"--login"],"RunAtLoad":true,"LimitLoadToSessionType":"Aqua","Umask":0o077]
        try PropertyListSerialization.data(fromPropertyList:spec,format:.xml,options:0).write(to:url,options:.atomic)
    }
}
