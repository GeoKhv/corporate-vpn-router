import Foundation
import Darwin
enum BetaInstall {
    static let label="com.geokhv.corporate-vpn-router.menu"
    static func install(_ paths:ProductPaths)throws{
        let fm=FileManager.default, source=try Lifecycle.sourceApp()
        try Lifecycle.verifyOwnership(paths);try paths.createData()
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
        let url=paths.home.appendingPathComponent("Library/LaunchAgents/\(label).plist")
        try fm.createDirectory(at:url.deletingLastPathComponent(),withIntermediateDirectories:true)
        if fm.fileExists(atPath:url.path){
            guard (try? url.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink) != true,
                  let data=try PropertyListSerialization.propertyList(from:Data(contentsOf:url),format:nil) as? [String:Any],
                  data["Label"] as? String == label,(data["ProgramArguments"] as? [String])?.first==paths.executable.path else{throw RouterError.destinationDenied}
        }
        let spec:[String:Any]=["Label":label,"ProgramArguments":[paths.executable.path,"--login"],"RunAtLoad":true,"LimitLoadToSessionType":"Aqua","Umask":0o077]
        try PropertyListSerialization.data(fromPropertyList:spec,format:.xml,options:0).write(to:url,options:.atomic)
    }
}
