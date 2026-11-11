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
    static func beta5(_ paths:ProductPaths)->URL?{
        let fm=FileManager.default
        return (try? fm.contentsOfDirectory(at:paths.data,includingPropertiesForKeys:nil))?.first{ url in
            url.lastPathComponent.hasPrefix("rollback-") &&
            (try? String(contentsOf:url.appendingPathComponent("Contents/Resources/VERSION")).trimmingCharacters(in:.whitespacesAndNewlines))=="0.2.0-beta.5" &&
            command("/usr/bin/codesign",["--verify","--deep","--strict","-R=cdhash H\"3ca41db3fd8e567a01fab830cbc691434b004b6f\"",url.path],timeout:30).code==0
        }
    }
    static func install(_ paths:ProductPaths)throws{
        _ = try AppInstallation.install(source: Lifecycle.sourceApp(), home: paths.home)
    }

    static func isInstalledCopy(_ source: URL, _ paths: ProductPaths) throws -> Bool {
        if source.resolvingSymlinksInPath() == paths.app.resolvingSymlinksInPath() { return true }
        // Gatekeeper can run the installed bundle from App Translocation.
        // Recognize the same verified code instead of installing it over itself.
        for relative in ["Contents/MacOS/CorporateVPNRouter", "Contents/Info.plist", "Contents/_CodeSignature/CodeResources"] {
            guard FileManager.default.contentsEqual(atPath: source.appendingPathComponent(relative).path, andPath: paths.app.appendingPathComponent(relative).path) else { return false }
        }
        try AppInstallation.verify(source)
        try AppInstallation.verify(paths.app)
        return true
    }
}
