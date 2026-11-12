import Foundation
import Darwin
import AppKit
#if CVR_SELECTIVE_TUN
import CoreServices
#endif
enum BetaInstall {
    private struct SiteAdditions: Decodable { let version: Int; let id: String; let sites: [WorkSite] }
    static let label=AppInstallation.label
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
        let target = try AppInstallation.install(source: Lifecycle.sourceApp(), home: paths.home, systemApplications: paths.systemApplications)
#if CVR_SELECTIVE_TUN
        // Refresh only this installed app's metadata, never global icon caches.
        // Disposable test homes must not register duplicate launcher entries.
        if let user = getpwuid(getuid()), let home = user.pointee.pw_dir,
           paths.home.standardizedFileURL == URL(fileURLWithPath: String(cString: home)).standardizedFileURL {
            _ = LSRegisterURL(target as CFURL, true)
        }
#endif
    }

    static func seedWorkSites(_ paths: ProductPaths) throws {
        let target = paths.data.appendingPathComponent("work-sites.json")
        if !FileManager.default.fileExists(atPath: target.path),
           let source = Bundle.main.url(forResource: "DefaultWorkSites", withExtension: "json") {
            let data = try Data(contentsOf: source)
            let profile = try JSONDecoder().decode(WorkProfile.self, from: data)
            guard profile.version == 1, !profile.sites.isEmpty, profile.sites.count <= 256,
                  profile.sites.allSatisfy({ Configuration.validHost($0.domain) && ["tree", "exact"].contains($0.scope) }),
                  profile.beforeLogin.allSatisfy({ Configuration.validHost($0) }),
                  !profile.ports.isEmpty, profile.ports.allSatisfy({ (1...65535).contains($0) }) else { throw RouterError.invalidConfiguration }
            try data.write(to: target, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        }
#if CVR_SELECTIVE_TUN
        // Explicit private-build additions are applied once, without resetting
        // the user's list or re-adding sites the user removes later.
        if let source = Bundle.main.url(forResource:"WorkSiteAdditions",withExtension:"json") {
            let update = try JSONDecoder().decode(SiteAdditions.self,from:Data(contentsOf:source))
            guard update.version == 1, !update.id.isEmpty, update.id.count <= 64,
                  update.id.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
                  !update.sites.isEmpty, update.sites.allSatisfy({ Configuration.validHost($0.domain) && $0.scope == "tree" }) else { throw RouterError.invalidConfiguration }
            let marker = paths.data.appendingPathComponent("work-site-updates.json")
            try AppInstallation.rejectLink(target); try AppInstallation.rejectLink(marker)
            var applied = FileManager.default.fileExists(atPath:marker.path) ? try JSONDecoder().decode([String].self,from:Data(contentsOf:marker)) : []
            guard !applied.contains(update.id) else { return }
            let previous = try Data(contentsOf:target)
            var profile = try JSONDecoder().decode(WorkProfile.self,from:previous)
            let additions = update.sites.filter { rule in !profile.sites.contains(where: { $0.domain == rule.domain || ($0.scope == "tree" && rule.domain.hasSuffix("." + $0.domain)) }) }
            if !additions.isEmpty {
                let sessionFile = paths.data.appendingPathComponent("Selective/last-session.txt")
                if let session = try? String(contentsOf:sessionFile) {
                    let folder = URL(fileURLWithPath:session.trimmingCharacters(in:.whitespacesAndNewlines))
                    if FileManager.default.fileExists(atPath:folder.appendingPathComponent("ready.json").path),
                       !FileManager.default.fileExists(atPath:folder.appendingPathComponent("cleanup.json").path) {
                        throw InstallationError(step:"Дождитесь остановки рабочих маршрутов",detail:"Новый рабочий сайт будет добавлен при следующем запуске. Существующий список сохранён.")
                    }
                }
                guard profile.sites.count + additions.count <= 256,
                      !additions.contains(where:{ rule in profile.beforeLogin.contains(where:{ $0 == rule.domain || $0.hasSuffix("." + rule.domain) }) }) else { throw RouterError.invalidConfiguration }
                let backup = paths.data.appendingPathComponent("work-sites-before-" + update.id + ".json")
                try AppInstallation.rejectLink(backup)
                if !FileManager.default.fileExists(atPath:backup.path) { try previous.write(to:backup,options:.withoutOverwriting) }
                profile.sites.append(contentsOf:additions)
                try JSONFile.write(profile,to:target)
            }
            applied.append(update.id); try JSONFile.write(applied,to:marker)
        }
#endif
    }

    static func registerLogin(_ paths: ProductPaths) throws {
        try AppInstallation.rejectLink(paths.app)
        let url = try AppInstallation.agent(paths.home, systemApplications: paths.systemApplications)
        guard !FileManager.default.fileExists(atPath: url.path) else { return }
        let spec: [String: Any] = ["Label": label, "ProgramArguments": [paths.executable.path, "--login"],
                                  "RunAtLoad": true, "LimitLoadToSessionType": "Aqua", "Umask": 0o077]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: spec, format: .xml, options: 0)
        try data.write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func isInstalledCopy(_ source: URL, _ paths: ProductPaths) throws -> Bool {
        try AppInstallation.rejectLink(paths.app)
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
