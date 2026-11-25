#if CVR_SELECTIVE_TUN
import Foundation
import CryptoKit

// Private bootstrap material survives replacement by a generic update. Never
// overwrite an existing user's copy, policy, receipt, domain map or credentials.
enum Provisioning {
    static func directory(_ paths: ProductPaths) -> URL { paths.data.appendingPathComponent("Provisioning") }
    static func migrate(_ paths: ProductPaths, resources: URL) throws {
        let fm = FileManager.default, target = directory(paths)
        try AppInstallation.rejectLink(target)
        try fm.createDirectory(at: target, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for name in ["ApprovedGateway.json", "ApprovedSitePin.json", "ApprovedCertificates", "CertificateEndpoints.json", "DefaultDomainMap.json", "DefaultDesktop.json", "RouteHelper"] {
            let source = resources.appendingPathComponent(name), destination = target.appendingPathComponent(name)
            try AppInstallation.rejectLink(destination)
            if fm.fileExists(atPath: destination.path) { continue }
            // Public updates include only RouteClient: never shadow a complete seed with it.
            if name == "RouteHelper" && !fm.fileExists(atPath: source.appendingPathComponent("RouteHelper").path) { continue }
            if fm.fileExists(atPath: source.path) {
                let staging = target.appendingPathComponent(".seed-" + UUID().uuidString)
                defer { try? fm.removeItem(at: staging) }
                try fm.copyItem(at: source, to: staging)
                try fm.moveItem(at: staging, to: destination)
            }
        }
        // A private upgrade carries a new helper; future generic updates must
        // be able to find this exact payload without replacing the old seed.
        let incoming = resources.appendingPathComponent("RouteHelper")
        let executable = incoming.appendingPathComponent("RouteHelper")
        if fm.fileExists(atPath:executable.path),
           let expected = Bundle.main.object(forInfoDictionaryKey:"CVRRouteHelperSHA256") as? String,
           try checksum(executable) == expected {
            let legacy = target.appendingPathComponent("RouteHelper/RouteHelper")
            if (try? checksum(legacy)) != expected {
                let destination = target.appendingPathComponent("RouteHelper-" + expected)
                try AppInstallation.rejectLink(destination)
                if !fm.fileExists(atPath:destination.path) {
                    let stage = target.appendingPathComponent(".seed-" + UUID().uuidString)
                    defer { try? fm.removeItem(at:stage) }
                    try fm.copyItem(at:incoming, to:stage)
                    try fm.moveItem(at:stage, to:destination)
                }
            }
        }
    }
    static func enrollmentDesktop(status: [String:Any]?, resources: URL, paths: ProductPaths, profile: WorkProfile) -> String {
        if let current = status?["approvedRDPHost"] as? String, Configuration.validHost(current), profile.work(current) { return current }
        return defaultDesktop(resources:resources,paths:paths,profile:profile) ?? ""
    }
    static func matchesEnrollment(_ status: [String:Any]?, _ expected: [String:Any]?) -> Bool {
        guard let rules = status?["tcpRules"] as? NSArray, let desktop = expected?["desktop"] as? String else { return false }
        return rules.isEqual(expected?["rules"]) && (status?["approvedRDPHost"] as? String ?? "") == desktop
    }
    static func defaultDesktop(resources: URL, paths: ProductPaths, profile: WorkProfile) -> String? {
        // The signed bundle may provide a deployment default; the saved copy
        // allows subsequent generic updates to use the same enrollment.
        for folder in [resources, directory(paths)] {
            let file = folder.appendingPathComponent("DefaultDesktop.json")
            guard (try? AppInstallation.rejectLink(file)) != nil,
                  let bytes = try? Data(contentsOf:file),
                  let record = try? JSONDecoder().decode([String:String].self,from:bytes),
                  let host = record["desktop"], host.contains("."), Configuration.validHost(host),
                  profile.work(host) else { continue }
            return host
        }
        return nil
    }
    static func checksum(_ url: URL) throws -> String {
        try AppInstallation.rejectLink(url)
        return SHA256.hash(data:try Data(contentsOf:url)).map { String(format:"%02x",$0) }.joined()
    }
    static func helper(_ resources: URL, paths: ProductPaths = ProductPaths()) throws -> URL {
        let bundled = resources.appendingPathComponent("RouteHelper/RouteHelper")
        let saved = directory(paths).appendingPathComponent("RouteHelper/RouteHelper")
        guard let expected = Bundle.main.object(forInfoDictionaryKey:"CVRRouteHelperSHA256") as? String,
              expected.range(of:"^[0-9a-f]{64}$",options:.regularExpression) != nil,
              let source = [bundled, directory(paths).appendingPathComponent("RouteHelper-" + expected + "/RouteHelper"), saved]
                .first(where:{ (try? checksum($0)) == expected }) else {
            throw InstallationError(step:"Нужен приватный стартовый пакет", detail:"Для этой версии не найден проверенный помощник. Откройте соответствующий приватный комплект.")
        }
        return source
    }
}
#endif
