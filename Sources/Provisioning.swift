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
        for name in ["ApprovedGateway.json", "ApprovedCertificates", "CertificateEndpoints.json", "DefaultDomainMap.json", "RouteHelper"] {
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
    }
    static func helper(_ resources: URL, paths: ProductPaths = ProductPaths()) throws -> URL {
        let bundled = resources.appendingPathComponent("RouteHelper/RouteHelper")
        let saved = directory(paths).appendingPathComponent("RouteHelper/RouteHelper")
        let source = FileManager.default.fileExists(atPath: bundled.path) ? bundled : saved
        try AppInstallation.rejectLink(source)
        guard let expected = Bundle.main.object(forInfoDictionaryKey: "CVRRouteHelperSHA256") as? String,
              SHA256.hash(data: try Data(contentsOf: source)).map({ String(format: "%02x", $0) }).joined() == expected else {
            throw InstallationError(step: "Нужен приватный стартовый пакет", detail: "Проверенный помощник не найден. Восстановите приватную стартовую сборку; общий пакет предназначен для обновления уже настроенного Router.")
        }
        return source
    }
}
#endif
