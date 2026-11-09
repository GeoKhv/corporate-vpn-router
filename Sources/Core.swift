import Foundation

let productVersion = "0.2.0-beta.4"

enum RouterError: String, Error {
    case unconfigured, invalidConfiguration, vpnUnavailable, dnsUnavailable
    case routeDenied, destinationDenied, staleNetwork, timeout, io, unsupportedPlatform
}

struct Configuration: Codable, Equatable {
    var schemaVersion = 1
    var listenPort = 1089
    var domains: [String] = []
    var dnsServers: [String] = []
    var ports: [Int] = [443]

    func validated() throws -> Configuration {
        guard schemaVersion == 1, (1024...65535).contains(listenPort),
              !domains.isEmpty, domains.count <= 256,
              !dnsServers.isEmpty, dnsServers.count <= 4,
              !ports.isEmpty, ports.count <= 32,
              ports.allSatisfy({ (1...65535).contains($0) }),
              domains.allSatisfy({ Self.validHost($0) && $0 == $0.lowercased()
                  && !$0.hasSuffix(".onion") && $0 != "onion" && $0.contains(".") }),
              dnsServers.allSatisfy({ Self.validIPv4($0) && Self.safeDestination($0) }) else {
            throw RouterError.invalidConfiguration
        }
        return self
    }

    static func validIPv4(_ text: String) -> Bool {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            !$0.isEmpty && $0.allSatisfy({ $0.isASCII && $0.isNumber })
                && ($0 == "0" || !$0.hasPrefix("0")) && (Int($0) ?? 256) <= 255
        }
    }

    static func safeDestination(_ text: String) -> Bool {
        guard validIPv4(text) else { return false }
        let p = text.split(separator: ".").map { Int($0)! }
        return p[0] != 0 && p[0] != 127 && p[0] < 224
            && !(p[0] == 169 && p[1] == 254) && text != "255.255.255.255"
    }

    static func validHost(_ text: String) -> Bool {
        guard !text.isEmpty, text.utf8.count <= 253, !validIPv4(text) else { return false }
        return text.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-")
                && $0.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }

    func permits(_ host: String, port: Int) -> Bool {
        Self.validHost(host) && !host.hasSuffix(".onion") && ports.contains(port)
            && domains.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    static func load(_ url: URL) throws -> Configuration {
        try JSONDecoder().decode(Configuration.self, from: Data(contentsOf: url)).validated()
    }
}

#if !CVR_MENU_BETA
struct Link: Equatable {
    let interface: String
    let index: UInt32
    let source: String
    let peer: String
    let networkSignature: String
}

struct Snapshot {
    let link: Link?
    let reason: String
}

// The core depends on this boundary. Windows must implement native binding,
// route ownership, DNS transport, change notifications and cancellation first.
protocol VPNPlatform {
    func discover(dnsServers: [String]) -> Snapshot
    func routeAllowed(address: String, link: Link) -> Bool
    func connect(address: String, port: Int, link: Link, session: Session) throws -> OwnedSocket
    func resolve(host: String, servers: [String], link: Link, session: Session) throws -> [String]
}

struct PublicStatus: Codable {
    var version = productVersion
    var state: String
    var reason: String
    var updatedAt = Date().timeIntervalSince1970
    var listen: String
    var activeConnections: Int
    var generation: UInt64
    // No domains, addresses, username, site, packets or command output.
}

#endif

enum JSONFile {
    static func write<T: Encodable>(_ value: T, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(value).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

func field(_ text: String, _ name: String) -> String? {
    for line in text.components(separatedBy: .newlines) {
        let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.count == 2 && parts[0] == name { return parts[1].split(separator: " ").first.map(String.init) }
    }
    return nil
}

extension NSLock {
    func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock(); defer { unlock() }; return try body()
    }
}
