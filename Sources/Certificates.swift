import Foundation
import Security
import CryptoKit
import Darwin

struct CertificateInfo: Codable {
    var subject: String
    var issuer: String
    var notBefore: String
    var notAfter: String
    var sha256: String
    var isCA: Bool
    var selfIssued: Bool
    var currentlyValid: Bool
    var presentInKeychain: Bool
    var basicSystemTrust: Bool
    var keychainSearchStatus: String
}

struct HTTPSCertificateResult: Codable {
    var host: String
    var tlsTrusted = false
    var httpStatus: Int?
    var clientCertificateRequested = false
    var certificates: [CertificateInfo] = []
    var issue = "NOT_CHECKED"
    var sourceAuthenticity = "NOT_ESTABLISHED_BY_LOCAL_TRUST_OR_SERVER_CHAIN"
    var revocation = "OFFLINE_EVALUATION_ONLY"
    var routeScope = "CORPORATE_BOUND_SOCKET"
    var trustExplanation = "Not evaluated. Local system trust does not independently confirm corporate authenticity."
    var peerDER: [Data] = []
    enum CodingKeys: String, CodingKey {
        case host, tlsTrusted, httpStatus, clientCertificateRequested, certificates, issue,
             sourceAuthenticity, revocation, routeScope, trustExplanation
    }
}

struct CertificatePreferences: Codable { var hosts: [String] = [] }
struct CertificateReceipt: Codable {
    var sha256: String
    var sourceURL: String
    var sourceConfirmation = "USER_ATTESTED_AUTHORIZED_IT_SOURCE_AND_INDEPENDENT_FINGERPRINT"
    var role: String
    var importedAt = Date().timeIntervalSince1970
    var der: Data
    var undone = false
    var completed = false
    var userTrustAfter: String?
}

struct DERNode {
    let tag: UInt8, value: [UInt8]
    static func nodes(_ bytes: [UInt8]) throws -> [DERNode] {
        var pos = 0, result: [DERNode] = []
        while pos < bytes.count {
            let tag = bytes[pos]; pos += 1
            guard pos < bytes.count else { throw RouterError.invalidConfiguration }
            var length = Int(bytes[pos]); pos += 1
            if length & 128 != 0 {
                let n = length & 127
                guard (1...4).contains(n), pos+n <= bytes.count else { throw RouterError.invalidConfiguration }
                length = 0
                for _ in 0..<n { length = (length << 8) | Int(bytes[pos]); pos += 1 }
            }
            guard length >= 0, length <= bytes.count-pos else { throw RouterError.invalidConfiguration }
            result.append(DERNode(tag: tag, value: Array(bytes[pos..<pos+length]))); pos += length
        }
        return result
    }
    static func isCA(_ data: Data) -> Bool {
        guard let root = try? nodes(Array(data)), root.count == 1, root[0].tag == 0x30,
              let certificate = try? nodes(root[0].value), let tbs = certificate.first, tbs.tag == 0x30,
              let fields = try? nodes(tbs.value), let extensions = fields.first(where: { $0.tag == 0xa3 }),
              let wrapper = try? nodes(extensions.value), wrapper.count == 1,
              let records = try? nodes(wrapper[0].value) else { return false }
        for record in records {
            guard let parts = try? nodes(record.value), parts.first?.value == [0x55, 0x1d, 0x13],
                  let octets = parts.last, octets.tag == 4,
                  let inner = try? nodes(octets.value), inner.count == 1,
                  let constraints = try? nodes(inner[0].value), let ca = constraints.first,
                  ca.tag == 1, ca.value == [255] else { continue }
            return true
        }
        return false
    }
}

enum Certificates {
    static func fingerprint(_ cert: SecCertificate) -> String {
        SHA256.hash(data: SecCertificateCopyData(cert) as Data).map { String(format: "%02X", $0) }.joined(separator: ":")
    }
    static func canonicalFingerprint(_ text: String) -> String {
        text.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "").uppercased()
    }
    static func parse(_ data: Data) throws -> SecCertificate {
        guard data.count <= 1_048_576 else { throw RouterError.invalidConfiguration }
        var der = data
        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN") {
            guard !text.contains("PRIVATE KEY"), !text.contains("PKCS"),
                  text.components(separatedBy: "-----BEGIN CERTIFICATE-----").count == 2,
                  text.components(separatedBy: "-----END CERTIFICATE-----").count == 2,
                  let start = text.range(of: "-----BEGIN CERTIFICATE-----"),
                  let end = text.range(of: "-----END CERTIFICATE-----"), start.upperBound < end.lowerBound,
                  text[..<start.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  text[end.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let decoded = Data(base64Encoded: String(text[start.upperBound..<end.lowerBound]).filter { !$0.isWhitespace }) else { throw RouterError.invalidConfiguration }
            der = decoded
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { throw RouterError.invalidConfiguration }
        return certificate
    }

    static func inventorySnapshot() -> (certificates: [SecCertificate], complete: Bool) {
        var chains: [SecKeychain] = []
        for path in [FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db").path,
                     "/Library/Keychains/System.keychain", "/System/Library/Keychains/SystemRootCertificates.keychain"] {
            var chain: SecKeychain?; if SecKeychainOpen(path, &chain) == errSecSuccess, let c = chain { chains.append(c) }
        }
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll, kSecMatchSearchList as String: chains]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess || status == errSecItemNotFound else { return ([], false) }
        return ((result as? [SecCertificate]) ?? [], chains.count == 3)
    }
    static func inventory() -> [SecCertificate] { inventorySnapshot().certificates }

    static func describe(_ certificate: SecCertificate, installed: Set<String>? = nil, inventoryComplete: Bool? = nil) -> CertificateInfo {
        let keys = [kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName, kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
        let values = (SecCertificateCopyValues(certificate, keys, nil) as? [String: Any]) ?? [:]
        func property(_ key: CFString) -> Any? { (values[key as String] as? [String: Any])?[kSecPropertyKeyValue as String] }
        func text(_ value: Any?) -> String {
            if let a = value as? [[String: Any]] {
                return a.map { "\($0[kSecPropertyKeyLabel as String] ?? "")=\(text($0[kSecPropertyKeyValue as String]))" }.joined(separator: ", ")
            }
            if let s = value as? String { return s }
            return value.map { String(describing: $0) } ?? "UNKNOWN"
        }
        let before = (property(kSecOIDX509V1ValidityNotBefore) as? NSNumber).map { Date(timeIntervalSinceReferenceDate: $0.doubleValue) }
        let after = (property(kSecOIDX509V1ValidityNotAfter) as? NSNumber).map { Date(timeIntervalSinceReferenceDate: $0.doubleValue) }
        let formatter = ISO8601DateFormatter(), sha = fingerprint(certificate)
        var trust: SecTrust?
        var trusted = false
        if SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let t = trust {
            SecTrustSetNetworkFetchAllowed(t, false)
            trusted = SecTrustEvaluateWithError(t, nil)
        }
        let searched = installed == nil ? inventorySnapshot() : (certificates: [], complete: inventoryComplete ?? false)
        let presence = (installed ?? Set(searched.certificates.map(fingerprint))).contains(sha)
        return CertificateInfo(subject: text(property(kSecOIDX509V1SubjectName)), issuer: text(property(kSecOIDX509V1IssuerName)),
            notBefore: before.map { formatter.string(from: $0) } ?? "UNKNOWN", notAfter: after.map { formatter.string(from: $0) } ?? "UNKNOWN",
            sha256: sha, isCA: DERNode.isCA(SecCertificateCopyData(certificate) as Data),
            selfIssued: (SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?) == (SecCertificateCopyNormalizedIssuerSequence(certificate) as Data?),
            currentlyValid: before.map { $0 <= Date() } == true && after.map { $0 > Date() } == true,
            presentInKeychain: presence, basicSystemTrust: trusted,
            keychainSearchStatus: searched.complete ? "COMPLETE_LOGIN_SYSTEM_ROOTS_PUBLIC_CERTIFICATES" : "INCOMPLETE_ABSENCE_CANNOT_BE_ASSUMED")
    }

    static func preferences(_ paths: ProductPaths) -> CertificatePreferences {
        (try? JSONDecoder().decode(CertificatePreferences.self, from: Data(contentsOf: paths.data.appendingPathComponent("certificate-endpoints.json")))) ?? CertificatePreferences()
    }
    static func saveHosts(_ hosts: [String], paths: ProductPaths) throws {
        let config = try Configuration.load(paths.config)
        guard !hosts.isEmpty, hosts.count <= 16, hosts.allSatisfy({ config.permits($0, port: 443) }) else { throw RouterError.destinationDenied }
        try paths.createData()
        try JSONFile.write(CertificatePreferences(hosts: hosts), to: paths.data.appendingPathComponent("certificate-endpoints.json"))
    }

    static func receiptURL(_ sha: String, paths: ProductPaths) -> URL { paths.data.appendingPathComponent("certificate-imports/\(canonicalFingerprint(sha)).json") }
    static func receipts(_ paths: ProductPaths) -> [CertificateReceipt] {
        let dir = paths.data.appendingPathComponent("certificate-imports")
        return ((try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []).compactMap {
            guard $0.pathExtension == "json", let data = try? Data(contentsOf: $0) else { return nil }
            return try? JSONDecoder().decode(CertificateReceipt.self, from: data)
        }
    }

    // No download, enrollment, PFX, identity or private key path exists here.
    // The caller must display exact metadata and obtain a fresh explicit consent.
    static func importConfirmed(_ certificate: SecCertificate, expectedSHA256: String, sourceURL: String, consent: Bool, paths: ProductPaths, evidence: CertificateImportEvidence? = nil) throws {
        let sha = fingerprint(certificate), canonical = canonicalFingerprint(expectedSHA256)
        guard consent, canonical.count == 64, canonical.allSatisfy({ $0.isHexDigit }), canonical == canonicalFingerprint(sha),
              let evidence, CertificatePlan.assess(evidence).needed.contains(sha) else { throw RouterError.destinationDenied }
        let ownerSource = sourceURL == "owner-approved-keychain:" + canonical && evidence.sourceKind == "OWNER_APPROVED_EXISTING_KEYCHAIN_AND_VERIFIED_CHAIN"
        let source = URLComponents(string: sourceURL)
        let itSource = source?.scheme == "https" && source?.host.map(Configuration.validHost) == true && source?.user == nil && source?.password == nil && source?.query == nil && source?.fragment == nil
        guard ownerSource || itSource, userTrustFingerprint(certificate) == "NONE" else { throw RouterError.destinationDenied }
        let info = describe(certificate)
        let inventory = inventorySnapshot()
        guard inventory.complete, info.isCA, info.currentlyValid, !inventory.certificates.contains(where: { fingerprint($0) == sha }) else { throw RouterError.destinationDenied }
        try paths.createData()
        let dir = paths.data.appendingPathComponent("certificate-imports")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let der = SecCertificateCopyData(certificate) as Data
        var receipt = CertificateReceipt(sha256: sha, sourceURL: sourceURL, role: info.selfIssued ? "ROOT_SSL_USER_TRUST" : "INTERMEDIATE_NO_TRUST_OVERRIDE", der: der)
        receipt.sourceConfirmation = ownerSource ? evidence.sourceKind : receipt.sourceConfirmation
        // Persist before mutation, so a crash cannot erase the rollback material.
        try JSONFile.write(receipt, to: receiptURL(sha, paths: paths))
        let certFile = dir.appendingPathComponent("\(canonical).cer")
        try der.write(to: certFile, options: .atomic)
        defer { try? FileManager.default.removeItem(at: certFile) }
        let login = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db").path
        let args = info.selfIssued ? ["add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", login, certFile.path]
            : ["add-certificates", "-k", login, certFile.path]
        let result = command("/usr/bin/security", args, timeout: 120)
        guard result.code == 0, Self.inventory().contains(where: { fingerprint($0) == sha }) else { throw RouterError.io }
        receipt.completed = true
        receipt.userTrustAfter = userTrustFingerprint(certificate)
        try JSONFile.write(receipt, to: receiptURL(sha, paths: paths))
    }

    static func userTrustFingerprint(_ certificate: SecCertificate) -> String? {
        var settings: CFArray?
        let status = SecTrustSettingsCopyTrustSettings(certificate, .user, &settings)
        if status == errSecItemNotFound || status == errSecNoTrustSettings { return "NONE" }
        guard status == errSecSuccess, let rows = settings as? [[String: Any]] else { return nil }
        var normalized = [[String: Any]]()
        for var row in rows {
            if let policy = row[kSecTrustSettingsPolicy as String] {
                guard CFGetTypeID(policy as CFTypeRef) == SecPolicyGetTypeID() else { return nil }
                row[kSecTrustSettingsPolicy as String] = SecPolicyCopyProperties(policy as! SecPolicy)
            }
            guard JSONSerialization.isValidJSONObject(row) else { return nil }
            normalized.append(row)
        }
        guard let data = try? JSONSerialization.data(withJSONObject: normalized, options: [.sortedKeys]) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func undoConfirmed(_ sha: String, consent: Bool, paths: ProductPaths) throws {
        let canonical = canonicalFingerprint(sha)
        guard consent, canonical.count == 64, canonical.allSatisfy({ $0.isHexDigit }) else { throw RouterError.destinationDenied }
        let url = receiptURL(sha, paths: paths)
        var receipt = try JSONDecoder().decode(CertificateReceipt.self, from: Data(contentsOf: url))
        guard !receipt.undone, canonicalFingerprint(receipt.sha256) == canonical,
              fingerprint(try parse(receipt.der)) == receipt.sha256 else { throw RouterError.destinationDenied }
        let inventory = inventorySnapshot()
        guard inventory.complete else { throw RouterError.io }
        if !receipt.completed && !inventory.certificates.contains(where: { fingerprint($0) == receipt.sha256 }) {
            receipt.undone = true; try JSONFile.write(receipt, to: url); return
        }
        guard let expectedTrust = receipt.userTrustAfter,
              userTrustFingerprint(try parse(receipt.der)) == expectedTrust else { throw RouterError.destinationDenied }
        let login = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db").path
        // Exact hash, exact user keychain, user trust only. Never touch system/admin stores.
        guard command("/usr/bin/security", ["delete-certificate", "-Z", canonical, "-t", login], timeout: 120).code == 0 else { throw RouterError.io }
        receipt.undone = true; try JSONFile.write(receipt, to: url)
    }
}
