import Foundation
import Security

struct ApprovedCertificateEntry: Codable {
    var sha256: String
    var file: String
    var subject: String
    var hosts: [String]
}
struct ApprovedCertificateManifest: Codable {
    var schema: Int
    var provenance: String
    var certificates: [ApprovedCertificateEntry]
}
struct CertificateImportEvidence {
    var result: HTTPSCertificateResult
    var candidates: [SecCertificate]
    var captured = Date()
    var sourceKind = "OWNER_APPROVED_EXISTING_KEYCHAIN_AND_VERIFIED_CHAIN"
}
struct CertificatePlanResult {
    var valid: Bool
    var needed: Set<String>
    var explanation: String
}

enum CertificatePlan {
    static func load(_ resources: URL) throws -> (ApprovedCertificateManifest, [SecCertificate]) {
        let dir = resources.appendingPathComponent("ApprovedCertificates")
        let manifest = try JSONDecoder().decode(ApprovedCertificateManifest.self, from: Data(contentsOf: dir.appendingPathComponent("manifest.json")))
        guard manifest.schema == 1, manifest.provenance == "OWNER_APPROVED_EXISTING_KEYCHAIN_AND_VERIFIED_CHAIN",
              (1...16).contains(manifest.certificates.count) else { throw RouterError.invalidConfiguration }
        let certificates = try manifest.certificates.map { entry -> SecCertificate in
            let sha = Certificates.canonicalFingerprint(entry.sha256)
            guard sha.count == 64, sha.allSatisfy({ $0.isHexDigit }), entry.file == sha + ".cer" else { throw RouterError.invalidConfiguration }
            let cert = try Certificates.parse(Data(contentsOf: dir.appendingPathComponent(entry.file)))
            let info = Certificates.describe(cert)
            guard info.isCA, info.currentlyValid, Certificates.canonicalFingerprint(info.sha256) == sha else { throw RouterError.invalidConfiguration }
            return cert
        }
        return (manifest, certificates)
    }

    static func evaluate(_ peer: [SecCertificate], host: String, candidates: [SecCertificate]) -> Bool {
        guard !peer.isEmpty, Configuration.validHost(host) else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates((peer + candidates) as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess, let trust else { return false }
        SecTrustSetNetworkFetchAllowed(trust, false)
        let roots = candidates.filter { Certificates.describe($0).selfIssued }
        if !roots.isEmpty {
            SecTrustSetAnchorCertificates(trust, roots as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, false)
        }
        return SecTrustEvaluateWithError(trust, nil)
    }

    static func assess(_ evidence: CertificateImportEvidence) -> CertificatePlanResult {
        let fail = CertificatePlanResult(valid: false, needed: [], explanation: "Цепочка, имя или срок сертификата не прошли проверку. Импорт заблокирован.")
        guard Date().timeIntervalSince(evidence.captured) < 600,
              let peer = try? evidence.result.peerDER.map(Certificates.parse), !peer.isEmpty,
              evidence.candidates.allSatisfy({ let i = Certificates.describe($0); return i.isCA && i.currentlyValid }) else { return fail }
        if evidence.result.tlsTrusted { return .init(valid: true, needed: [], explanation: "HTTPS уже доверен. Импорт не требуется.") }
        guard evaluate(peer, host: evidence.result.host, candidates: evidence.candidates) else { return fail }
        // Find a sufficient minimal addition for this Mac, including its existing
        // trust and the actual peer-supplied intermediates. No fixed CA count.
        var needed = evidence.candidates
        for candidate in evidence.candidates {
            let trial = needed.filter { Certificates.fingerprint($0) != Certificates.fingerprint(candidate) }
            if evaluate(peer, host: evidence.result.host, candidates: trial) { needed = trial }
        }
        let inventory = Certificates.inventorySnapshot()
        guard inventory.complete else { return .init(valid: false, needed: [], explanation: "Не удалось полностью проверить Keychain; импорт заблокирован.") }
        let installed = Set(inventory.certificates.map(Certificates.fingerprint))
        let hashes = Set(needed.map(Certificates.fingerprint))
        guard hashes.isDisjoint(with: installed) else { return .init(valid: false, needed: [], explanation: "Сертификат уже есть, но его доверие требует проверки. Существующие настройки не заменяются.") }
        return .init(valid: true, needed: hashes, explanation: hashes.isEmpty ? "Добавление CA не требуется; повторите HTTPS-проверку." : "Цепочка с проверенным набором проходит. Требуется добавить CA: \(hashes.count). Изменений доверия ещё нет.")
    }
}
