import Foundation
import Network
import Security
import Darwin

private final class ProbeBox {
    let lock = NSLock(), done = DispatchSemaphore(value: 0)
    var result: HTTPSCertificateResult
    var finished = false
    var chain: [SecCertificate] = []
    init(host: String) { result = HTTPSCertificateResult(host: host) }
    func finish(_ issue: String) {
        lock.locked { if !finished { finished = true; result.issue = issue; done.signal() } }
    }
}

enum HTTPSCertificates {
    static func inspect(host: String, configuration: Configuration, controlPlane: Bool = false, platform: VPNPlatform = MacOSAdapter()) -> HTTPSCertificateResult {
        let box = ProbeBox(host: host)
        if controlPlane {
            box.result.routeScope = "CHECKPOINT_CONFIGURED_SITE_HTTPS_ONLY_SYSTEM_ROUTE_NOT_IKE"
            guard host == CheckPointPermissions.siteHost(), Configuration.validHost(host) else { box.result.issue = "NOT_CONFIGURED_CHECKPOINT_SITE"; return box.result }
        } else {
            guard configuration.permits(host, port: 443) else { box.result.issue = "HOST_NOT_ALLOWLISTED"; return box.result }
        }
        let session = Session(); defer { session.cancel() }
        do {
            let upstream: OwnedSocket
            if controlPlane {
                upstream = try controlSocket(host: host, session: session)
            } else {
                guard let link = platform.discover(dnsServers: configuration.dnsServers).link else { throw RouterError.vpnUnavailable }
                let answers = try platform.resolve(host: host, servers: configuration.dnsServers, link: link, session: session)
                var found: OwnedSocket?
                for ip in answers where Configuration.safeDestination(ip) {
                    if let s = try? platform.connect(address: ip, port: 443, link: link, session: session) { found = s; break }
                }
                guard let s = found else { throw RouterError.routeDenied }; upstream = s
            }
            defer { session.remove(upstream) }
            // Network.framework owns TLS 1.2/1.3, while a one-use loopback bridge
            // preserves the exact already-bound corporate transport socket.
            let listener = try OwnedSocket(Darwin.socket(AF_INET, SOCK_STREAM, 0))
            var local = try address("127.0.0.1", port: 0)
            guard withAddress(&local, { Darwin.bind(listener.fd, $0, $1) }) == 0, Darwin.listen(listener.fd, 1) == 0 else { throw RouterError.io }
            var size = socklen_t(MemoryLayout<sockaddr_in>.size)
            guard withUnsafeMutablePointer(to: &local, { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener.fd, $0, &size) } }) == 0 else { throw RouterError.io }
            let port = UInt16(bigEndian: local.sin_port)
            let bridgeDone = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                defer { listener.close(); bridgeDone.signal() }
                var ready = pollfd(fd: listener.fd, events: Int16(POLLIN), revents: 0)
                guard poll(&ready, 1, 5000) > 0, let bridge = try? OwnedSocket(Darwin.accept(listener.fd, nil, nil)) else { return }
                defer { bridge.close() }; bridge.timeouts(5); upstream.timeouts(5)
                guard (try? session.add(bridge)) != nil else { return }
                let group = DispatchGroup()
                func copy(_ src: OwnedSocket, _ dst: OwnedSocket) {
                    defer { group.leave() }
                    while (try? session.check()) != nil, let b = try? src.read(65536), !b.isEmpty { if (try? dst.write(b)) == nil { break } }
                    _ = Darwin.shutdown(dst.fd, SHUT_WR)
                }
                group.enter(); DispatchQueue.global().async { copy(bridge, upstream) }
                group.enter(); DispatchQueue.global().async { copy(upstream, bridge) }
                group.wait(); session.remove(bridge)
            }
            // Do not close/reuse an fd while the bridge workers can still read it.
            defer { session.cancel(); bridgeDone.wait() }
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
            let queue = DispatchQueue(label: "corporate-vpn-router.tls-probe.\(UUID().uuidString)", qos: .userInitiated)
            sec_protocol_options_set_challenge_block(tls.securityProtocolOptions, { _, complete in
                box.lock.locked { box.result.clientCertificateRequested = true; box.result.trustExplanation = "The server requested an individual TLS identity. Use your organization's enrollment; this product does not copy keys." }
                complete(nil)
                box.finish("CLIENT_CERTIFICATE_REQUIRED_USE_CORPORATE_ENROLLMENT")
            }, queue)
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
                let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
                SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
                SecTrustSetNetworkFetchAllowed(trust, false)
                var error: CFError?
                let trusted = SecTrustEvaluateWithError(trust, &error)
                let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
                let stillActive = box.lock.locked { () -> Bool in
                    guard !box.finished else { return false }
                    box.chain = chain
                    box.result.tlsTrusted = trusted
                    box.result.trustExplanation = trusted ? "System trust and hostname validation passed. Independently confirm corporate CA authenticity with IT."
                        : error.flatMap { SecCopyErrorMessageString(OSStatus(CFErrorGetCode($0)), nil) as String? } ?? "System TLS trust evaluation failed. Confirm the chain and hostname with IT; do not bypass verification."
                    if !trusted { box.result.issue = "TLS_TRUST_FAILED_\(error.map { CFErrorGetCode($0) } ?? 0)" }
                    return true
                }
                // A negative evaluation always aborts TLS. No permissive callback.
                complete(trusted && stillActive)
                if !trusted { box.finish(box.lock.locked { box.result.issue }) }
            }, queue)
            let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
            let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: parameters)
            defer { connection.stateUpdateHandler = nil; connection.cancel() }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard box.lock.locked({ box.result.tlsTrusted && !box.finished }) else { box.finish("TLS_NOT_VERIFIED"); return }
                    let request = Data("HEAD / HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8)
                    connection.send(content: request, completion: .contentProcessed { error in
                        if error != nil { box.finish("HTTPS_WRITE_FAILED"); return }
                        receiveHeader(connection, box: box, bytes: Data())
                    })
                case .failed:
                    let issue = box.lock.locked { box.result.issue }
                    box.finish(issue.hasPrefix("TLS_TRUST_FAILED_") ? issue : "TLS_HANDSHAKE_FAILED_OR_CLIENT_IDENTITY_REQUIRED")
                case .cancelled: box.finish("TLS_CANCELLED")
                default: break
                }
            }
            connection.start(queue: queue)
            if box.done.wait(timeout: .now() + 25) != .success { box.finish("TLS_TIMEOUT") }
            let chain = box.lock.locked { box.chain }
            let inventory = Certificates.inventorySnapshot()
            let installed = Set(inventory.certificates.map(Certificates.fingerprint))
            let certificates = chain.map { Certificates.describe($0, installed: installed, inventoryComplete: inventory.complete) }
            box.lock.locked { box.result.certificates = certificates }
            return box.lock.locked { box.result }
        } catch { box.result.issue = (error as? RouterError)?.rawValue ?? "LOCAL_ERROR"; return box.result }
    }

    private static func receiveHeader(_ connection: NWConnection, box: ProbeBox, bytes: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, complete, error in
            let accumulated = bytes + (data ?? Data())
            if let text = String(data: accumulated, encoding: .utf8), let line = text.components(separatedBy: "\r\n").first, text.contains("\r\n") {
                let parts = line.split(separator: " ")
                let code = parts.count >= 2 && parts[0].hasPrefix("HTTP/") ? Int(parts[1]) : nil
                box.lock.locked { box.result.httpStatus = code }
                box.finish(code == nil ? "HTTPS_RESPONSE_INVALID" : "TLS_AND_HTTPS_PASS"); return
            }
            if error != nil || complete || accumulated.count >= 4096 { box.finish("HTTPS_RESPONSE_INCOMPLETE"); return }
            receiveHeader(connection, box: box, bytes: accumulated)
        }
    }

    private static func controlSocket(host: String, session: Session) throws -> OwnedSocket {
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &list) == 0 else { throw RouterError.dnsUnavailable }
        defer { if let list { freeaddrinfo(list) } }
        var cursor = list
        while let node = cursor {
            let a = node.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var bytes = a.sin_addr, output = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &bytes, &output, socklen_t(INET_ADDRSTRLEN))
            let ip = String(cString: output)
            if Configuration.safeDestination(ip), let s = try? OwnedSocket(Darwin.socket(AF_INET, SOCK_STREAM, 0)) {
                s.timeouts(5)
                if (try? MacOSAdapter().connectSocket(s, address: ip, port: 443)) != nil { try session.add(s); return s }
            }
            cursor = node.pointee.ai_next
        }
        throw RouterError.io
    }
}
