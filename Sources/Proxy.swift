import Foundation
import Darwin

final class RouterService {
    let configuration: Configuration
    let platform: VPNPlatform
    let statusURL: URL
    private let lock = NSLock()
    private var current: Link?
    private var observedAt = Date.distantPast
    private var generation: UInt64 = 0
    private var sessions: [UUID: Session] = [:]
    private var state = "WAITING_FOR_VPN", reason = "STARTING"
    private var listener: OwnedSocket?
    private var stopped = false
    private let monitorQueue = DispatchQueue(label: "corporate-vpn-router.monitor", qos: .userInitiated)
    private let watchdogQueue = DispatchQueue(label: "corporate-vpn-router.watchdog", qos: .userInitiated)
    private var monitor: DispatchSourceTimer?, watchdog: DispatchSourceTimer?

    init(configuration: Configuration, platform: VPNPlatform, statusURL: URL) {
        self.configuration = configuration; self.platform = platform; self.statusURL = statusURL
    }

    func refresh() {
        let started = Date()
        let snapshot = platform.discover(dnsServers: configuration.dnsServers)
        let fresh = Date().timeIntervalSince(started) < 6
        lock.locked {
            guard !stopped else { return }
            let next = fresh ? snapshot.link : nil
            if next != current {
                current = next; generation &+= 1
                sessions.values.forEach { $0.cancel() }
                state = next == nil ? "WAITING_FOR_VPN" : "TUNNEL_READY"
            }
            observedAt = started
            if next == nil { state = "WAITING_FOR_VPN"; reason = fresh ? snapshot.reason : "NETWORK_STATE_STALE" }
            else if state == "WAITING_FOR_VPN" { state = "TUNNEL_READY"; reason = "TUNNEL_READY" }
            else if state == "TUNNEL_READY" { reason = "TUNNEL_READY" }
        }
        persist()
    }

    func checkFreshness() {
        var changed = false
        lock.locked {
            let age = Date().timeIntervalSince(observedAt)
            if current != nil && (age > 6 || age < 0) {
                current = nil; generation &+= 1; state = "WAITING_FOR_VPN"; reason = "NETWORK_STATE_STALE"
                sessions.values.forEach { $0.cancel() }; changed = true
            }
        }
        if changed { persist() }
    }

    func acquire() throws -> (Link, UInt64) {
        checkFreshness()
        return try lock.locked { guard let link = current, !stopped else { throw RouterError.vpnUnavailable }; return (link, generation) }
    }

    func validate(_ link: Link, _ token: UInt64) throws {
        let pair = try acquire()
        guard pair.0 == link && pair.1 == token else { throw RouterError.staleNetwork }
    }

    func status() -> PublicStatus {
        lock.locked { PublicStatus(state: state, reason: reason, listen: "127.0.0.1:\(configuration.listenPort)", activeConnections: sessions.count, generation: generation) }
    }
    func persist() { try? JSONFile.write(status(), to: statusURL) }

    func serveClient(_ client: OwnedSocket, session: Session) {
        var success = false
        do {
            client.timeouts(5)
            let greeting = try client.exact(2)
            guard greeting[0] == 5, greeting[1] > 0 else { throw RouterError.destinationDenied }
            let methods = try client.exact(Int(greeting[1]))
            guard methods.contains(0) else { try client.write([5, 255]); return }
            try client.write([5, 0])
            let request = try client.exact(4)
            guard request == [5, 1, 0, 3] else { throw RouterError.destinationDenied }
            let size = Int(try client.exact(1)[0])
            guard size > 0, let raw = String(bytes: try client.exact(size), encoding: .ascii) else { throw RouterError.destinationDenied }
            let host = raw.lowercased().hasSuffix(".") ? String(raw.lowercased().dropLast()) : raw.lowercased()
            let port = try DNS.u16(client.exact(2), 0)
            guard configuration.permits(host, port: port) else { throw RouterError.destinationDenied }
            let (link, token) = try acquire()
            let addresses = try platform.resolve(host: host, servers: configuration.dnsServers, link: link, session: session)
            try validate(link, token)
            var upstream: OwnedSocket?
            for addr in addresses where Configuration.safeDestination(addr) {
                try validate(link, token)
                guard platform.routeAllowed(address: addr, link: link) else { continue }
                do { upstream = try platform.connect(address: addr, port: port, link: link, session: session); break }
                catch { continue }
            }
            guard let remote = upstream else { throw RouterError.routeDenied }
            defer { session.remove(remote) }
            try validate(link, token); try session.check()
            try client.write([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]); success = true
            lock.locked { state = "READY"; reason = "LAST_CONNECTION_SUCCEEDED" }; persist()
            client.timeouts(600); remote.timeouts(600)
            let group = DispatchGroup()
            func pump(_ source: OwnedSocket, _ target: OwnedSocket) {
                defer { group.leave() }
                do {
                    while true {
                        let bytes = try source.read(65536)
                        try self.validate(link, token); try session.check()
                        if bytes.isEmpty { _ = Darwin.shutdown(target.fd, SHUT_WR); return }
                        try target.write(bytes)
                    }
                } catch { session.cancel() }
            }
            group.enter(); DispatchQueue.global().async { pump(client, remote) }
            group.enter(); DispatchQueue.global().async { pump(remote, client) }
            group.wait()
        } catch {
            if !success { try? client.write([5, 4, 0, 1, 0, 0, 0, 0, 0, 0]) }
            if let e = error as? RouterError, e != .destinationDenied {
                lock.locked { if current != nil { state = "CONNECTION_BLOCKED"; reason = e.rawValue } }; persist()
            }
        }
    }

    func run() throws {
        signal(SIGPIPE, SIG_IGN)
        let server = try OwnedSocket(Darwin.socket(AF_INET, SOCK_STREAM, 0))
        var one: Int32 = 1
        setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var local = try address("127.0.0.1", port: configuration.listenPort)
        guard withAddress(&local, { Darwin.bind(server.fd, $0, $1) }) == 0,
              Darwin.listen(server.fd, 64) == 0 else { throw RouterError.io }
        lock.locked { listener = server }; persist()
        let m = DispatchSource.makeTimerSource(flags: .strict, queue: monitorQueue); monitor = m
        m.schedule(deadline: .now(), repeating: 2); m.setEventHandler { self.refresh() }; m.resume()
        let w = DispatchSource.makeTimerSource(flags: .strict, queue: watchdogQueue); watchdog = w
        w.schedule(deadline: .now(), repeating: 0.5); w.setEventHandler { self.checkFreshness() }; w.resume()
        while !lock.locked({ stopped }) {
            var readiness = pollfd(fd: server.fd, events: Int16(POLLIN), revents: 0)
            if Darwin.poll(&readiness, 1, 500) <= 0 { continue }
            if lock.locked({ stopped }) { break }
            let fd = Darwin.accept(server.fd, nil, nil)
            if fd < 0 { if errno == EINTR { continue }; break }
            guard let client = try? OwnedSocket(fd) else { continue }
            let session = Session(), id = UUID()
            let admitted = lock.locked { () -> Bool in
                guard sessions.count < 64, !stopped else { return false }; sessions[id] = session; return true
            }
            if !admitted { client.close(); continue }
            try session.add(client)
            DispatchQueue.global().async {
                defer {
                    session.cancel(); session.remove(client)
                    _ = self.lock.locked { self.sessions.removeValue(forKey: id) }; self.persist()
                }
                self.serveClient(client, session: session)
            }
        }
        server.close()
    }

    func stop() {
        lock.locked {
            stopped = true; state = "STOPPED"; reason = "SERVICE_STOPPED"; current = nil
            sessions.values.forEach { $0.cancel() }; listener?.cancel()
        }
        monitor?.cancel(); watchdog?.cancel(); persist()
    }
}
