import Foundation
import Darwin

let tracPath = "/Library/Application Support/Checkpoint/Endpoint Connect/trac"

struct CommandResult { let code: Int32; let output: String }
func command(_ path: String, _ arguments: [String], timeout: Double = 4) -> CommandResult {
    // Temporary files avoid a pipe-buffer deadlock on verbose vendor output.
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    do {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: dir) }
        let output = dir.appendingPathComponent("output")
        FileManager.default.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let handle = try FileHandle(forWritingTo: output); defer { try? handle.close() }
        let nullFD = Darwin.open("/dev/null", O_RDWR | O_CLOEXEC)
        guard nullFD >= 0 else { return CommandResult(code: -1, output: "") }
        defer { Darwin.close(nullFD) }
        // waitpid is independent of Foundation's main run loop. The daemon's
        // main thread accepts sockets and must not delay child reaping.
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { return CommandResult(code: -1, output: "") }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawn_file_actions_adddup2(&actions, handle.fileDescriptor, STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, nullFD, STDERR_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&actions, nullFD, STDIN_FILENO) == 0 else { return CommandResult(code: -1, output: "") }
        var argv = ([path] + arguments).map { strdup($0) } + [nil]
        defer { argv.forEach { if let p = $0 { free(p) } } }
        var environment = ProcessInfo.processInfo.environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { environment.forEach { if let p = $0 { free(p) } } }
        var pid: pid_t = 0
        guard posix_spawn(&pid, path, &actions, nil, &argv, &environment) == 0 else { return CommandResult(code: -1, output: "") }
        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        while true {
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid { break }
            if waited < 0 && errno != EINTR { return CommandResult(code: -1, output: "") }
            if Date() >= deadline { kill(pid, SIGKILL); while waitpid(pid, &status, 0) < 0 && errno == EINTR {}; break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        let data = (try? Data(contentsOf: output)) ?? Data()
        let code = status & 0x7f == 0 ? (status >> 8) & 0xff : -1
        return CommandResult(code: code, output: String(data: data.prefix(262144), encoding: .utf8) ?? "")
    } catch { return CommandResult(code: -1, output: "") }
}

func readCommand(_ path: String, _ args: [String]) -> String {
    for _ in 0..<2 { let r = command(path, args); if r.code == 0 && !r.output.isEmpty { return r.output } }
    return ""
}

final class OwnedSocket {
    let fd: Int32
    private let lock = NSLock()
    private var closed = false
    init(_ fd: Int32) throws {
        guard fd >= 0 else { throw RouterError.io }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { Darwin.close(fd); throw RouterError.io }
        self.fd = fd
    }
    func cancel() { lock.locked { if !closed { _ = Darwin.shutdown(fd, SHUT_RDWR) } } }
    func close() { lock.locked { if !closed { closed = true; _ = Darwin.close(fd) } } }
    deinit { close() }
    func timeouts(_ seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }
    func read(_ size: Int) throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: size)
        let n = Darwin.recv(fd, &b, size, 0)
        guard n >= 0 else { throw RouterError.io }; return Array(b.prefix(n))
    }
    func exact(_ size: Int) throws -> [UInt8] {
        guard (0...65535).contains(size) else { throw RouterError.io }
        var b: [UInt8] = []
        while b.count < size { let p = try read(size-b.count); guard !p.isEmpty else { throw RouterError.io }; b += p }
        return b
    }
    func write(_ bytes: [UInt8]) throws {
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.send(fd, raw.baseAddress!.advanced(by: offset), raw.count-offset, 0)
                guard n > 0 else { throw RouterError.io }; offset += n
            }
        }
    }
}

final class Session {
    private let lock = NSLock()
    private var sockets: [OwnedSocket] = []
    private var cancelled = false
    func add(_ socket: OwnedSocket) throws {
        try lock.locked { guard !cancelled else { throw RouterError.staleNetwork }; sockets.append(socket) }
    }
    func remove(_ socket: OwnedSocket) { lock.locked { sockets.removeAll { $0 === socket } }; socket.close() }
    func cancel() { lock.locked { cancelled = true; sockets.forEach { $0.cancel() } } }
    func check() throws { try lock.locked { if cancelled { throw RouterError.staleNetwork } } }
}

func address(_ text: String, port: Int) throws -> sockaddr_in {
    guard Configuration.validIPv4(text), (0...65535).contains(port) else { throw RouterError.io }
    var a = sockaddr_in(); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    a.sin_family = sa_family_t(AF_INET); a.sin_port = UInt16(port).bigEndian
    guard text.withCString({ inet_pton(AF_INET, $0, &a.sin_addr) }) == 1 else { throw RouterError.io }
    return a
}

func withAddress<T>(_ addr: inout sockaddr_in, _ f: (UnsafePointer<sockaddr>, socklen_t) throws -> T) rethrows -> T {
    try withUnsafePointer(to: &addr) { p in try p.withMemoryRebound(to: sockaddr.self, capacity: 1) { try f($0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
}

final class MacOSAdapter: VPNPlatform {
    func discover(dnsServers: [String]) -> Snapshot {
        let info = readCommand(tracPath, ["info"])
        guard info.components(separatedBy: .newlines).contains(where: { $0.trimmingCharacters(in: .whitespaces) == "status: Connected" }) else {
            return Snapshot(link: nil, reason: FileManager.default.isExecutableFile(atPath: tracPath) ? "CHECKPOINT_LOGIN_REQUIRED" : "CHECKPOINT_NOT_INSTALLED")
        }
        let routes = dnsServers.map { readCommand("/sbin/route", ["-n", "get", $0]) }
        guard let first = routes.first, let iface = field(first, "interface"),
              iface.range(of: "^utun[0-9]+$", options: .regularExpression) != nil,
              let peer = field(first, "gateway"), Configuration.safeDestination(peer),
              routes.allSatisfy({ field($0, "interface") == iface && field($0, "gateway") == peer }) else {
            return Snapshot(link: nil, reason: "CORPORATE_DNS_ROUTE_MISSING")
        }
        let description = readCommand("/sbin/ifconfig", [iface])
        var source: String?
        for line in description.components(separatedBy: .newlines) {
            let p = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            if p.count >= 4 && p[0] == "inet" && p[2] == "-->" && p[3] == peer && p[1] != peer { source = p[1] }
        }
        guard let ip = source, Configuration.safeDestination(ip), description.contains("POINTOPOINT"),
              description.contains("RUNNING"), description.contains("UP"), if_nametoindex(iface) != 0,
              let externalInterface = field(readCommand("/sbin/route", ["-n", "get", "1.1.1.1"]), "interface"), externalInterface != iface else {
            return Snapshot(link: nil, reason: "TUNNEL_IDENTITY_UNCONFIRMED")
        }
        let signature = readCommand("/usr/sbin/scutil", ["--nwi"])
        guard !signature.isEmpty else { return Snapshot(link: nil, reason: "NETWORK_STATE_UNAVAILABLE") }
        return Snapshot(link: Link(interface: iface, index: if_nametoindex(iface), source: ip, peer: peer, networkSignature: signature), reason: "TUNNEL_READY")
    }

    func routeAllowed(address: String, link: Link) -> Bool {
        guard Configuration.safeDestination(address), if_nametoindex(link.interface) == link.index else { return false }
        let route = readCommand("/sbin/route", ["-n", "get", address])
        return field(route, "interface") == link.interface && field(route, "gateway") == link.peer
    }

    func bound(type: Int32, link: Link, session: Session) throws -> OwnedSocket {
        try session.check()
        guard if_nametoindex(link.interface) == link.index else { throw RouterError.staleNetwork }
        let s = try OwnedSocket(Darwin.socket(AF_INET, type, 0))
        s.timeouts(3)
        var index = link.index
        guard setsockopt(s.fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0 else { throw RouterError.io }
        // Verify that the OS accepted the interface constraint before binding source.
        var actual: UInt32 = 0, length = socklen_t(MemoryLayout<UInt32>.size)
        guard getsockopt(s.fd, IPPROTO_IP, IP_BOUND_IF, &actual, &length) == 0, actual == index else { throw RouterError.io }
        var source = try address(link.source, port: 0)
        guard withAddress(&source, { Darwin.bind(s.fd, $0, $1) }) == 0 else { throw RouterError.io }
        try session.add(s); return s
    }

    func connectSocket(_ s: OwnedSocket, address text: String, port: Int) throws {
        let flags = fcntl(s.fd, F_GETFL, 0)
        guard flags >= 0, fcntl(s.fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw RouterError.io }
        defer { _ = fcntl(s.fd, F_SETFL, flags) }
        var target = try address(text, port: port)
        let result = withAddress(&target) { Darwin.connect(s.fd, $0, $1) }
        if result == 0 { return }
        guard errno == EINPROGRESS else { throw RouterError.io }
        var p = pollfd(fd: s.fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&p, 1, 5000) > 0 else { throw RouterError.timeout }
        var error: Int32 = 0, n = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &error, &n) == 0, error == 0 else { throw RouterError.io }
    }

    func connect(address: String, port: Int, link: Link, session: Session) throws -> OwnedSocket {
        guard routeAllowed(address: address, link: link) else { throw RouterError.routeDenied }
        let s = try bound(type: SOCK_STREAM, link: link, session: session)
        do { try connectSocket(s, address: address, port: port); try session.check(); return s }
        catch { session.remove(s); throw error }
    }

    func resolve(host: String, servers: [String], link: Link, session: Session) throws -> [String] {
        let id = UInt16.random(in: 0...UInt16.max), query = DNS.query(host: host, id: id)
        for server in servers {
            try session.check()
            guard routeAllowed(address: server, link: link) else { continue }
            do {
                let s = try bound(type: SOCK_DGRAM, link: link, session: session)
                defer { session.remove(s) }
                try connectSocket(s, address: server, port: 53)
                try s.write(query)
                var bytes = try s.read(65535)
                let flags = bytes.count >= 4 ? try DNS.u16(bytes, 2) : 0
                if flags & 0x200 != 0 {
                    let tcp = try connect(address: server, port: 53, link: link, session: session)
                    defer { session.remove(tcp) }
                    try tcp.write([UInt8(query.count >> 8), UInt8(query.count & 255)] + query)
                    let count = try DNS.u16(tcp.exact(2), 0)
                    bytes = try tcp.exact(count)
                }
                let answers = try DNS.answers(bytes, host: host, id: id)
                try session.check()
                if !answers.isEmpty { return answers }
            } catch { continue }
        }
        throw RouterError.dnsUnavailable
    }
}
