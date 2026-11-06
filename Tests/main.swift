import Foundation
import Darwin

if CommandLine.arguments.contains("--command-io-fixture") {
    let result = command("/bin/sh", ["-c", "printf fixture-stdout; printf fixture-stderr >&2; if read value; then exit 9; fi"])
    print("\(result.code):\(result.output)")
    exit(0)
}

setbuf(stdout, nil)
var passed = 0
func expect(_ condition: @autoclosure () throws -> Bool, _ name: String) {
    do { guard try condition() else { fatalError("FAIL: \(name)") } }
    catch { fatalError("FAIL: \(name): \(error)") }
    passed += 1; print("PASS \(name)")
}
func rejects(_ name: String, _ body: () throws -> Void) { do { try body(); fatalError("FAIL: \(name)") } catch { passed += 1; print("PASS \(name)") } }

var config = Configuration()
config.domains = ["corp.example.com"]; config.dnsServers = ["192.0.2.53"]
expect(try config.validated() == config, "valid configuration")
expect(config.permits("wiki.corp.example.com", port: 443), "suffix subdomain permitted")
expect(!config.permits("evilcorp.example.com", port: 443), "suffix boundary")
expect(!config.permits("corp.example.com.evil.example", port: 443), "suffix spoof denied")
expect(!config.permits("corp.example.com", port: 80), "port denied")
expect(!Configuration.validHost("192.0.2.1"), "literal IPv4 denied")
expect(!Configuration.validHost("-bad.example.com"), "invalid DNS label denied")
expect(!Configuration.validHost("a..example.com"), "empty label denied")
expect(!Configuration.validHost("a/evil.example.com"), "non DNS characters denied")
expect(!Configuration.safeDestination("127.0.0.1"), "loopback DNS result denied")
expect(!Configuration.safeDestination("169.254.169.254"), "link local denied")
expect(!Configuration.safeDestination("224.0.0.1"), "multicast denied")
expect(!Configuration.safeDestination("0.0.0.1"), "zero network denied")
var invalid = config; invalid.dnsServers = ["127.0.0.1"]
rejects("local resolver rejected") { _ = try invalid.validated() }
invalid = config; invalid.domains = []
rejects("empty policy rejected") { _ = try invalid.validated() }
invalid = config; invalid.schemaVersion = 2
rejects("unknown schema rejected") { _ = try invalid.validated() }
invalid = config; invalid.listenPort = 80
rejects("privileged listener rejected") { _ = try invalid.validated() }

let host = "wiki.corp.example.com", id: UInt16 = 42
var packet = DNS.query(host: host, id: id)
packet[2] = 0x81; packet[3] = 0x80; packet[7] = 1
packet += [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 10]
expect(try DNS.answers(packet, host: host, id: id) == ["192.0.2.10"], "compressed DNS A answer")
rejects("wrong DNS id") { _ = try DNS.answers(packet, host: host, id: 43) }
rejects("wrong DNS question") { _ = try DNS.answers(packet, host: "other.example.com", id: id) }
rejects("short DNS message") { _ = try DNS.answers([0], host: host, id: id) }
rejects("DNS pointer cycle") { _ = try DNS.name([0xc0, 0], 0) }
var truncated = packet; truncated[2] |= 2
rejects("truncated UDP not accepted as final answer") { _ = try DNS.answers(truncated, host: host, id: id) }
var nxdomain = packet; nxdomain[3] |= 3
rejects("NXDOMAIN rejected") { _ = try DNS.answers(nxdomain, host: host, id: id) }
rejects("partial DNS RDATA rejected") { _ = try DNS.answers(Array(packet.dropLast()), host: host, id: id) }
for n in 0..<packet.count {
    _ = try? DNS.answers(Array(packet.prefix(n)), host: host, id: id)
}
expect(true, "all DNS truncation boundaries handled")

final class FakeAdapter: VPNPlatform {
    let lock = NSLock()
    var available = true, routes = true, dnsOK = true
    var signature = "network-a", resolutions = 0, connections = 0
    func discover(dnsServers: [String]) -> Snapshot {
        lock.locked { Snapshot(link: available ? Link(interface: "utun999", index: 999, source: "192.0.2.2", peer: "192.0.2.1", networkSignature: signature) : nil, reason: available ? "TUNNEL_READY" : "CHECKPOINT_LOGIN_REQUIRED") }
    }
    func routeAllowed(address: String, link: Link) -> Bool { lock.locked { routes } }
    func resolve(host: String, servers: [String], link: Link, session: Session) throws -> [String] {
        try lock.locked { resolutions += 1; guard dnsOK else { throw RouterError.dnsUnavailable }; return ["192.0.2.10"] }
    }
    func connect(address: String, port: Int, link: Link, session: Session) throws -> OwnedSocket {
        try lock.locked { guard routes else { throw RouterError.routeDenied }; connections += 1 }
        var pair: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RouterError.io }
        let client = try OwnedSocket(pair[0]), peer = try OwnedSocket(pair[1]); client.timeouts(3); peer.timeouts(3)
        try session.add(client)
        DispatchQueue.global().async {
            defer { peer.close() }
            while let b = try? peer.read(65535), !b.isEmpty { if (try? peer.write(b)) == nil { break } }
        }
        return client
    }
}

let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: tmp) }
let platform = FakeAdapter()
config.listenPort = Int.random(in: 22000...29000)
let service = RouterService(configuration: config, platform: platform, statusURL: tmp.appendingPathComponent("state.json"))
let done = DispatchSemaphore(value: 0)
DispatchQueue.global().async { try! service.run(); done.signal() }
Thread.sleep(forTimeInterval: 0.3); service.refresh()

func socks(_ host: String, port: Int = 443, type: UInt8 = 3, command: UInt8 = 1) throws -> (OwnedSocket, [UInt8]) {
    let c = try OwnedSocket(socket(AF_INET, SOCK_STREAM, 0)); c.timeouts(3)
    try MacOSAdapter().connectSocket(c, address: "127.0.0.1", port: config.listenPort)
    try c.write([5, 1, 0]); expect(try c.exact(2) == [5, 0], "SOCKS greeting")
    let payload: [UInt8] = type == 3 ? [UInt8(host.utf8.count)] + Array(host.utf8) : [192, 0, 2, 10]
    try c.write([5, command, 0, type] + payload + [UInt8(port >> 8), UInt8(port & 255)])
    return (c, try c.exact(10))
}
let (good, goodReply) = try socks(host)
expect(goodReply[1] == 0, "allowlisted domain CONNECT")
try good.write([1, 2, 3]); expect(try good.exact(3) == [1, 2, 3], "duplex relay")

let beforeDenied = platform.lock.locked { platform.resolutions }
for (h, p, t, cmd, label) in [("example.com", 443, UInt8(3), UInt8(1), "outside allowlist"), (host, 80, 3, 1, "disallowed port"), ("192.0.2.10", 443, 1, 1, "literal IP"), (host, 443, 4, 1, "IPv6"), (host, 443, 3, 3, "UDP associate"), ("hidden.onion", 443, 3, 1, "onion")] {
    let (c, reply) = try socks(h, port: p, type: t, command: cmd)
    expect(reply[1] != 0, "reject \(label)"); c.close()
}
expect(platform.lock.locked { platform.resolutions } == beforeDenied, "denied requests produce no DNS")

platform.lock.locked { platform.routes = false }
let beforeRouteDenied = platform.lock.locked { platform.connections }
let (badRoute, deniedRouteReply) = try socks(host)
expect(deniedRouteReply[1] != 0, "external route rejected")
expect(platform.lock.locked { platform.connections } == beforeRouteDenied, "route denial opens no upstream socket")
badRoute.close()
platform.lock.locked { platform.routes = true; platform.dnsOK = false }
let (badDNS, deniedDNSReply) = try socks(host)
expect(deniedDNSReply[1] != 0, "DNS failure blocks connection"); badDNS.close()
expect(platform.lock.locked { platform.connections } == beforeRouteDenied, "DNS failure has no system resolver fallback")

platform.lock.locked { platform.dnsOK = true; platform.available = false }; service.refresh()
expect(try good.read(1).isEmpty, "VPN loss closes existing relay")
good.close()
let resolutionsBeforeLoss = platform.lock.locked { platform.resolutions }
let (offline, offlineReply) = try socks(host)
expect(offlineReply[1] != 0, "VPN loss blocks new request"); offline.close()
expect(platform.lock.locked { platform.resolutions } == resolutionsBeforeLoss, "no DNS while VPN absent")
platform.lock.locked { platform.available = true }; service.refresh()
let (recovered, recoveredReply) = try socks(host)
expect(recoveredReply[1] == 0, "VPN return recovers without stored credentials")
platform.lock.locked { platform.signature = "network-b" }; service.refresh()
expect(try recovered.read(1).isEmpty, "network change closes existing relay"); recovered.close()
let (afterChange, afterChangeReply) = try socks(host)
expect(afterChangeReply[1] == 0, "new network accepts freshly checked relay"); afterChange.close()

service.stop()
expect(done.wait(timeout: .now() + 3) == .success, "service stops listener")
rejects("stopped proxy refuses client connection") { let (c, _) = try socks(host); c.close() }

// Real Darwin socket option acceptance, without external traffic.
let local = Link(interface: "lo0", index: if_nametoindex("lo0"), source: "127.0.0.1", peer: "127.0.0.1", networkSignature: "loopback-test")
let boundSession = Session()
let bound = try MacOSAdapter().bound(type: SOCK_DGRAM, link: local, session: boundSession)
var boundIndex: UInt32 = 0, boundSize = socklen_t(MemoryLayout<UInt32>.size)
expect(getsockopt(bound.fd, IPPROTO_IP, IP_BOUND_IF, &boundIndex, &boundSize) == 0 && boundIndex == local.index, "Darwin IP_BOUND_IF applied and read back")
boundSession.remove(bound)

let caURL = URL(fileURLWithPath: ProcessInfo.processInfo.environment["CVR_TEST_CA_FILE"]!)
let caData = try Data(contentsOf: caURL), ca = try Certificates.parse(caData)
let caInfo = Certificates.describe(ca)
expect(caInfo.isCA && caInfo.selfIssued && caInfo.currentlyValid, "public CA constraints and validity inspected")
expect(caInfo.subject.contains("Corporate VPN Router Test CA") && caInfo.issuer == caInfo.subject, "CA subject and issuer read")
expect(!caInfo.presentInKeychain && !caInfo.basicSystemTrust, "test CA remains absent and untrusted")
expect(Certificates.canonicalFingerprint(caInfo.sha256).count == 64, "SHA-256 fingerprint generated")
rejects("private key text rejected") { _ = try Certificates.parse(Data("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----".utf8)) }
rejects("certificate bundle rejected") { _ = try Certificates.parse(caData + caData) }
let certPaths = ProductPaths(root: tmp.path)
rejects("CA import without consent blocked") { try Certificates.importConfirmed(ca, expectedSHA256: caInfo.sha256, sourceURL: "https://it.example.com/ca", consent: false, paths: certPaths) }
rejects("CA fingerprint mismatch blocked") { try Certificates.importConfirmed(ca, expectedSHA256: String(repeating: "0", count: 64), sourceURL: "https://it.example.com/ca", consent: true, paths: certPaths) }
rejects("insecure CA source blocked") { try Certificates.importConfirmed(ca, expectedSHA256: caInfo.sha256, sourceURL: "http://it.example.com/ca", consent: true, paths: certPaths) }
rejects("credential-bearing CA source blocked") { try Certificates.importConfirmed(ca, expectedSHA256: caInfo.sha256, sourceURL: "https://user:secret@it.example.com/ca", consent: true, paths: certPaths) }
rejects("token-bearing CA source blocked") { try Certificates.importConfirmed(ca, expectedSHA256: caInfo.sha256, sourceURL: "https://it.example.com/ca?token=secret", consent: true, paths: certPaths) }
expect(Certificates.receipts(certPaths).isEmpty, "rejected CA imports produce no mutation receipt")
rejects("unowned CA undo blocked") { try Certificates.undoConfirmed(caInfo.sha256, consent: true, paths: certPaths) }
expect(!Certificates.inventory().contains { Certificates.fingerprint($0) == caInfo.sha256 }, "certificate rejection tests leave Keychain unchanged")

let childDone = DispatchSemaphore(value: 0)
DispatchQueue.global().async {
    let r = command("/bin/echo", ["background-child"])
    expect(r.code == 0 && r.output == "background-child\n", "child command reaped without main run loop")
    childDone.signal()
}
expect(childDone.wait(timeout: .now() + 6) == .success, "background process deadline")

let child = Process(), childInput = Pipe(), childOutput = Pipe(), childErrors = Pipe()
child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]); child.arguments = ["--command-io-fixture"]
child.standardInput = childInput; child.standardOutput = childOutput; child.standardError = childErrors
try child.run()
childInput.fileHandleForWriting.write(Data("must-not-reach-vendor-command\n".utf8)); try childInput.fileHandleForWriting.close()
child.waitUntilExit()
expect(child.terminationStatus == 0, "command I/O fixture exits normally")
expect(String(data: childOutput.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) == "0:fixture-stdout\n", "vendor command stdin isolated and stdout captured")
expect(childErrors.fileHandleForReading.readDataToEndOfFile().isEmpty, "vendor stderr does not escape to caller")
let deadlineStart = Date(), timedCommand = command("/bin/sleep", ["2"], timeout: 0.15)
expect(timedCommand.code != 0 && Date().timeIntervalSince(deadlineStart) < 1, "vendor command timeout kills and reaps child")

final class TLSFixtureAdapter: VPNPlatform {
    func discover(dnsServers: [String]) -> Snapshot { Snapshot(link: Link(interface: "test", index: 1, source: "192.0.2.2", peer: "192.0.2.1", networkSignature: "test"), reason: "TUNNEL_READY") }
    func routeAllowed(address: String, link: Link) -> Bool { true }
    func resolve(host: String, servers: [String], link: Link, session: Session) throws -> [String] { ["192.0.2.10"] }
    func connect(address: String, port: Int, link: Link, session: Session) throws -> OwnedSocket {
        let s = try OwnedSocket(Darwin.socket(AF_INET, SOCK_STREAM, 0)); s.timeouts(3)
        try MacOSAdapter().connectSocket(s, address: "127.0.0.1", port: Int(ProcessInfo.processInfo.environment["CVR_TLS_FIXTURE_PORT"]!)!)
        try session.add(s); return s
    }
}
let untrusted = HTTPSCertificates.inspect(host: host, configuration: config, platform: TLSFixtureAdapter())
expect(!untrusted.tlsTrusted && untrusted.httpStatus == nil, "untrusted TLS never sends HTTPS")
expect(untrusted.issue.hasPrefix("TLS_TRUST_FAILED_"), "system trust failure is explicit: \(untrusted.issue)")
expect(untrusted.certificates.contains { $0.sha256 == caInfo.sha256 }, "untrusted peer chain can be reviewed without trusting it")

print("\(passed) checks passed. Fault simulations do not certify real sleep, reboot or network switching.")
