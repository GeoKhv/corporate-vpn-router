import Foundation

// Exercise the local enrollment decoder, IPC validator and sing-box rule builder as
// the released helper without changing launchd, resolvers or routing.
@main struct PortableTests {
    static func main() throws {
        let arguments = CommandLine.arguments
        let domain = arguments[1], desktop = arguments[2]
        func policy(_ domains: [String], _ name: String) throws -> LocalRoutePolicy {
            try LocalRoutePolicy.decode(jsonData(["domains":domains,"desktop":name]))
        }
        precondition(approvedDomains.isEmpty && approvedRDPHost.isEmpty)
        localPolicy = try policy([domain], "")
        precondition(approvedRDPHost.isEmpty)
        for (domains, name) in [([domain], "outside.invalid"), (["../../etc"], ""), (["com"], ""),
                                (["192.0.2.1"], ""), ([domain,domain], ""), ([], "")] {
            do { _ = try policy(domains,name); fatalError("accepted invalid local rules") }
            catch is HelperFailure {}
        }
        localPolicy = try policy([domain], desktop)
        let status = try Broker().request(["op":"status"], owner: UUID())
        precondition(status["build"] as? String == "0.3.20")
        let base: [String:Any] = ["op":"begin", "domains":[domain], "ports":[443],
                                  "password":String(repeating:"a",count:48)]
        _ = try validateBegin(base)
        var rdp = base
        rdp["rdpSlot"] = 12
        let (_, ports, _, slot) = try validateBegin(rdp)
        let rules = adapterRules(ports:ports, rdpSlot:slot)
        precondition(rules[1]["override_address"] as? String == desktop)
        precondition(rules[1]["ip_cidr"] as? [String] == ["198.18.75.12/32","fdc7:7652:9a10:75::c/128"])
        precondition(rules[2]["action"] as? String == "reject")
        for change in [["rdpHost":"other." + domain], ["ports":[443,3389]],
                       ["domains":["example.invalid"]], ["rdpSlot":255]] as [[String:Any]] {
            do {
                _ = try validateBegin(rdp.merging(change) { _, new in new })
                fatalError("accepted unauthorized request")
            } catch is HelperFailure {}
        }
        print("PASS portable helper release policy, exact RDP, HTTPS, local enrollment and rejected destinations")
    }
}
