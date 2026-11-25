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
        precondition(systemDNSMismatch("", slot: 2))
        precondition(systemDNSMismatch("ip_address: 192.0.2.3", slot: 2))
        precondition(!systemDNSMismatch("name: work.invalid\nip_address: 198.18.75.2\nipv6_address: fdc7:7652:9a10:0075:0:0:0:2", slot: 2))
        precondition(!systemDNSMismatch("error: lookup failed", slot: 2))
        let broker = Broker(), owner = UUID()
        precondition(status["allowCheckPointStart"] as? Bool == false)
        let ensure: [String:Any] = ["op":"ensureCheckPointService"]
        do { _ = try broker.request(ensure, owner:owner); fatalError("unenrolled start") }
        catch let e as HelperFailure { precondition(e.description == "CHECKPOINT_START_NOT_AUTHORIZED") }
        localPolicy = try LocalRoutePolicy.decode(jsonData(["domains":[domain], "desktop":desktop, "allowCheckPointStart":true]))
        do { _ = try broker.request(["op":"ensureCheckPointService", "path":"/tmp/job"], owner:owner); fatalError("custom launch job") }
        catch let e as HelperFailure { precondition(e.description == "CHECKPOINT_START_NOT_AUTHORIZED") }
        broker.lease = owner
        do { _ = try broker.request(ensure, owner:owner); fatalError("start during active session") }
        catch let e as HelperFailure { precondition(e.description == "HELPER_SESSION_PENDING") }
        broker.lease = nil

        let label = CheckPointService.label
        let missing: (Int32,String) = (113 << 8, "Could not find service \"" + label + "\" in domain for system")
        let enabled: (Int32,String) = (0, "disabled services = {\n\"" + label + "\" => enabled\n}")
        func simulate(_ replies: [(Int32,String)], trusted: Bool = true) -> ([[String]], String?) {
            var calls = [[String]]()
            do {
                try CheckPointService.restore(verify: {
                    if !trusted { throw HelperFailure("untrusted fixture") }
                }, launchctl: { args in
                    calls.append(args)
                    return replies[calls.count - 1]
                })
                return (calls, nil)
            } catch { return (calls, String(describing:error)) }
        }
        let probe = ["print", CheckPointService.target]
        let load = ["bootstrap", "system", CheckPointService.plist]
        let expected = [probe, ["print-disabled","system"], load]
        let loaded = simulate([(0,"running")])
        precondition(loaded.0 == [probe] && loaded.1 == nil)
        let started = simulate([missing, enabled, (0,"")])
        precondition(started.0 == expected && started.1 == nil)
        let raced = simulate([missing, enabled, (5,""), (0,"registered")])
        precondition(raced.0 == expected + [probe] && raced.1 == nil)
        precondition(simulate([missing, enabled, (5,""), missing]).1 == "CHECKPOINT_BOOTSTRAP_FAILED")
        precondition(simulate([(1,"permission denied")]).1 == "CHECKPOINT_SERVICE_STATE_UNKNOWN")
        precondition(simulate([missing, enabled], trusted:false).1 == "untrusted fixture")
        let disabled = (Int32(0), enabled.1.replacingOccurrences(of:"enabled", with:"disabled"))
        precondition(simulate([missing, disabled]).1 == "CHECKPOINT_SERVICE_DISABLED")
        let repair: [String:Any] = ["op":"refreshDNS", "name":desktop]
        do { _ = try broker.request(repair, owner:owner); fatalError("idle DNS repair") }
        catch let e as HelperFailure { precondition(e.description == "NO_SESSION") }
        broker.lease = owner
        do { _ = try broker.request(repair, owner:UUID()); fatalError("foreign DNS repair") }
        catch let e as HelperFailure { precondition(e.description == "NO_SESSION") }
        do { _ = try broker.request(repair, owner:owner); fatalError("unenrolled DNS repair") }
        catch let e as HelperFailure { precondition(e.description == "DNS_REPAIR_NOT_AUTHORIZED") }
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
        let mainRule: [String:Any] = ["domain":domain,"scope":"tree","anyTCP":false,"ports":[443,8443]]
        let childRule: [String:Any] = ["domain":"restricted."+domain,"scope":"exact","anyTCP":false,"ports":[443]]
        let spareRule: [String:Any] = ["domain":"unused.example.invalid","scope":"exact","anyTCP":false,"ports":[22]]
        let enrolled = try LocalRoutePolicy.decode(jsonData(["domains":[domain,"restricted."+domain,"unused.example.invalid"],"desktop":desktop,"rules":[mainRule,childRule,spareRule]]))
        localPolicy = enrolled
        let narrower = mainRule.merging(["ports":[443]]) { _,new in new }
        let selection = [narrower,childRule]
        let selected = try sessionGrants(selection, approved:enrolled.rules!)
        precondition(selected.count == 2 && selected[0].ports == [443])
        let confirmed = try broker.request(["op":"checkSessionRules","sessionRules":selection], owner:owner)
        precondition(confirmed["ok"] as? Bool == true && localPolicy?.rules?.count == 3)
        var begin = base
        begin.removeValue(forKey:"domains")
        begin["sessionRules"] = selection
        begin["rdpSlot"] = 12
        let (sessionDomains, _, _, desktopSlot) = try broker.prepareSessionRules(begin)
        precondition(sessionDomains == [domain,"restricted."+domain] && desktopSlot == 12)
        precondition(broker.sessionTCPRules.map { $0.ports } == [[443],[443]] && localPolicy?.rules?.count == 3)
        for invalid in [[narrower], [narrower,narrower], [mainRule.merging(["ports":[80]]) { _,new in new },childRule],
                        [childRule.merging(["scope":"tree"]) { _,new in new }]] {
            do { _ = try sessionGrants(invalid, approved:enrolled.rules!); fatalError("unapproved session rules") }
            catch is HelperFailure {}
        }
        print("PASS session uses selected domains and ports, keeps nested restrictions and stored grants")
        print("PASS portable helper release policy, exact RDP, HTTPS, local enrollment and rejected destinations")
    }
}
