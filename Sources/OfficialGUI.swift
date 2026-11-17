import AppKit

enum OfficialGUI {
    static let url = URL(fileURLWithPath: "/Applications/Endpoint Security VPN.app")
    static let vendor = "anchor apple generic and certificate leaf[subject.OU] = \"TZ3UEPFYKD\""
    static func compatible(checkPort: Bool) -> Bool {
        let guis = NSWorkspace.shared.runningApplications.filter { $0.bundleURL?.standardizedFileURL == url.standardizedFileURL }
        let owners = command("/usr/sbin/lsof",["-nP","-a","-iTCP:7779","-sTCP:LISTEN","-Fp"])
            .output.components(separatedBy:.newlines).filter{$0.hasPrefix("p")}.compactMap{Int32($0.dropFirst())}
        guard !checkPort || owners.allSatisfy({pid in guis.contains{$0.processIdentifier == pid}}) else { return false }
        return guis.isEmpty || command("/usr/bin/codesign",["--verify","--strict","-R="+vendor+" and identifier \"com.checkpoint.eps_vpn.ui\"",url.path]).code == 0
    }
    static func allSitesIdle(_ output: String) -> Bool {
        var inSite = false, seenIdle = false
        for line in output.components(separatedBy: .newlines) {
            let field = line.trimmingCharacters(in: .whitespaces)
            let key = field.lowercased()
            if key.hasPrefix("conn ") || key.hasPrefix("conn\t") {
                guard (!inSite || seenIdle), field.hasSuffix(":") else { return false }
                inSite = true; seenIdle = false
            } else if key.hasPrefix("status:") {
                guard inSite, !seenIdle, field.dropFirst(7).trimmingCharacters(in: .whitespaces) == "Idle" else { return false }
                seenIdle = true
            }
        }
        return inSite && seenIdle
    }
    static func closeIfIdle(checkPort: Bool = true) -> Bool {
        let trac = "/Library/Application Support/Checkpoint/Endpoint Connect/trac"
        guard command("/usr/bin/codesign", ["--verify","--strict","-R="+vendor+" and identifier \"trac\"",trac]).code == 0 else { return false }
        func idle() -> Bool {
            let r = command(trac, ["info"], timeout:12)
            return r.code == 0 && allSitesIdle(r.output)
        }
        guard idle() else { return false }
        guard compatible(checkPort:checkPort), idle() else { return false }
        let guis = NSWorkspace.shared.runningApplications.filter { $0.bundleURL?.standardizedFileURL == url.standardizedFileURL }
        // NSRunningApplication.terminate requests the app's normal Quit. A clean
        // exit satisfies the vendor LaunchAgent's SuccessfulExit=false policy.
        return guis.allSatisfy { $0.terminate() }
    }
}
