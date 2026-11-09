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
    static func closeIfIdle(checkPort: Bool = true) -> Bool {
        let trac = "/Library/Application Support/Checkpoint/Endpoint Connect/trac"
        guard command("/usr/bin/codesign", ["--verify","--strict","-R="+vendor+" and identifier \"trac\"",trac]).code == 0 else { return false }
        func idle() -> Bool {
            let r = command(trac, ["info"], timeout:12)
            let states = r.output.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespaces)}.filter{$0.hasPrefix("status:")}
            return r.code == 0 && states == ["status: Idle"]
        }
        guard idle() else { return false }
        guard compatible(checkPort:checkPort), idle() else { return false }
        let guis = NSWorkspace.shared.runningApplications.filter { $0.bundleURL?.standardizedFileURL == url.standardizedFileURL }
        // NSRunningApplication.terminate requests the app's normal Quit. A clean
        // exit satisfies the vendor LaunchAgent's SuccessfulExit=false policy.
        return guis.allSatisfy { $0.terminate() }
    }
}
