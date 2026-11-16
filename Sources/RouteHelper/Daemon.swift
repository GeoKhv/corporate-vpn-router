import Foundation
import Darwin
import CryptoKit

func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format:"%02x", $0) }.joined() }
let fm = FileManager.default
let ioQueue = DispatchQueue(label: routeHelperLabel + ".serial")

func checkRootPath(_ path: String, directory: Bool) throws {
    var info = stat()
    guard lstat(path, &info) == 0, info.st_uid == 0, info.st_mode & 0o022 == 0,
          info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) else { throw HelperFailure("UNTRUSTED_ROOT_PATH: " + path) }
}
func checkParents(_ path: String) throws {
    var current = URL(fileURLWithPath: path).deletingLastPathComponent().path
    while true { try checkRootPath(current, directory:true); if current == "/" { break }; current = URL(fileURLWithPath:current).deletingLastPathComponent().path }
}
func secureDirectory(_ path: String) throws {
    try checkParents(path)
    if !fm.fileExists(atPath:path) { guard mkdir(path, 0o700) == 0 else { throw HelperFailure("MKDIR_FAILED") } }
    try checkRootPath(path, directory:true)
}
func syncDirectory(_ path: String) {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    if fd >= 0 { _ = fsync(fd); close(fd) }
}
func writeRoot(_ data: Data, _ path: String, mode: mode_t = 0o600, exclusive: Bool = false) throws {
    try checkParents(path)
    let temp = path + "." + UUID().uuidString + ".new"
    let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
    guard fd >= 0 else { throw HelperFailure("CREATE_FAILED") }
    defer { close(fd); unlink(temp) }
    try data.withUnsafeBytes { raw in
        var count = 0
        while count < raw.count {
            let n = write(fd, raw.baseAddress!.advanced(by:count), raw.count-count)
            guard n > 0 else { throw HelperFailure("WRITE_FAILED") }; count += n
        }
    }
    guard fchmod(fd, mode) == 0, fsync(fd) == 0 else { throw HelperFailure("SYNC_FAILED") }
    if exclusive {
        guard link(temp,path) == 0 else { throw HelperFailure("EXISTING_FILE_PRESERVED") }
        unlink(temp)
    } else {
        var info = stat()
        if lstat(path,&info) == 0 { try checkRootPath(path,directory:false) }
        guard rename(temp,path) == 0 else { throw HelperFailure("RENAME_FAILED") }
    }
    syncDirectory(URL(fileURLWithPath:path).deletingLastPathComponent().path)
}

// POSIX children have bounded waits. Foundation Process.waitUntilExit can
// strand a serial dispatch worker when a long-lived child was started on a
// different worker thread; root cleanup must never depend on that run loop.
final class Child {
    let pid: pid_t
    var finished=false, result:Int32=0
    private(set) var statusKnown=false, waitError:Int32?
    init(_ pid:pid_t) { self.pid=pid }
    var isRunning:Bool {
        if finished { return false }
        var status:Int32=0
        let r=waitpid(pid,&status,WNOHANG)
        if r==pid { finished=true;result=status;statusKnown=true;return false }
        if r<0 && errno==ECHILD { finished=true;waitError=errno;return false }
        return true
    }
    var processIdentifier:pid_t { pid }
    func terminate() { if isRunning { kill(pid,SIGTERM) } }
}

// Capture BEFORE cleanup sends SIGTERM/SIGKILL. An empty warn-level log does
// not distinguish an early exit, a suspended process, and a startup timeout.
// This schema contains no arguments, configuration, domains or credentials.
enum AdapterStartupStage: String, Codable {
    case configuration, spawn, identity, interfaceWait, prepared
}
struct AdapterFailureEvidence: Codable {
    let schema: Int
    let time: Double
    let stage: AdapterStartupStage
    let elapsedMilliseconds: Double
    let identityMilliseconds: Double?
    let interfaceIndex: UInt32
    let childPID: Int32?
    let childRunning: Bool?
    let waitStatus: Int32?
    let waitErrno: Int32?
    let processState: UInt32?
    let processInfoErrno: Int32?
    var logSHA256: String?

    init(stage: AdapterStartupStage, started: TimeInterval, identityMilliseconds: Double?,
         interfaceIndex: UInt32, child: Child?) {
        schema=1;time=Date().timeIntervalSince1970;self.stage=stage
        elapsedMilliseconds=max(0,(ProcessInfo.processInfo.systemUptime-started)*1000)
        self.identityMilliseconds=identityMilliseconds;self.interfaceIndex=interfaceIndex
        childPID=child?.pid;childRunning=child?.isRunning
        waitStatus=child?.statusKnown == true ? child?.result : nil
        waitErrno=child?.waitError
        var info=proc_bsdinfo()
        if let child,childRunning == true {
            let size=Int32(MemoryLayout<proc_bsdinfo>.size)
            let count=proc_pidinfo(child.pid,PROC_PIDTBSDINFO,0,&info,size)
            processState=count == size ? info.pbi_status : nil
            processInfoErrno=count == size ? nil : errno
        } else { processState=nil;processInfoErrno=nil }
    }
    func object() throws -> [String:Any] { try jsonObject(JSONEncoder().encode(self)) }
}

// Only the serial broker queue accesses these abandoned command children.
// A kill is not a wait: retain a slow-to-exit child until the timer can reap it.
var pendingCommandReaps=[Child]()
func killCommand(_ child:Child) {
    if child.isRunning { kill(child.pid,SIGKILL) }
    let end=ProcessInfo.processInfo.systemUptime+0.25
    while child.isRunning && ProcessInfo.processInfo.systemUptime<end { Thread.sleep(forTimeInterval:0.01) }
    if child.isRunning { pendingCommandReaps.append(child) }
}
func reapCommands() { pendingCommandReaps.removeAll { !$0.isRunning } }
func spawn(_ executable:String,_ arguments:[String],output:Int32) throws -> Child {
    var actions:posix_spawn_file_actions_t?;var attrs:posix_spawnattr_t?
    posix_spawn_file_actions_init(&actions);posix_spawnattr_init(&attrs)
    defer { posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attrs) }
    posix_spawn_file_actions_addopen(&actions,STDIN_FILENO,"/dev/null",O_RDONLY,0)
    posix_spawn_file_actions_adddup2(&actions,output,STDOUT_FILENO)
    posix_spawn_file_actions_adddup2(&actions,output,STDERR_FILENO)
    if output>2 { posix_spawn_file_actions_addclose(&actions,output) }
    var defaults:sigset_t=0,mask:sigset_t=0
    sigemptyset(&defaults);sigaddset(&defaults,SIGTERM);sigaddset(&defaults,SIGINT);sigaddset(&defaults,SIGPIPE);sigemptyset(&mask)
    posix_spawnattr_setsigdefault(&attrs,&defaults);posix_spawnattr_setsigmask(&attrs,&mask)
    posix_spawnattr_setflags(&attrs,Int16(POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_CLOEXEC_DEFAULT))
    let av=([executable]+arguments).map { strdup($0) }+[nil]
    let environment: [String] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin","LANG=C"]
    let ev: [UnsafeMutablePointer<CChar>?] = environment.map { strdup($0) }+[nil]
    defer { for p in av+ev { free(p) } }
    var pid:pid_t=0
    let rc=av.withUnsafeBufferPointer { argv in ev.withUnsafeBufferPointer { env in
        posix_spawn(&pid,executable,&actions,&attrs,argv.baseAddress!,env.baseAddress!)
    } }
    guard rc==0 else { throw HelperFailure("SPAWN_FAILED: \(rc)") }
    return Child(pid)
}
func command(_ executable:String,_ arguments:[String],timeout:TimeInterval = 8) throws -> (Int32,String) {
    var fds:[Int32]=[0,0];guard pipe(&fds)==0 else { throw HelperFailure("PIPE_FAILED") }
    let child:Child
    do { child=try spawn(executable,arguments,output:fds[1]) }
    catch { close(fds[0]);close(fds[1]);throw error }
    close(fds[1]);defer { close(fds[0]) }
    _=fcntl(fds[0],F_SETFL,O_NONBLOCK)
    var result=Data(),buffer=[UInt8](repeating:0,count:8192)
    let end=Date().addingTimeInterval(timeout)
    while true {
        let n=read(fds[0],&buffer,buffer.count)
        if n>0 { result.append(contentsOf:buffer.prefix(n)); if result.count>1048576 { killCommand(child);throw HelperFailure("COMMAND_OUTPUT_LIMIT") };continue }
        if !child.isRunning { break }
        if Date()>end { killCommand(child);throw HelperFailure("COMMAND_TIMEOUT") }
        Thread.sleep(forTimeInterval:0.01)
    }
    return (child.result,String(decoding:result,as:UTF8.self))
}
func processIdentity(_ pid: Int32) -> String {
    (try? command("/bin/ps",["-p",String(pid),"-o","lstart=","-o","comm="]).1.trimmingCharacters(in:.whitespacesAndNewlines)) ?? ""
}
func validateAddress(_ address: String) -> Bool {
    var a4 = in_addr(); var a6 = in6_addr()
    if inet_pton(AF_INET,address,&a4) == 1 {
        let n = UInt32(bigEndian:a4.s_addr)
        return n >> 8 == 0xc6124b && (1...253).contains(n & 255)
    }
    if inet_pton(AF_INET6,address,&a6) == 1 {
        let bytes = withUnsafeBytes(of:&a6) { Array($0) }
        return Array(bytes.prefix(15)) == [0xfd,0xc7,0x76,0x52,0x9a,0x10,0,0x75,0,0,0,0,0,0,0] && (1...253).contains(bytes[15])
    }
    return false
}
func validateBegin(_ input: [String:Any]) throws -> ([String],[Int],String) {
    guard Set(input.keys) == Set(["op","domains","ports","password"]),
          let domains=input["domains"] as? [String], !domains.isEmpty,
          Set(domains).count == domains.count, Set(domains).isSubset(of:Set(approvedDomains)),
          let ports=input["ports"] as? [Int], !ports.isEmpty, Set(ports).isSubset(of:Set(approvedPorts)),
          let password=input["password"] as? String, password.count == 48,
          password.allSatisfy({ "0123456789abcdef".contains($0) }) else { throw HelperFailure("OUTSIDE_APPROVED_POLICY") }
    return (domains,ports,password)
}

final class Broker {
    let home: String, state: String
    var journal: [String:Any] = [:]
    var adapter: Child?
    var lease: UUID?
    var beat = Date.distantPast
    var error: String?
    var lastAdapterFailure: AdapterFailureEvidence?
    init(home:String = routeHelperHome,state:String = routeHelperState) { self.home=home;self.state=state }
    var journalPath: String { state + "/session.json" }
    func persist() throws { try writeRoot(try jsonData(journal),journalPath) }
    func recover() throws {
        try secureDirectory(state)
        let evidencePath=state+"/last-adapter-failure.json"
        if fm.fileExists(atPath:evidencePath),
           (try? checkRootPath(evidencePath,directory:false)) != nil,
           let size=(try? fm.attributesOfItem(atPath:evidencePath)[.size]) as? NSNumber,
           size.intValue <= 16384,
           let data=try? Data(contentsOf:URL(fileURLWithPath:evidencePath)),
           let evidence=try? JSONDecoder().decode(AdapterFailureEvidence.self,from:data),evidence.schema == 1 {
            lastAdapterFailure=evidence
        }
        if fm.fileExists(atPath:journalPath) {
            try checkRootPath(journalPath,directory:false)
            journal = try jsonObject(Data(contentsOf:URL(fileURLWithPath:journalPath)))
            try cleanup("daemon restart")
        }
    }
    func liveInterface() -> UInt32 { if_nametoindex("utun73") }
    func resolverData(_ domain:String) -> Data {
        Data("# CVR Route Helper \(journal["id"] as! String)\ndomain \(domain)\nnameserver 127.0.0.1\nport 53541\nsearch_order 1000\ntimeout 1\n".utf8)
    }
    func begin(_ input:[String:Any],owner:UUID) throws -> [String:Any] {
        guard journal.isEmpty, lease == nil else { throw HelperFailure("SESSION_BUSY_OR_CLEANUP_REQUIRED") }
        let (domains,ports,password)=try validateBegin(input)
        guard liveInterface() == 0 else { throw HelperFailure("UTUN73_IN_USE") }
        let resolver="/private/etc/resolver"
        try checkParents(resolver)
        if fm.fileExists(atPath:resolver) { try checkRootPath(resolver,directory:true) }
        for d in domains {
            var st=stat(); guard lstat(resolver+"/"+d,&st) != 0 && errno == ENOENT else { throw HelperFailure("EXISTING_RESOLVER_PRESERVED") }
        }
        try checkRootPath(home+"/sing-box",directory:false)
        guard digest(try Data(contentsOf:URL(fileURLWithPath:home+"/sing-box"))) == adapterSHA256 else { throw HelperFailure("ADAPTER_HASH_MISMATCH") }
        journal=["schema":1,"id":UUID().uuidString,"domains":domains,"resolvers":[],"routes":[],"madeResolverDirectory":!fm.fileExists(atPath:resolver)]
        lease=owner;beat=Date();try persist()
        let started=ProcessInfo.processInfo.systemUptime
        var startupStage=AdapterStartupStage.configuration
        var identityMilliseconds:Double?
        var logWasReset=false
        do {
            let config:[String:Any] = ["log":["level":"warn","timestamp":true],
                "inbounds":[["type":"tun","tag":"work-tun","interface_name":"utun73","address":["198.18.73.1/32","fdc7:7652:9a10::1/128"],"mtu":1500,"auto_route":false,"dns_mode":"disabled","stack":"gvisor"]],
                "outbounds":[["type":"socks","tag":"verified-work","server":"127.0.0.1","server_port":11090,"version":"5","username":"trial","password":password]],
                "route":["rules":[["inbound":["work-tun"],"network":"tcp","port":ports,"action":"route","outbound":"verified-work"],["action":"reject","no_drop":true]]]]
            try writeRoot(try jsonData(config),state+"/adapter.json")
            try writeRoot(Data(),state+"/adapter.log")
            logWasReset=true
            let log=open(state+"/adapter.log",O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC)
            guard log>=0 else { throw HelperFailure("ADAPTER_LOG_FAILED") }
            let p:Child
            startupStage = .spawn
            do { p=try spawn(home+"/sing-box",["run","-c",state+"/adapter.json"],output:log) }
            catch { close(log);throw error }
            close(log);adapter=p
            startupStage = .identity
            let identityStarted=ProcessInfo.processInfo.systemUptime
            journal["adapterPID"]=p.processIdentifier;journal["adapterIdentity"]=processIdentity(p.processIdentifier);try persist()
            identityMilliseconds=(ProcessInfo.processInfo.systemUptime-identityStarted)*1000
            startupStage = .interfaceWait
            let deadline=Date().addingTimeInterval(10)
            while liveInterface() == 0 && p.isRunning && Date()<deadline { Thread.sleep(forTimeInterval:0.05) }
            guard p.isRunning && liveInterface() != 0 else { throw HelperFailure("ADAPTER_START_FAILED") }
            journal["interfaceIndex"]=liveInterface();try persist()
            startupStage = .prepared
            return ["ok":true,"state":"prepared"]
        } catch {
            var evidence=AdapterFailureEvidence(stage:startupStage,started:started,
                identityMilliseconds:identityMilliseconds,interfaceIndex:liveInterface(),child:adapter)
            // Failure to save diagnostics must never prevent route cleanup or
            // replace the original failure. Successful starts keep this record.
            // Keep the failed process's bounded log even after the next begin
            // truncates adapter.log. It stays root-only and is never in status.
            let path=state+"/adapter.log"
            if logWasReset,(try? checkRootPath(path,directory:false)) != nil,
               let handle=try? FileHandle(forReadingFrom:URL(fileURLWithPath:path)) {
                defer { try? handle.close() }
                if let size=try? handle.seekToEnd(),
                   (try? handle.seek(toOffset:size > 65536 ? size-65536 : 0)) != nil,
                   let log=try? handle.read(upToCount:65536) {
                    if (try? writeRoot(log,state+"/last-adapter-failure.log")) != nil { evidence.logSHA256=digest(log) }
                }
            }
            lastAdapterFailure=evidence
            try? writeRoot(try JSONEncoder().encode(evidence),state+"/last-adapter-failure.json")
            try? cleanup("start failed"); throw error
        }
    }
    func addRoutes(_ addresses:[String]) throws {
        guard addresses.count <= 16, addresses.allSatisfy(validateAddress),
              let index=journal["interfaceIndex"] as? UInt32, index == liveInterface(), adapter?.isRunning == true else { throw HelperFailure("INVALID_ROUTE_OR_INTERFACE") }
        var routes=journal["routes"] as! [String]
        for address in Set(addresses).sorted() where !routes.contains(address) {
            let family=address.contains(":") ? "-inet6":"-inet"
            let actual=try command("/sbin/route",["-n","get",family,address]).1
            // An exact pre-existing host route is someone else's, even if it
            // happens to use our interface. Do not adopt or overwrite it.
            if actual.contains("HOST") { throw HelperFailure("EXISTING_HOST_ROUTE_PRESERVED") }
            routes.append(address);journal["routes"]=routes;try persist()
            let result=try command("/sbin/route",["-n","add",family,"-host",address,"-interface","utun73"])
            guard result.0 == 0 else { throw HelperFailure("ROUTE_ADD_FAILED") }
            let check=try command("/sbin/route",["-n","get",family,address]).1
            guard check.contains("interface: utun73"),check.contains("HOST") else { throw HelperFailure("ROUTE_VERIFY_FAILED") }
        }
    }
    func publish() throws {
        let resolver="/private/etc/resolver"
        if !fm.fileExists(atPath:resolver) { guard mkdir(resolver,0o755)==0,chmod(resolver,0o755)==0 else { throw HelperFailure("RESOLVER_DIRECTORY_FAILED") } }
        try checkRootPath(resolver,directory:true)
        for d in journal["domains"] as! [String] {
            var made=journal["resolvers"] as! [String]
            if made.contains(d) { continue }
            made.append(d);journal["resolvers"]=made;try persist()
            try writeRoot(resolverData(d),resolver+"/"+d,mode:0o644,exclusive:true)
        }
    }
    func cleanup(_ reason:String) throws {
        guard !journal.isEmpty else { lease=nil;return }
        // Stop packet capture before removing any owned route. launchd also
        // kills the job's children on broker death (AbandonProcessGroup=false).
        if let p=adapter,p.isRunning {
            p.terminate();let until=Date().addingTimeInterval(3)
            while p.isRunning && Date()<until { Thread.sleep(forTimeInterval:0.05) }
            if p.isRunning { kill(p.processIdentifier,SIGKILL) }
            let hardDeadline=Date().addingTimeInterval(3)
            while p.isRunning && Date()<hardDeadline { Thread.sleep(forTimeInterval:0.02) }
            guard !p.isRunning else { throw HelperFailure("ADAPTER_STOP_TIMEOUT") }
        } else if let pid=journal["adapterPID"] as? Int32,let identity=journal["adapterIdentity"] as? String,
                  !identity.isEmpty, identity.hasSuffix(home+"/sing-box"), processIdentity(pid)==identity {
            kill(pid,SIGTERM);Thread.sleep(forTimeInterval:0.2)
            if processIdentity(pid)==identity { kill(pid,SIGKILL) }
        }
        adapter=nil
        var conflicts=[String]()
        for domain in journal["resolvers"] as? [String] ?? [] {
            guard approvedDomains.contains(domain) else { throw HelperFailure("INVALID_JOURNAL_DOMAIN") }
            let path="/private/etc/resolver/"+domain
            var st=stat()
            if lstat(path,&st)==0 {
                if st.st_uid==0,st.st_mode&S_IFMT==S_IFREG,st.st_mode&0o022==0,try Data(contentsOf:URL(fileURLWithPath:path))==resolverData(domain) { guard unlink(path)==0 else { throw HelperFailure("RESOLVER_REMOVE_FAILED") } }
                else { conflicts.append(domain) }
            }
        }
        for address in journal["routes"] as? [String] ?? [] {
            guard validateAddress(address) else { throw HelperFailure("INVALID_JOURNAL_ROUTE") }
            let family=address.contains(":") ? "-inet6":"-inet"
            let actual=try command("/sbin/route",["-n","get",family,address]).1
            if actual.contains("interface: utun73"),actual.contains("HOST") {
                guard let index=journal["interfaceIndex"] as? UInt32,index==liveInterface() else { throw HelperFailure("ROUTE_OWNERSHIP_CHANGED") }
                guard try command("/sbin/route",["-n","delete",family,"-host",address,"-interface","utun73"]).0==0 else { throw HelperFailure("ROUTE_REMOVE_FAILED") }
            }
        }
        if journal["madeResolverDirectory"] as? Bool == true { _=rmdir("/private/etc/resolver") }
        guard liveInterface()==0 else { throw HelperFailure("INTERFACE_REMAINS") }
        let result:[String:Any] = ["ok":true,"reason":reason,"interface_present":false,"resolver_conflicts_preserved":conflicts,"at":Date().timeIntervalSince1970]
        try writeRoot(try jsonData(result),state+"/last-cleanup.json")
        guard unlink(journalPath)==0 else { throw HelperFailure("JOURNAL_REMOVE_FAILED") };syncDirectory(state)
        unlink(state+"/adapter.json");journal=[:];lease=nil;error=nil
    }
    func request(_ input:[String:Any],owner:UUID) throws -> [String:Any] {
        guard let op=input["op"] as? String else { throw HelperFailure("INVALID_OPERATION") }
        if op=="status" {
            var status:[String:Any] = ["ok":true,"version":helperBuild,"active":lease != nil,"cleanupPending":!journal.isEmpty && lease==nil,"error":error ?? "", "approvedDomains":approvedDomains,"approvedPorts":approvedPorts]
            if let evidence=lastAdapterFailure { status["lastAdapterFailure"]=try evidence.object() }
            return status
        }
        if op=="begin" { return try begin(input,owner:owner) }
        guard lease==owner else { throw HelperFailure("NO_SESSION") }
        beat=Date()
        switch op {
        case "heartbeat": guard Set(input.keys)==["op"] else { throw HelperFailure("INVALID_REQUEST") }
        case "route":
            guard Set(input.keys)==["op","addresses"],let addresses=input["addresses"] as? [String] else { throw HelperFailure("INVALID_REQUEST") }
            try addRoutes(addresses)
        case "publish": guard Set(input.keys)==["op"] else { throw HelperFailure("INVALID_REQUEST") };try publish()
        case "stop": try cleanup("client stop")
        default:throw HelperFailure("INVALID_OPERATION")
        }
        return ["ok":true]
    }
    func tick() {
        reapCommands()
        if lease == nil {
            if !journal.isEmpty { do { try cleanup("retry pending cleanup") } catch { self.error=String(describing:error) } }
            return
        }
        if Date().timeIntervalSince(beat)>20 || adapter?.isRunning != true { do { try cleanup("lease expired or adapter exited") } catch { self.error=String(describing:error);lease=nil } }
    }
}

final class Peer: NSObject, RouteHelperProtocol {
    let id=UUID(),broker:Broker
    init(_ broker:Broker) { self.broker=broker }
    func request(_ data:Data,reply:@escaping (Data)->Void) {
        ioQueue.async {
            do { reply(try jsonData(self.broker.request(jsonObject(data),owner:self.id))) }
            catch { reply(try! jsonData(["ok":false,"error":String(describing:error)])) }
        }
    }
}
final class Listener: NSObject,NSXPCListenerDelegate {
    let uid:uid_t,broker:Broker
    init(_ uid:uid_t,_ broker:Broker) { self.uid=uid;self.broker=broker }
    func listener(_ listener:NSXPCListener,shouldAcceptNewConnection connection:NSXPCConnection)->Bool {
        guard connection.effectiveUserIdentifier==uid else { return false }
        connection.setCodeSigningRequirement("cdhash H\""+clientCDHash+"\"")
        let peer=Peer(broker)
        connection.exportedInterface=NSXPCInterface(with:RouteHelperProtocol.self);connection.exportedObject=peer
        connection.invalidationHandler={ ioQueue.async { if self.broker.lease==peer.id { do { try self.broker.cleanup("client EOF") } catch { self.broker.error=String(describing:error);self.broker.lease=nil } } } }
        connection.resume();return true
    }
}

func install(_ uid:uid_t) throws {
    guard uid>=501,getpwuid(uid) != nil else { throw HelperFailure("INVALID_OWNER") }
    let exe=URL(fileURLWithPath:CommandLine.arguments[0]).resolvingSymlinksInPath()
    let payload=exe.deletingLastPathComponent().appendingPathComponent("sing-box")
    let binary=try Data(contentsOf:payload)
    guard digest(binary)==adapterSHA256 else { throw HelperFailure("ADAPTER_HASH_MISMATCH") }
    // An authorized update may replace only an idle instance. No forced
    // disconnect, arbitrary destination, or arbitrary executable is accepted.
    if fm.fileExists(atPath:routeHelperState+"/session.json") { throw HelperFailure("STOP_ROUTES_BEFORE_INSTALL") }
    try secureDirectory(routeHelperHome);try secureDirectory(routeHelperState)
    guard chmod(routeHelperHome,0o755)==0 else { throw HelperFailure("INSTALL_PERMISSIONS_FAILED") }
    if fm.fileExists(atPath:routeHelperPlist) {
        try checkRootPath(routeHelperPlist,directory:false)
        let old=try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:routeHelperPlist)),format:nil) as? [String:Any]
        guard let args=old?["ProgramArguments"] as? [String],args==[routeHelperHome+"/RouteHelper","--daemon",String(uid)] else { throw HelperFailure("EXISTING_INSTALLATION_PRESERVED") }
        _=try command("/bin/launchctl",["bootout","system/"+routeHelperLabel])
    }
    try writeRoot(binary,routeHelperHome+"/sing-box",mode:0o755)
    try writeRoot(try Data(contentsOf:exe),routeHelperHome+"/RouteHelper",mode:0o755)
    let plist:[String:Any] = ["Label":routeHelperLabel,"ProgramArguments":[routeHelperHome+"/RouteHelper","--daemon",String(uid)],"MachServices":[routeHelperLabel:true],"RunAtLoad":true,"KeepAlive":true,"ThrottleInterval":3,"ExitTimeOut":15,"AbandonProcessGroup":false,"ProcessType":"Background","Umask":63]
    try writeRoot(try PropertyListSerialization.data(fromPropertyList:plist,format:.xml,options:0),routeHelperPlist,mode:0o644)
    let result=try command("/bin/launchctl",["bootstrap","system",routeHelperPlist]);guard result.0==0 else { throw HelperFailure("LAUNCHD_BOOTSTRAP_FAILED: "+result.1) }
}
func uninstall() throws {
    if fm.fileExists(atPath:routeHelperState+"/session.json") { throw HelperFailure("STOP_ROUTES_BEFORE_UNINSTALL") }
    try checkRootPath(routeHelperPlist,directory:false)
    let result=try command("/bin/launchctl",["bootout","system/"+routeHelperLabel])
    guard result.0==0 || result.1.contains("Could not find service") else { throw HelperFailure("BOOTOUT_FAILED") }
    unlink(routeHelperPlist)
    // Only fixed product-owned files; no recursive deletion, user paths, or
    // removal of the shared Router settings/domain map/official Check Point.
    for name in ["RouteHelper","sing-box"] { unlink(routeHelperHome+"/"+name) }
    for name in ["adapter.json","adapter.log","last-cleanup.json","last-adapter-failure.json","last-adapter-failure.log"] { unlink(routeHelperState+"/"+name) }
    _=rmdir(routeHelperHome);_=rmdir(routeHelperState)
}
#if !CVR_HELPER_TEST
@main struct RouteDaemon {
    static func main() {
        umask(0o077)
        do {
            guard geteuid()==0 else { throw HelperFailure("ADMIN_INSTALLATION_REQUIRED") }
            let args=Array(CommandLine.arguments.dropFirst())
            if args.count==2,args[0]=="--install",let uid=uid_t(args[1]) { try install(uid);return }
            if args==["--uninstall"] { try uninstall();return }
            guard args.count==2,args[0]=="--daemon",let uid=uid_t(args[1]),uid>=501 else { throw HelperFailure("INVALID_OPERATION") }
            try checkParents(routeHelperHome+"/RouteHelper");try checkRootPath(routeHelperHome+"/RouteHelper",directory:false)
            let broker=Broker();try broker.recover()
            let delegate=Listener(uid,broker),listener=NSXPCListener(machServiceName:routeHelperLabel);listener.delegate=delegate;listener.resume()
            let timer=DispatchSource.makeTimerSource(queue:ioQueue);timer.schedule(deadline:.now()+1,repeating:1);timer.setEventHandler { broker.tick() };timer.resume()
            signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN)
            let term=DispatchSource.makeSignalSource(signal:SIGTERM,queue:ioQueue);term.setEventHandler { try? broker.cleanup("daemon shutdown");exit(0) };term.resume()
            withExtendedLifetime((delegate,listener,timer,term)) { dispatchMain() }
        } catch { fputs("RouteHelper: \(error)\n",stderr);exit(1) }
    }
}
#endif
