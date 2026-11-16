import Foundation
import Darwin

func rejected(_ body:() throws->Void) { do { try body();fatalError("accepted forbidden input") } catch {} }
@main struct Tests {
 static func main() throws {
    for good in ["198.18.75.1","198.18.75.253","fdc7:7652:9a10:75::1","fdc7:7652:9a10:75::fd"] { assert(validateAddress(good),good) }
    for bad in ["127.0.0.1","0.0.0.0","1.1.1.1","198.18.75.0","198.18.75.254","198.18.75.255","198.18.75.1/24","198.18.74.2","fdc7:7652:9a10:75::fe","::","::1","--help","198.18.75.1; touch /tmp/x"] { assert(!validateAddress(bad),bad) }
    let input:[String:Any]=["op":"begin","domains":[approvedDomains[0]],"ports":[approvedPorts[0]],"password":String(repeating:"a",count:48)]
    _=try validateBegin(input)
    for (key,value) in [("domains",["com"]) as (String,Any),("domains",["../../etc"]),("ports",[22]),("command","/bin/sh"),("password","bad\nvalue"),("domains",[])] {
        var changed=input;changed[key]=value;rejected { _=try validateBegin(changed) }
    }
    let b=Broker();let owner=UUID()
    for op in ["route","publish","heartbeat","stop","exec"] { rejected { _=try b.request(["op":op],owner:owner) } }
    let status=try b.request(["op":"status"],owner:owner);assert(status["active"] as? Bool == false)
    rejected { try checkRootPath("/private/tmp",directory:true) }
    rejected { try checkRootPath("/tmp",directory:true) }
    // Regression for a child created/stopped on different dispatch workers.
    let devnull=open("/dev/null",O_WRONLY);defer { close(devnull) }
    let child=try spawn("/bin/sleep",["10"],output:devnull)
    let done=DispatchSemaphore(value:0)
    DispatchQueue.global().async {
        child.terminate();let end=Date().addingTimeInterval(2)
        while child.isRunning && Date()<end { Thread.sleep(forTimeInterval:0.01) }
        assert(!child.isRunning);done.signal()
    }
    assert(done.wait(timeout:.now()+3) == .success)
    // Preserve a real startup exit status; do not report cleanup's SIGTERM as
    // the reason for an adapter failure, or ECHILD as a successful exit(0).
    let failed=try spawn("/bin/sh",["-c","exit 7"],output:devnull)
    let until=Date().addingTimeInterval(2)
    while failed.isRunning && Date()<until { Thread.sleep(forTimeInterval:0.01) }
    let failure=AdapterFailureEvidence(stage:.interfaceWait,started:ProcessInfo.processInfo.systemUptime,
        identityMilliseconds:0,interfaceIndex:0,child:failed)
    assert(failure.childRunning == false && failure.waitStatus == 7 << 8 && failure.waitErrno == nil)
    let sleeper=try spawn("/bin/sleep",["10"],output:devnull)
    defer { if sleeper.isRunning { kill(sleeper.pid,SIGKILL) } }
    kill(sleeper.pid,SIGSTOP)
    var stopped:AdapterFailureEvidence!
    let stoppedDeadline=Date().addingTimeInterval(2)
    repeat {
        stopped=AdapterFailureEvidence(stage:.interfaceWait,started:ProcessInfo.processInfo.systemUptime,
            identityMilliseconds:123,interfaceIndex:0,child:sleeper)
        if stopped.processState == 4 { break };Thread.sleep(forTimeInterval:0.01)
    } while Date()<stoppedDeadline
    assert(stopped.childRunning == true && stopped.processState == 4 && stopped.waitStatus == nil)
    kill(sleeper.pid,SIGCONT);sleeper.terminate()
    let exitDeadline=Date().addingTimeInterval(2)
    while sleeper.isRunning && Date()<exitDeadline { Thread.sleep(forTimeInterval:0.01) }
    assert(!sleeper.isRunning && sleeper.result & 0x7f == SIGTERM)
    assert(stopped.childRunning == true && stopped.waitStatus == nil) // immutable pre-cleanup evidence
    let unknown=Child(getpid()) // Not our child; waitpid returns ECHILD.
    let lost=AdapterFailureEvidence(stage:.identity,started:ProcessInfo.processInfo.systemUptime,
        identityMilliseconds:nil,interfaceIndex:0,child:unknown)
    assert(lost.waitStatus == nil && lost.waitErrno == ECHILD)
    let decoded=try JSONDecoder().decode(AdapterFailureEvidence.self,from:JSONEncoder().encode(stopped))
    b.lastAdapterFailure=decoded
    let diagnostic=(try b.request(["op":"status"],owner:owner))["lastAdapterFailure"] as! [String:Any]
    assert(diagnostic["processState"] as? UInt32 == 4)
    assert(diagnostic["password"] == nil && diagnostic["arguments"] == nil && diagnostic["log"] == nil)
    for (executable,args,timeout,reason) in [
        ("/bin/sleep",["10"],0.05,"COMMAND_TIMEOUT"),
        ("/usr/bin/yes",["fixture"],2.0,"COMMAND_OUTPUT_LIMIT")
    ] {
        do { _=try command(executable,args,timeout:timeout);fatalError("command should fail") }
        catch { assert(String(describing:error) == reason) }
        reapCommands();assert(pendingCommandReaps.isEmpty)
        var status:Int32=0
        assert(waitpid(-1,&status,WNOHANG) == -1 && errno == ECHILD,"failed command left an unreaped child")
    }
    print("PASS address/policy bounds, injection/unknown operations, per-connection ownership and idle status")
    print("PASS real child exit, suspended startup, pre-cleanup evidence, ECHILD, schema round trip and metadata-only status")
    print("PASS timed-out and output-limited commands are killed and reaped without zombies")
 }
}
