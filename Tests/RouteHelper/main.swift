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
    print("PASS address/policy bounds, injection/unknown operations, per-connection ownership and idle status")
 }
}
