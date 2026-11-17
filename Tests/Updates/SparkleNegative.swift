import Foundation
import AppKit
import Sparkle
import CryptoKit

// Disposable real-SPUUpdater integration; no production keys or app processes.
final class Driver: NSObject, SPUUserDriver {
    let scenario:String
    var updater:SPUUpdater!, cancellation:(()->Void)?
    var downloaded:UInt64=0
    var found=false, cancelled=false
    init(_ scenario:String) {self.scenario=scenario;super.init()}
    func finish(_ result:String,_ success:Bool) -> Never {
        print("\(success ? "PASS" : "FAIL") \(scenario): \(result), bytes=\(downloaded)");fflush(stdout);exit(success ? 0:1)
    }
    func show(_ request:SPUUpdatePermissionRequest,reply:@escaping(SUUpdatePermissionResponse)->Void){reply(.init(automaticUpdateChecks:false,sendSystemProfile:false))}
    func showUserInitiatedUpdateCheck(cancellation:@escaping()->Void){}
    func showUpdateFound(with item:SUAppcastItem,state:SPUUserUpdateState,reply:@escaping(SPUUserUpdateChoice)->Void){found=true;reply(.install)}
    func showUpdateReleaseNotes(with data:SPUDownloadData){}
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error:Error){}
    func showUpdateNotFoundWithError(_ error:Error,acknowledgement:@escaping()->Void){finish("no update",false)}
    func showUpdaterError(_ error:Error,acknowledgement:@escaping()->Void){
        let e=error as NSError
        // Verify the refusal came from the expected stage, not an unrelated test setup error.
        let expected = scenario == "wrong-signature" ? 3002 : 2001
        var chain=[e]; var current=e
        while let inner=current.userInfo[NSUnderlyingErrorKey] as? NSError {chain.append(inner);current=inner}
        print("Error chain:",chain.map { "\($0.domain):\($0.code) \($0.localizedDescription)" })
        finish("\(e.domain):\(e.code) \(e.localizedDescription)",found && chain.contains { $0.domain=="SUSparkleErrorDomain" && $0.code==expected })
    }
    func showDownloadInitiated(cancellation:@escaping()->Void){self.cancellation=cancellation}
    func showDownloadDidReceiveExpectedContentLength(_ value:UInt64){}
    func showDownloadDidReceiveData(ofLength length:UInt64){
        downloaded+=length
        if scenario=="cancel",!cancelled {cancelled=true;cancellation?()}
    }
    func showDownloadDidStartExtractingUpdate(){}
    func showExtractionReceivedProgress(_ progress:Double){}
    func showReady(toInstallAndRelaunch reply:@escaping(SPUUserUpdateChoice)->Void){reply(.skip);finish("unexpected install-ready",false)}
    func showInstallingUpdate(withApplicationTerminated terminated:Bool,retryTerminatingApplication:@escaping()->Void){finish("unexpected install",false)}
    func showUpdateInstalledAndRelaunched(_ value:Bool,acknowledgement:@escaping()->Void){finish("unexpected installed",false)}
    func dismissUpdateInstallation(){if scenario=="cancel",cancelled {finish("download cancelled; no install",true)}}
}
let args=Array(CommandLine.arguments.dropFirst())
if args.first=="--fixtures" {
    let root=URL(fileURLWithPath:args[1]),port=args[2]
    let key=Curve25519.Signing.PrivateKey()
    try key.publicKey.rawRepresentation.base64EncodedString().write(to:root.appendingPathComponent("public-key.txt"),atomically:true,encoding:.utf8)
    let payload=try Data(contentsOf:root.appendingPathComponent("source-archive.zip"))
    try payload.write(to:root.appendingPathComponent("payload"))
    for scenario in ["wrong-signature","interrupted","cancel"] {
        // Signature is deliberately for different bytes in wrong-signature case.
        let sig=try key.signature(for:scenario=="wrong-signature" ? Data("wrong".utf8):payload).base64EncodedString()
        let xml="""
        <?xml version="1.0" encoding="utf-8"?><rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Test only</title><item><title>0.3.1</title><sparkle:version>3001</sparkle:version><sparkle:shortVersionString>0.3.1</sparkle:shortVersionString><sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion><enclosure url="http://127.0.0.1:\(port)/\(scenario).zip" length="\(payload.count)" type="application/octet-stream" sparkle:edSignature="\(sig)"/></item></channel></rss>
        """
        let data=Data(xml.utf8),signature=try key.signature(for:data).base64EncodedString()
        try (data+Data("<!-- sparkle-signatures:\nedSignature: \(signature)\nlength: \(data.count)\n-->\n".utf8)).write(to:root.appendingPathComponent(scenario+".xml"))
    }
    print("Test fixtures signed by ephemeral key held only in memory")
} else {
    let app=NSApplication.shared
    let driver=Driver(args[0])
    driver.updater=SPUUpdater(hostBundle:.main,applicationBundle:.main,userDriver:driver,delegate:nil)
    do {try driver.updater.start();driver.updater.checkForUpdates()}
    catch {driver.finish(error.localizedDescription,false)}
    DispatchQueue.main.asyncAfter(deadline:.now()+30){driver.finish("timeout",false)}
    withExtendedLifetime(driver){app.run()}
}
