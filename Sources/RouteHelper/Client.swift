import Foundation
import Darwin

// The daemon authenticates this exact hardened executable with an XPC code
// requirement on every message, as well as the enrolled effective UID.
@main struct RouteClient {
    static func main() {
        let connection = NSXPCConnection(machServiceName: routeHelperLabel, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: RouteHelperProtocol.self)
        connection.resume()
        defer { connection.invalidate() }
        while let line = readLine() {
            guard line.utf8.count <= 65536, let data = line.data(using: .utf8) else { exit(2) }
            let sem = DispatchSemaphore(value: 0)
            var response = try! jsonData(["ok": false, "error": "HELPER_UNAVAILABLE"])
            let proxy = connection.remoteObjectProxyWithErrorHandler { _ in sem.signal() } as! RouteHelperProtocol
            proxy.request(data) { value in response = value; sem.signal() }
            guard sem.wait(timeout: .now() + 30) == .success else { exit(3) }
            print(String(decoding: response, as: UTF8.self)); fflush(stdout)
        }
        // EOF invalidates the lease even when the owning Python/app was killed.
    }
}
