import Foundation

let routeHelperLabel = "com.geokhv.corporate-vpn-router.routes"
let routeHelperHome = "/Library/Application Support/Corporate VPN Router Route Helper"
let routeHelperState = "/private/var/db/com.geokhv.corporate-vpn-router.routes"
let routeHelperPlist = "/Library/LaunchDaemons/" + routeHelperLabel + ".plist"

@objc protocol RouteHelperProtocol {
    func request(_ data: Data, reply: @escaping (Data) -> Void)
}

struct HelperFailure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}
func jsonData(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
func jsonObject(_ data: Data) throws -> [String: Any] {
    guard data.count <= 65536, let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw HelperFailure("INVALID_REQUEST") }
    return value
}
