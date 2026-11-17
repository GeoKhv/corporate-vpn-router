// Disposable, offscreen WebKit client. No Safari profile, persistent store or custom trust.
import AppKit
import WebKit
import Network

@main @MainActor
final class Probe: NSObject, WKNavigationDelegate {
    static var running: Probe?
    var web: WKWebView!
    var needle = ""
    var expected: URL!
    var responseOK = false
    static func main() {
        guard CommandLine.arguments.count == 3, let port = UInt16(CommandLine.arguments[1]),
              let line = readLine(), let url = URL(string: line), url.scheme == "https" else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let probe = Probe()
        running = probe
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        var proxy = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: .init(rawValue: port)!))
        proxy.allowFailover = false
        config.websiteDataStore.proxyConfigurations = [proxy]
        probe.needle = CommandLine.arguments[2]
        probe.expected = url
        probe.web = WKWebView(frame: NSRect(x: 0, y: 0, width: 600, height: 400), configuration: config)
        probe.web.navigationDelegate = probe
        probe.web.load(URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15))
        DispatchQueue.main.asyncAfter(deadline: .now() + 22) { exit(3) }
        app.run()
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if navigationResponse.isForMainFrame, let http = navigationResponse.response as? HTTPURLResponse {
            responseOK = http.url == expected && (200..<300).contains(http.statusCode)
            print("main-response", http.statusCode)
        }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Read the original WebKit main resource, not the text viewer's DOM. No archive is saved.
        guard responseOK else { exit(4) }
        webView.createWebArchiveData { result in
            guard case .success(let data) = result,
                  let archive = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let resource = archive["WebMainResource"] as? [String: Any],
                  let bytes = resource["WebResourceData"] as? Data else { exit(4) }
            exit(String(decoding: bytes, as: UTF8.self).lowercased().contains(self.needle) ? 0 : 4)
        }
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { print("navigation", (error as NSError).domain, (error as NSError).code); exit(1) }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { print("navigation", (error as NSError).domain, (error as NSError).code); exit(1) }
}
