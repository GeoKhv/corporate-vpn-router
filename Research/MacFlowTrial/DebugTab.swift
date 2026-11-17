// Single disposable Yandex tab; only accepts the loopback debugger started by clients.py.
import Foundation
enum ProbeError: Error { case badResponse }
typealias Dict = [String: Any]

@main struct DebugTab {
    static func main() async {
        guard CommandLine.arguments.count == 3, let socketURL = URL(string: CommandLine.arguments[1]),
              socketURL.scheme == "ws", socketURL.host == "127.0.0.1",
              let address = readLine(), let destination = URL(string: address), destination.scheme == "https"
        else { exit(2) }
        let task = URLSession(configuration: .ephemeral).webSocketTask(with: socketURL)
        task.resume()
        var sequence = 0
        func call(_ method: String, _ params: Dict) async throws -> Dict {
            sequence += 1
            let data = try JSONSerialization.data(withJSONObject: ["id":sequence,"method":method,"params":params])
            try await task.send(.string(String(decoding: data, as: UTF8.self)))
            while true {
                let msg = try await task.receive()
                guard case .string(let json) = msg, let reply = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? Dict else { throw ProbeError.badResponse }
                guard reply["id"] as? Int == sequence else { continue }
                guard let result = reply["result"] as? Dict else { throw ProbeError.badResponse }
                return result
            }
        }
        do {
            let nav = try await call("Page.navigate", ["url":address])
            if nav["errorText"] != nil { exit(1) }
            for _ in 0..<60 {
                let result = try await call("Runtime.evaluate", ["expression":"document.readyState==='complete' ? (document.title+' '+(document.body?.innerText || '')) : ''","returnByValue":true])
                if let text = (result["result"] as? Dict)?["value"] as? String,
                   text.lowercased().contains(CommandLine.arguments[2]) { exit(0) }
                try await Task.sleep(nanoseconds: 100_000_000)
            }
            exit(4) // document missing, not proof of a network denial
        } catch { exit(2) }
    }
}
