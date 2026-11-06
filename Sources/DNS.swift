import Foundation

enum DNS {
    static func u16(_ b: [UInt8], _ p: Int) throws -> Int {
        guard p >= 0, p + 2 <= b.count else { throw RouterError.dnsUnavailable }
        return Int(b[p]) << 8 | Int(b[p + 1])
    }

    static func name(_ b: [UInt8], _ start: Int) throws -> (String, Int) {
        var pos = start, end: Int?, seen = Set<Int>(), labels: [String] = []
        while true {
            guard pos < b.count, seen.insert(pos).inserted, seen.count <= 128 else { throw RouterError.dnsUnavailable }
            let n = Int(b[pos])
            if n & 0xc0 == 0xc0 {
                let ptr = try u16(b, pos) & 0x3fff
                if end == nil { end = pos + 2 }
                pos = ptr; continue
            }
            guard n <= 63 else { throw RouterError.dnsUnavailable }
            pos += 1
            if n == 0 { return (labels.joined(separator: ".").lowercased(), end ?? pos) }
            guard pos + n <= b.count, let label = String(bytes: b[pos..<pos+n], encoding: .ascii) else { throw RouterError.dnsUnavailable }
            labels.append(label); pos += n
            guard labels.joined(separator: ".").utf8.count <= 253 else { throw RouterError.dnsUnavailable }
        }
    }

    static func query(host: String, id: UInt16) -> [UInt8] {
        var b: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in host.split(separator: ".") { b.append(UInt8(label.utf8.count)); b += label.utf8 }
        return b + [0, 0, 1, 0, 1]
    }

    static func answers(_ b: [UInt8], host: String, id: UInt16) throws -> [String] {
        guard b.count >= 12, try u16(b, 0) == Int(id),
              try u16(b, 2) & 0x8000 != 0, try u16(b, 2) & 0x7a0f == 0,
              try u16(b, 4) == 1 else { throw RouterError.dnsUnavailable }
        let (question, qend) = try name(b, 12)
        guard question == host, try u16(b, qend) == 1, try u16(b, qend + 2) == 1 else { throw RouterError.dnsUnavailable }
        var pos = qend + 4, records: [(String, String)] = [], aliases: [String: String] = [:]
        let count = try u16(b, 6)
        guard count <= 2048 else { throw RouterError.dnsUnavailable }
        for _ in 0..<count {
            let (owner, next) = try name(b, pos); pos = next
            let kind = try u16(b, pos), cls = try u16(b, pos+2), size = try u16(b, pos+8)
            pos += 10
            guard pos + size <= b.count else { throw RouterError.dnsUnavailable }
            if cls == 1 && kind == 1 && size == 4 { records.append((owner, b[pos..<pos+4].map(String.init).joined(separator: "."))) }
            if cls == 1 && kind == 5 {
                let (alias, consumed) = try name(b, pos)
                guard consumed == pos + size else { throw RouterError.dnsUnavailable }
                aliases[owner] = alias
            }
            pos += size
        }
        var names: Set<String> = [host]
        for _ in 0..<16 { for n in Array(names) { if let a = aliases[n] { names.insert(a) } } }
        return Array(Set(records.filter { names.contains($0.0) }.map { $0.1 })).sorted()
    }
}
