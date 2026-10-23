import Foundation

/// Parsed phobos:// payload from the PCA Phobos panel:
/// [Interface] + [Peer] (WireGuard) + [instance] (wg-obfuscator) + "# pca-tcp = <port>".
struct PhobosProfile {
    let raw: String

    init(_ raw: String) { self.raw = raw }

    /// phobos://<urlsafe base64>#name
    static func fromLink(_ link: String) -> (profile: PhobosProfile, name: String)? {
        var s = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix("phobos://") else { return nil }
        s.removeFirst("phobos://".count)
        var name = "Phobos"
        if let hash = s.firstIndex(of: "#") {
            name = String(s[s.index(after: hash)...]).removingPercentEncoding ?? name
            s = String(s[..<hash])
        }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64), let text = String(data: data, encoding: .utf8),
              text.contains("[Interface]"), text.contains("[instance]") else { return nil }
        return (PhobosProfile(text), name)
    }

    /// Lines of a section, without "= none" placeholders and comments.
    func lines(_ header: String) -> [(key: String, line: String)] {
        var inSection = false
        var out: [(String, String)] = []
        for rawLine in raw.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") { inSection = line.lowercased() == header.lowercased(); continue }
            guard inSection, !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.lowercased() == "none" { continue }
            out.append((line[..<eq].trimmingCharacters(in: .whitespaces).lowercased(), line))
        }
        return out
    }

    private func value(_ header: String, _ key: String) -> String? {
        lines(header).first { $0.key == key }.map { line in
            line.line[line.line.index(after: line.line.firstIndex(of: "=")!)...].trimmingCharacters(in: .whitespaces)
        }
    }

    var target: String? { value("[instance]", "target") }
    var targetHost: String? { target.map { String($0[..<($0.lastIndex(of: ":") ?? $0.endIndex)]) } }
    var targetPort: Int? { target.flatMap { $0.split(separator: ":").last.flatMap { Int($0) } } }

    /// "# pca-tcp = 443" written by the panel when the server has the TCP fallback.
    var tcpPort: Int? {
        for rawLine in raw.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#"), line.contains("pca-tcp"), let eq = line.firstIndex(of: "=") {
                return Int(line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }

    func obfuscatorConfig(listen: Int, target: String) -> String {
        var out = "[instance]\nsource-if = 127.0.0.1\nsource-lport = \(listen)\ntarget = \(target)\n"
        for item in lines("[instance]") where !["source-if", "source-lport", "target", "verbose"].contains(item.key) {
            out += item.line + "\n"
        }
        return out + "verbose = INFO\n"
    }

    func wireGuardConfig(endpoint: String, allowedIPs: String?) -> String {
        var out = "[Interface]\n"
        for item in lines("[Interface]") where !item.key.hasSuffix("applications") { out += item.line + "\n" }
        out += "\n[Peer]\n"
        for item in lines("[Peer]") {
            switch item.key {
            case "endpoint": out += "Endpoint = \(endpoint)\n"
            case "allowedips" where allowedIPs != nil: out += "AllowedIPs = \(allowedIPs!)\n"
            default: out += item.line + "\n"
            }
        }
        return out
    }
}
