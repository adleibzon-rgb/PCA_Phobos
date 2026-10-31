import Foundation

/// Channel «Облако»: one binary WebSocket message = one obfuscated packet, both ways.
/// pcarelay (C) calls send() for every packet from the obfuscator; received messages go back via pcarelay_ws_in().
final class WsLink {
    static let shared = WsLink()

    private let q = DispatchQueue(label: "pca.ws")
    private let session = URLSession(configuration: .ephemeral)
    private var url: URL?
    private var task: URLSessionWebSocketTask?

    func start(_ url: URL) {
        q.async { self.url = url; self.connect() }
    }

    func send(_ p: UnsafePointer<UInt8>?, _ n: Int32) {
        guard let p, n > 0 else { return }
        let data = Data(bytes: p, count: Int(n))
        q.async {
            if self.task == nil { self.connect() }
            guard let t = self.task else { return }
            t.send(.data(data)) { [weak self] err in
                if let err { self?.q.async { if self?.task === t { self?.drop("send: \(err.localizedDescription)") } } }
            }
        }
    }

    private func connect() {
        guard let url, task == nil else { return }
        let t = session.webSocketTask(with: url)
        t.maximumMessageSize = 1 << 20
        task = t
        t.resume()
        NSLog("PCAPhobos ws: connect %@", url.absoluteString)
        receive(t)
    }

    private func receive(_ t: URLSessionWebSocketTask) {
        t.receive { [weak self] result in
            switch result {
            case .success(.data(let d)):
                d.withUnsafeBytes { pcarelay_ws_in($0.bindMemory(to: UInt8.self).baseAddress, Int32(d.count)) }
                self?.receive(t)
            case .success:
                self?.receive(t)
            case .failure(let err):
                self?.q.async { if self?.task === t { self?.drop("recv: \(err.localizedDescription)") } }
            }
        }
    }

    /// Next packet from the obfuscator reconnects (WireGuard keepalives make that quick).
    private func drop(_ why: String) {
        NSLog("PCAPhobos ws: %@", why)
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }
}
