import Foundation
import NetworkExtension
import WireGuardKit

/// PCA Phobos packet tunnel:
/// WireGuard (userspace) -> 127.0.0.1:13255 wg-obfuscator -> 127.0.0.1:13258 pcarelay -> server (UDP or TCP).
/// providerConfiguration: "conf" (phobos:// payload), "ruDirect" (Bool), "transport" ("auto"|"udp"|"tcp").
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let wgPort = 13255, relayPort = 13258
    private static var obfuscatorStarted = false   // one wg-obfuscator per process (it forks for more)

    private lazy var adapter = WireGuardAdapter(with: self) { _, message in NSLog("wg: %@", message) }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let pc = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        guard let conf = pc["conf"] as? String, !conf.isEmpty else {
            completionHandler(NSError(domain: "PCAPhobos", code: 1, userInfo: [NSLocalizedDescriptionKey: "нет профиля"]))
            return
        }
        let ruDirect = pc["ruDirect"] as? Bool ?? true
        let transport = pc["transport"] as? String ?? "auto"
        let profile = PhobosProfile(conf)

        guard let host = profile.targetHost, let udpPort = profile.targetPort else {
            completionHandler(NSError(domain: "PCAPhobos", code: 2, userInfo: [NSLocalizedDescriptionKey: "в профиле нет адреса сервера"]))
            return
        }
        let tcpPort = profile.tcpPort ?? 0
        if transport == "tcp" && tcpPort == 0 {
            completionHandler(NSError(domain: "PCAPhobos", code: 3, userInfo: [NSLocalizedDescriptionKey: "на сервере нет TCP-канала"]))
            return
        }

        pcarelay_use_tcp(transport == "tcp" ? 1 : 0)
        if !Self.obfuscatorStarted {
            Self.obfuscatorStarted = true
            pcarelay_start(Int32(Self.relayPort), host, Int32(udpPort), Int32(tcpPort))
            let path = NSTemporaryDirectory() + "obf.conf"
            try? profile.obfuscatorConfig(listen: Self.wgPort, target: "127.0.0.1:\(Self.relayPort)")
                .write(toFile: path, atomically: true, encoding: .utf8)
            Thread.detachNewThread {
                var args: [UnsafeMutablePointer<CChar>?] = ["wg-obfuscator", "-c", path].map { strdup($0) }
                _ = wgobf_main(Int32(args.count), &args)
            }
        }

        let allowed = ruDirect ? Self.ruBypassAllowedIPs() : nil
        let wgText = profile.wireGuardConfig(endpoint: "127.0.0.1:\(Self.wgPort)", allowedIPs: allowed)
        let tunnelConfig: TunnelConfiguration
        do {
            tunnelConfig = try TunnelConfiguration(fromWgQuickConfig: wgText, called: "phobos")
        } catch {
            completionHandler(error)
            return
        }
        adapter.start(tunnelConfiguration: tunnelConfig) { [weak self] error in
            completionHandler(error)
            if error == nil && transport == "auto" && tcpPort != 0 { self?.watchUdp() }
        }
    }

    /// Auto: nothing came back over UDP within 15 s -> UDP is cut, move the relay to TCP.
    private func watchUdp() {
        DispatchQueue.global().asyncAfter(deadline: .now() + 15) {
            if pcarelay_is_tcp() == 0 && pcarelay_rx_bytes() == 0 {
                NSLog("PCAPhobos: no UDP answer in 15 s -> TCP")
                pcarelay_use_tcp(1)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        adapter.stop { _ in
            completionHandler()
            // the obfuscator thread cannot be stopped cleanly; a fresh process starts next time
            exit(0)
        }
    }

    /// App asks for status: {"transport": "UDP"|"TCP", "rx": bytes}
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let status: [String: Any] = ["transport": pcarelay_is_tcp() != 0 ? "TCP" : "UDP",
                                     "rx": pcarelay_rx_bytes()]
        completionHandler?(try? JSONSerialization.data(withJSONObject: status))
    }

    private static func ruBypassAllowedIPs() -> String? {
        guard let url = Bundle.main.url(forResource: "ru_bypass", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return text.split(separator: "\n").first { !$0.hasPrefix("#") && $0.contains("/") }.map(String.init)
    }
}
