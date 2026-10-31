import NetworkExtension
import SwiftUI

@main
struct PCAPhobosApp: App {
    @StateObject private var vpn = VPNController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpn)
                .onOpenURL { vpn.importLink($0.absoluteString) }   // phobos:// from the panel
        }
    }
}

/// Owns the NETunnelProviderManager: profile, options, connect/disconnect, live status.
@MainActor
final class VPNController: ObservableObject {
    @Published var name = UserDefaults.standard.string(forKey: "name") ?? ""
    @Published var conf = UserDefaults.standard.string(forKey: "conf") ?? ""
    @Published var ruDirect = UserDefaults.standard.object(forKey: "ruDirect") as? Bool ?? true { didSet { saveOptions() } }
    @Published var transportMode = UserDefaults.standard.string(forKey: "transport") ?? "auto" { didSet { saveOptions() } }
    /// Channel «Облако»: wss:// of the user's Keenetic (empty -> "# pca-ws" from the link).
    @Published var wsURL = UserDefaults.standard.string(forKey: "wsURL") ?? "" { didSet { saveOptions() } }
    /// Imported servers: [["name": …, "conf": …]]; name/conf above mirror the selected one.
    @Published var servers = UserDefaults.standard.array(forKey: "servers") as? [[String: String]] ?? []
    @Published var status: NEVPNStatus = .invalid
    @Published var transport = ""
    @Published var message = ""

    private var manager: NETunnelProviderManager?
    private var timer: Timer?

    init() {
        if servers.isEmpty && !conf.isEmpty { servers = [["name": name, "conf": conf]] }   // pre-list single profile
        Task { await load() }
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.status = self?.manager?.connection.status ?? .invalid }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollTransport() }
        }
    }

    var profile: PhobosProfile? { conf.isEmpty ? nil : PhobosProfile(conf) }
    var isOn: Bool { status == .connected || status == .connecting || status == .reasserting }

    func load() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = all.first
        status = manager?.connection.status ?? .invalid
    }

    func importLink(_ link: String) {
        guard let parsed = PhobosProfile.fromLink(link) else { message = "Это не ссылка phobos:// из панели"; return }
        servers.removeAll { $0["name"] == parsed.name }   // same name = updated link
        servers.append(["name": parsed.name, "conf": parsed.profile.raw])
        select(parsed.name)
        message = "Профиль «\(name)» импортирован"
    }

    func select(_ server: String) {
        guard let s = servers.first(where: { $0["name"] == server }) else { return }
        name = server
        conf = s["conf"] ?? ""
        persist()
        Task { await save(reconnect: isOn) }
    }

    func remove(_ server: String) {
        servers.removeAll { $0["name"] == server }
        if server == name {
            if let next = servers.first?["name"] { select(next); return }
            if isOn { manager?.connection.stopVPNTunnel() }
            name = ""; conf = ""
        }
        persist()
    }

    private func persist() {
        UserDefaults.standard.set(servers, forKey: "servers")
        UserDefaults.standard.set(conf, forKey: "conf")
        UserDefaults.standard.set(name, forKey: "name")
    }

    private func saveOptions() {
        UserDefaults.standard.set(ruDirect, forKey: "ruDirect")
        UserDefaults.standard.set(transportMode, forKey: "transport")
        UserDefaults.standard.set(wsURL, forKey: "wsURL")
        Task { await save(reconnect: isOn) }
    }

    /// Write the VPN configuration to iOS settings (asks the user once).
    func save(reconnect: Bool = false) async {
        guard let profile else { return }
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.bobyrev.pcaphobos.tunnel"
        proto.serverAddress = profile.targetHost ?? "Phobos"
        proto.providerConfiguration = ["conf": conf, "ruDirect": ruDirect, "transport": transportMode, "wsURL": wsURL]
        m.protocolConfiguration = proto
        m.localizedDescription = "PCA Phobos"
        m.isEnabled = true
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            manager = m
            if reconnect { m.connection.stopVPNTunnel(); try await Task.sleep(nanoseconds: 1_000_000_000); try m.connection.startVPNTunnel() }
        } catch {
            message = "Не удалось сохранить VPN: \(error.localizedDescription)"
        }
    }

    func toggle() {
        Task {
            if isOn { manager?.connection.stopVPNTunnel(); return }
            guard profile != nil else { message = "Сначала импортируйте ссылку phobos:// из панели"; return }
            await save()
            do { try manager?.connection.startVPNTunnel() } catch { message = "Ошибка: \(error.localizedDescription)" }
        }
    }

    private func pollTransport() {
        guard status == .connected, let session = manager?.connection as? NETunnelProviderSession else { transport = ""; return }
        try? session.sendProviderMessage(Data()) { [weak self] data in
            guard let data, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
            Task { @MainActor in self?.transport = obj["transport"] as? String ?? "" }
        }
    }
}
