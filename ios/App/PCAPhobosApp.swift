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
    @Published var status: NEVPNStatus = .invalid
    @Published var transport = ""
    @Published var message = ""

    private var manager: NETunnelProviderManager?
    private var timer: Timer?

    init() {
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
        conf = parsed.profile.raw
        name = parsed.name
        UserDefaults.standard.set(conf, forKey: "conf")
        UserDefaults.standard.set(name, forKey: "name")
        message = "Профиль «\(name)» импортирован"
        Task { await save(reconnect: isOn) }
    }

    private func saveOptions() {
        UserDefaults.standard.set(ruDirect, forKey: "ruDirect")
        UserDefaults.standard.set(transportMode, forKey: "transport")
        Task { await save(reconnect: isOn) }
    }

    /// Write the VPN configuration to iOS settings (asks the user once).
    func save(reconnect: Bool = false) async {
        guard let profile else { return }
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.bobyrev.pcaphobos.tunnel"
        proto.serverAddress = profile.targetHost ?? "Phobos"
        proto.providerConfiguration = ["conf": conf, "ruDirect": ruDirect, "transport": transportMode]
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
