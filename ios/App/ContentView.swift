import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var pasteText = ""
    @State private var showImport = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    profileCard
                    if vpn.servers.count > 1 { serversCard }
                    powerButton
                    statusLine
                    optionsCard
                    Button { showImport = true } label: {
                        Label("Импорт ссылки phobos://", systemImage: "square.and.arrow.down")
                            .frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .buttonStyle(.borderedProminent).tint(.indigo)
                    Link(destination: URL(string: "https://speed.cloudflare.com/")!) {
                        Label("Проверить скорость", systemImage: "speedometer").frame(maxWidth: .infinity).padding(.vertical, 12)
                    }
                    .buttonStyle(.bordered)
                    if !vpn.message.isEmpty {
                        Text(vpn.message).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                }
                .padding()
            }
            .navigationTitle("PCA Phobos VPN")
            .alert("Ссылка из панели", isPresented: $showImport) {
                TextField("phobos://…", text: $pasteText)
                Button("Импорт") { vpn.importLink(pasteText); pasteText = "" }
                Button("Из буфера") { vpn.importLink(UIPasteboard.general.string ?? "") }
                Button("Отмена", role: .cancel) {}
            } message: {
                Text("В панели: клиент → 📱 → ссылка phobos://. Можно просто открыть ссылку на iPhone — профиль импортируется сам.")
            }
        }
    }

    private var profileCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let p = vpn.profile {
                Text(vpn.name).font(.title3.bold())
                Text("Сервер: \(p.target ?? "?")").font(.subheadline).foregroundStyle(.secondary)
                if let tcp = p.tcpPort { Text("Резервный TCP: порт \(tcp)").font(.caption).foregroundStyle(.secondary) }
            } else {
                Text("Профиль не импортирован").font(.headline)
                Text("Откройте на iPhone ссылку phobos:// из панели PCA Phobos или вставьте её кнопкой ниже.")
                    .font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding().background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var serversCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Серверы").font(.subheadline.bold()).padding(.bottom, 6)
            ForEach(vpn.servers, id: \.self) { s in
                let n = s["name"] ?? ""
                HStack {
                    Image(systemName: n == vpn.name ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(n == vpn.name ? .green : .secondary)
                    Text(n)
                    Spacer()
                    if n != vpn.name {
                        Button(role: .destructive) { vpn.remove(n) } label: { Image(systemName: "trash") }
                            .buttonStyle(.borderless)
                    }
                }
                .padding(.vertical, 8)
                .contentShape(Rectangle())
                .onTapGesture { vpn.select(n) }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding().background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var powerButton: some View {
        Button(action: vpn.toggle) {
            Text(vpn.isOn ? "Отключить" : "Подключить")
                .font(.title2.bold()).foregroundStyle(.white)
                .frame(width: 180, height: 180)
                .background(Circle().fill(vpn.isOn ? Color.green : Color.indigo))
        }
        .padding(.top, 8)
    }

    private var statusLine: some View {
        let text: String = {
            switch vpn.status {
            case .connected: return "🟢 VPN включён" + (vpn.transport.isEmpty ? "" : " · \(vpn.transport)")
            case .connecting, .reasserting: return "🟡 Подключение…"
            case .disconnecting: return "Отключение…"
            default: return "⚪ VPN выключен"
            }
        }()
        return Text(text).font(.headline)
    }

    private var optionsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle("Российские сайты — напрямую, без VPN", isOn: $vpn.ruDirect)
            VStack(alignment: .leading, spacing: 6) {
                Text("Канал до сервера").font(.subheadline.bold())
                Picker("Канал", selection: $vpn.transportMode) {
                    Text("Авто").tag("auto"); Text("UDP").tag("udp"); Text("TCP").tag("tcp"); Text("Облако").tag("cloud")
                }
                .pickerStyle(.segmented)
                if vpn.transportMode == "cloud" {
                    TextField("wss://phobos.имя.keenetic.pro/", text: $vpn.wsURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        .textFieldStyle(.roundedBorder).onSubmit { vpn.wsURL = vpn.wsURL.trimmingCharacters(in: .whitespaces) }
                    Text("Облако: телефон → облако KeenDNS → ваш Keenetic → сервер. Работает, когда до сервера напрямую не достучаться.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("Авто: если UDP режут, через 15 секунд переходит на TCP. Изменения применяются сразу.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding().background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}
