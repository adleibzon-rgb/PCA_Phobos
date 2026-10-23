// PCA Phobos — menu bar app for macOS. Drives /usr/local/bin/phobos through
// `sudo -n` (sudoers NOPASSWD for that one root-owned script). No Network Extension.
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var status = ""

    func applicationDidFinishLaunching(_ n: Notification) {
        refresh()
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
    }

    @discardableResult
    private func phobos(_ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", "/usr/local/bin/phobos"] + args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        try? p.run()
        p.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }

    private func refresh() {
        DispatchQueue.global().async {
            let s = self.phobos(["status"])
            DispatchQueue.main.async { self.status = s; self.rebuild() }
        }
    }

    private var isOn: Bool { status.contains("VPN: включён") }

    private func rebuild() {
        item.button?.title = isOn ? (status.contains("TCP") ? "🛡 TCP" : "🛡") : "◌"
        item.button?.toolTip = "PCA Phobos"
        let m = NSMenu()
        for line in status.split(separator: "\n") {
            let i = NSMenuItem(title: String(line), action: nil, keyEquivalent: "")
            i.isEnabled = false
            m.addItem(i)
        }
        m.addItem(.separator())
        m.addItem(action(isOn ? "Отключить" : "Подключить", isOn ? ["off"] : ["on"]))
        m.addItem(.separator())
        let mode = status.contains("Режим: tcp") ? "tcp" : status.contains("Режим: udp") ? "udp" : "auto"
        for (t, v) in [("Канал: Авто", "auto"), ("Канал: UDP", "udp"), ("Канал: TCP", "tcp")] {
            let i = action(t, [v]); i.state = mode == v ? .on : .off; m.addItem(i)
        }
        let ruOn = status.contains("РФ напрямую: да")
        let ru = action("Российские сайты — напрямую", ["ru", ruOn ? "off" : "on"]); ru.state = ruOn ? .on : .off
        m.addItem(ru)
        m.addItem(.separator())
        m.addItem(withTitle: "Импорт ссылки phobos:// из буфера", action: #selector(importLink), keyEquivalent: "").target = self
        m.addItem(withTitle: "Выход", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = m
    }

    private func action(_ title: String, _ args: [String]) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: #selector(run(_:)), keyEquivalent: "")
        i.target = self
        i.representedObject = args
        return i
    }

    @objc private func run(_ sender: NSMenuItem) {
        guard let args = sender.representedObject as? [String] else { return }
        item.button?.title = "…"
        DispatchQueue.global().async {
            let out = self.phobos(args)
            DispatchQueue.main.async {
                if out.contains("password is required") { self.alert("Нет права sudo без пароля для /usr/local/bin/phobos") }
                self.refresh()
            }
        }
    }

    @objc private func importLink() {
        guard let s = NSPasteboard.general.string(forType: .string), s.hasPrefix("phobos://") else {
            alert("Скопируйте ссылку phobos:// из панели (клиент → 📱) и повторите"); return
        }
        alert(phobos(["import", s]))
        refresh()
    }

    private func alert(_ text: String) {
        let a = NSAlert(); a.messageText = "PCA Phobos"; a.informativeText = text; a.runModal()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
