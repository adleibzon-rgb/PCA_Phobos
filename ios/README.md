# PCA Phobos VPN — iPhone

То же, что Android-клиент: импорт `phobos://` из панели, обфускация (wg-obfuscator внутри
расширения), **российские сайты напрямую**, канал **Авто/UDP/TCP/Облако** (при блокировке UDP — сам на TCP; «Облако» — через KeenDNS своего Keenetic, см. `../wsgw/README.md`).
Выбор отдельных приложений на iOS невозможен (Apple даёт это только через MDM) — делим по адресам.

Устройство:
- `App/` — SwiftUI-приложение (профиль, кнопка, настройки), `Shared/PhobosProfile.swift` — разбор ссылки.
- `Tunnel/` — Packet Tunnel: WireGuardKit → 127.0.0.1:13255 wg-obfuscator (`-Dmain=wgobf_main`, один
  экземпляр: iOS запрещает fork) → 127.0.0.1:13258 `pcarelay.c` → сервер по UDP или TCP (формат udptcp),
  либо «Облако»: пакеты из pcarelay в `WsLink.swift` (URLSessionWebSocketTask) → wss://поддомен роутера → wsgw → сервер.
- `WireGuardKit/` — wireguard-apple (MIT), `WireGuardGo/<sdk>/libwg-go.a` — собран `make` (iphoneos) и
  `go build -buildmode c-archive` с `-target arm64-apple-ios15.0-simulator` (симулятор).

Сборка: `xcodegen generate` → `PCAPhobos.xcodeproj`. Проверка без телефона: `Tests/ProfileCheck`, режим «Облако» релея — `Tests/RelayCheck/main.c`.

## Установка на iPhone (нужен ПЛАТНЫЙ Apple Developer, $99/год)
Network Extension (packet-tunnel-provider) Apple выдаёт только платным аккаунтам — с бесплатным
Xcode не подпишет даже одно приложение. Когда аккаунт есть:
1. В `project.yml` вписать `DEVELOPMENT_TEAM: <Team ID>`, `xcodegen generate`.
2. Xcode → Signing: включить capability Network Extensions (Packet Tunnel) для обоих таргетов.
3. iPhone по кабелю → Run, либо Product → Archive → TestFlight (тестировщики по e-mail, 90 дней).
4. В панели клиента → 📱 → открыть ссылку `phobos://` на iPhone → «Открыть в PCA Phobos» → Подключить
   → разрешить добавление VPN.

Проверено 23.10.2026: сборка под iphoneos и симулятор, UI и импорт реальной ссылки в симуляторе.
Сам туннель в симуляторе iOS не работает — проверяется только на телефоне.
