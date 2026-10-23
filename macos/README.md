# PCA Phobos для macOS

Без Network Extension и без платного аккаунта Apple: `wireguard-go` (utun) + `wg-obfuscator` + `udptcp`,
запуск от root через `/usr/local/bin/phobos` (разрешён без пароля только он — sudoers.d/pca-phobos).

- `phobos on|off|status|auto|udp|tcp|ru on|off|import <phobos://...>`
- Интернет — через сервер Phobos, **российские сайты напрямую** (ru_bypass.txt, как в Android/iOS).
- **Авто UDP→TCP**: нет рукопожатия 15 с — обфускатор переключается на `udptcp` (TCP 443 сервера).
- **Дом**: отдельный WireGuard до домашнего Keenetic (Wireguard1, пир `macbook-phobos-home`, 172.16.6.32),
  только 192.168.88.0/24 и 172.16.6.0/24; дома (шлюз 192.168.88.1) не поднимается. Смена сети отслеживается.
- DNS на время работы — 1.1.1.1/8.8.8.8, при выключении возвращаются прежние.
- `PhobosMenu.swift` — значок в строке меню (сборка: `swiftc -O -o PCAPhobos PhobosMenu.swift`, ad-hoc подпись).

Установка: собрать `bin/wg-obfuscator` (clang *.c) и `bin/udptcp` в `~/.pca-phobos`, положить туда profile.conf,
home.key, home_pub, home_endpoint, home_addr, затем `sudo bash ~/.pca-phobos/install-mac.sh`.
