#!/bin/bash
# ============================================================
#  PCA Phobos — полное удаление сервера (primary / panel node)
#
#    bash <(curl -fsSL https://raw.githubusercontent.com/andrey271192/PCA_Phobos/main/uninstall.sh)
#
#  Останавливает и удаляет: панель, обфускатор-сервисы, WireGuard wg0,
#  nginx-сайт, watchdog-cron, бинарники, iptables-правила, каталоги Phobos.
#  По умолчанию спрашивает подтверждение. PURGE=1 — без вопросов.
# ============================================================
set -u
PHOBOS_DIR="/opt/Phobos"
PANEL_DIR="/opt/phobos-panel"

[ "$(id -u)" -eq 0 ] || { echo "Запусти от root"; exit 1; }

echo "=================================================="
echo "  PCA Phobos — УДАЛЕНИЕ сервера"
echo "  Будут удалены: панель, obfuscator, wg0, nginx-сайт,"
echo "  watchdog, бинарники, $PHOBOS_DIR, $PANEL_DIR"
echo "=================================================="
if [ "${PURGE:-0}" != "1" ]; then
    printf "Точно удалить ВСЁ? [yes/NO]: "
    read -r ans </dev/tty 2>/dev/null || read -r ans
    # tolerate CR from Windows/phone terminals, spaces, case, "да"
    ans=$(printf '%s' "$ans" | tr -d '\r[:space:]' | tr '[:upper:]' '[:lower:]')
    case "$ans" in yes|y|да|д) ;; *) echo "Отменено (нужно ввести yes)."; exit 0 ;; esac
fi

IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1)
IFACE="${IFACE:-eth0}"

echo "[1/8] stop + disable services..."
# obfuscator services (any port)
for svc in $(systemctl list-units --all --plain --no-legend 'wg-obfuscator-*' 2>/dev/null | awk '{print $1}'); do
    systemctl stop "$svc" 2>/dev/null; systemctl disable "$svc" 2>/dev/null
done
for svc in phobos-panel phobos-api wg-quick@wg0; do
    systemctl stop "$svc" 2>/dev/null; systemctl disable "$svc" 2>/dev/null
done

echo "[2/8] remove systemd units..."
rm -f /etc/systemd/system/wg-obfuscator-*.service 2>/dev/null
rm -f /etc/systemd/system/phobos-panel.service /etc/systemd/system/phobos-api.service 2>/dev/null
systemctl daemon-reload 2>/dev/null

echo "[3/8] remove WireGuard wg0..."
rm -f /etc/wireguard/wg0.conf 2>/dev/null

echo "[4/8] remove iptables rules..."
iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP 2>/dev/null || true

echo "[5/8] remove nginx site..."
rm -f /etc/nginx/sites-enabled/phobos /etc/nginx/sites-available/phobos 2>/dev/null
nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true

echo "[6/8] remove watchdog cron..."
( crontab -l 2>/dev/null | grep -v 'phobos-router-watchdog' | grep -v '/opt/Phobos' || true ) | crontab - 2>/dev/null || true

echo "[7/8] remove binaries / symlinks..."
rm -f /usr/local/bin/wg-obfuscator /usr/local/bin/phobos-update 2>/dev/null

echo "[8/8] remove directories..."
rm -rf "$PHOBOS_DIR" "$PANEL_DIR" 2>/dev/null

echo "=================================================="
echo "  Phobos удалён."
echo "  (WireGuard/nginx/cron-пакеты НЕ удалены — общие; убрать вручную при желании)"
echo "=================================================="
