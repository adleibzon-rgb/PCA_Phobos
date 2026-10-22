#!/bin/bash
# ============================================================
#  PCA Phobos — полный бэкап / восстановление сервера
#
#    phobos-backup create            # создать бэкап -> /opt/Phobos/backups/*.tar.gz
#    phobos-backup restore <file>    # восстановить из бэкапа
#    phobos-backup list              # список бэкапов
#
#  В бэкап входит ВСЁ состояние (НЕ бинарники/пакеты):
#    WireGuard ключ сервера (wg0.conf), server.env (OBF/WG ключи),
#    обфускатор-конфиги, все клиенты+ключи, токены, settings.json панели
#    (router_access, метки, назначения, токен подписчика, версия/канал/порт).
#
#  ⚠ Бэкап содержит ПРИВАТНЫЕ КЛЮЧИ — храни в защищённом месте.
#
#  Disaster recovery на чистом VPS:
#    1) поставить turnkey:  bash <(curl -fsSL .../install.sh)   (ставит бинарники/сервисы)
#    2) залить бэкап и:     phobos-backup restore phobos-backup-*.tar.gz
#    Ключ сервера восстановится — клиенты переподключатся без пересоздания.
# ============================================================
set -u
PHOBOS_DIR=/opt/Phobos
PANEL_DIR=/opt/phobos-panel
BACKUP_DIR="$PHOBOS_DIR/backups"

panel_service_name() {
  for name in phobos-dev-test phobos-panel; do
    systemctl status "$name" >/dev/null 2>&1 && { echo "$name"; return; }
  done
  echo phobos-panel
}

PATHS=(
  /etc/wireguard/wg0.conf
  "$PHOBOS_DIR/server/server.env"
  "$PHOBOS_DIR/clients"
  "$PHOBOS_DIR/tokens"
  "$PHOBOS_DIR/server/warp"
  "$PANEL_DIR/settings.json"
  "$PANEL_DIR/servers.json"
  "$PANEL_DIR/.version"
  "$PANEL_DIR/.channel"
  "$PANEL_DIR/.port"
  "$PANEL_DIR/.scheme"
  "$PANEL_DIR/.gh_token"
)

case "${1:-}" in
  create)
    mkdir -p "$BACKUP_DIR"
    OUT="$BACKUP_DIR/phobos-backup-$(hostname -s 2>/dev/null || echo srv)-$(date +%Y%m%d-%H%M%S).tar.gz"
    # -P: absolute paths (restore lands in original locations). obfuscator confs by glob.
    EXIST=()
    for p in "${PATHS[@]}"; do [ -e "$p" ] && EXIST+=("$p"); done
    for f in "$PHOBOS_DIR"/server/wg-obfuscator-*.conf; do [ -e "$f" ] && EXIST+=("$f"); done
    tar -czf "$OUT" -P --ignore-failed-read "${EXIST[@]}" 2>/dev/null
    chmod 600 "$OUT"
    echo "$OUT"
    ;;
  restore)
    FILE="${2:-}"
    [ -f "$FILE" ] || { echo "Файл не найден: $FILE"; exit 1; }
    # sanity: must be a phobos backup (contains server.env or wg0.conf)
    if ! tar -tzf "$FILE" 2>/dev/null | grep -qE 'server\.env|wg0\.conf'; then
        echo "Не похоже на бэкап PCA Phobos (нет server.env/wg0.conf). Отмена."; exit 1
    fi
    # safety snapshot before overwrite
    PRE="$BACKUP_DIR/pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
    mkdir -p "$BACKUP_DIR"
    PEX=()
    for p in "${PATHS[@]}"; do [ -e "$p" ] && PEX+=("$p"); done
    for f in "$PHOBOS_DIR"/server/wg-obfuscator-*.conf; do [ -e "$f" ] && PEX+=("$f"); done
    [ ${#PEX[@]} -gt 0 ] && tar -czf "$PRE" -P --ignore-failed-read "${PEX[@]}" 2>/dev/null && echo "Снимок до восстановления: $PRE"
    tar -xzf "$FILE" -P
    chmod 600 /etc/wireguard/wg0.conf 2>/dev/null || true
    systemctl restart wg-quick@wg0 2>/dev/null || true
    for s in $(systemctl list-units --all --plain --no-legend 'wg-obfuscator-*' 2>/dev/null | awk '{print $1}'); do
        systemctl restart "$s" 2>/dev/null || true
    done
    systemctl restart "$(panel_service_name)" 2>/dev/null || true
    echo "Восстановлено из $FILE. Сервисы перезапущены."
    ;;
  list)
    echo "Бэкапы в $BACKUP_DIR:"
    ls -lht "$BACKUP_DIR"/phobos-backup-*.tar.gz 2>/dev/null | awk '{print "  "$9"  ("$5")"}' || echo "  нет"
    ;;
  *)
    echo "phobos-backup — бэкап/восстановление сервера PCA Phobos"
    echo "  create            создать бэкап"
    echo "  restore <file>    восстановить"
    echo "  list              список бэкапов"
    ;;
esac
