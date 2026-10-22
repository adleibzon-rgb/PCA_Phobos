#!/bin/bash
# ============================================================
#  PCA Phobos — updater / rollback
#
#    phobos-update                 # обновить до стабильной (канал stable / main)
#    phobos-update stable|beta|dev # канал (ветка main/beta/dev)
#    phobos-update v1.2.4          # конкретная версия (git tag)
#    phobos-update --rollback      # откатить на предыдущую версию (из бэкапа)
#    phobos-update --check         # установленная + версии всех каналов
#    phobos-update --list          # список бэкапов для отката
#
#  Источник: Gitea git.bobyrev.com/PCA/PCA_Phobos (основной), GitHub — запасной.
#  Свой адрес: PCA_GIT=https://… phobos-update
#
#  Обновляет ТОЛЬКО PCA-слой (панель + скрипты). НЕ трогает ключи WireGuard,
#  server.env, клиентов. Перед каждым обновлением — бэкап; откат восстанавливает.
# ============================================================
set -e
PHOBOS_DIR=/opt/Phobos
PANEL_DIR=/opt/phobos-panel
PCA_GIT="${PCA_GIT:-https://git.bobyrev.com/PCA/PCA_Phobos}"
GH_RAW="${GH_RAW:-https://raw.githubusercontent.com/andrey271192/PCA_Phobos}"
BACKUPS="$PHOBOS_DIR/updates"
VERFILE="$PANEL_DIR/.version"
CUR=$(cat "$VERFILE" 2>/dev/null || echo "unknown")
# Токен подписчика для приватных каналов: env > сохранённый файл
GH_TOKEN="${GH_TOKEN:-$(cat "$PANEL_DIR/.gh_token" 2>/dev/null || true)}"

panel_service_name() {
    for name in phobos-dev-test phobos-panel; do
        systemctl status "$name" >/dev/null 2>&1 && { echo "$name"; return; }
    done
    echo phobos-panel
}

restart_panel_service() {
    local svc
    svc="$(panel_service_name)"
    systemctl restart "$svc" 2>/dev/null || true
}

# since 1.4.0 all channels are branches of one public repo (no subscriber token)
is_private() { return 1; }

fetch_repo_file() {  # $1=ref $2=repo_path $3=output ; Gitea first, GitHub fallback
    local ref="$1" rp="$2" out="$3" kind=branch
    case "$ref" in v[0-9]*) kind=tag;; esac
    curl -fsSL -m25 "$PCA_GIT/raw/$kind/$ref/$rp?cb=$(date +%s)" -o "$out" 2>/dev/null && return 0
    curl -fsSL -m25 "$GH_RAW/$ref/$rp?cb=$(date +%s)" -o "$out"
}

fetch_repo_text() {  # $1=ref $2=repo_path
    local tmp rc
    tmp=$(mktemp)
    fetch_repo_file "$1" "$2" "$tmp"; rc=$?
    if [ "$rc" = 0 ]; then cat "$tmp"; fi
    rm -f "$tmp"
    return "$rc"
}

managed_files() {
cat <<LIST
$PANEL_DIR/app.py|app.py
$PHOBOS_DIR/repo/server/scripts/lib-core.sh|overlay/lib-core.sh
$PHOBOS_DIR/repo/server/scripts/phobos-client.sh|overlay/phobos-client.sh
$PHOBOS_DIR/repo/client/templates/install-router.sh.template|overlay/install-router.sh.template
$PHOBOS_DIR/repo/client/templates/lib-client.sh|overlay/lib-client.sh
$PHOBOS_DIR/repo/client/templates/install-obfuscator.sh|overlay/install-obfuscator.sh
$PHOBOS_DIR/repo/client/templates/install-wireguard.sh|overlay/install-wireguard.sh
$PHOBOS_DIR/repo/client/templates/router-configure-wireguard.sh|overlay/router-configure-wireguard.sh
$PHOBOS_DIR/repo/client/templates/router-configure-wireguard-openwrt.sh|overlay/router-configure-wireguard-openwrt.sh
$PHOBOS_DIR/repo/client/templates/phobos-pull.sh|overlay/phobos-pull.sh
$PHOBOS_DIR/repo/client/templates/phobos-ttyd.sh|overlay/phobos-ttyd.sh
$PHOBOS_DIR/repo/client/templates/phobos-uninstall.sh|overlay/phobos-uninstall.sh
$PHOBOS_DIR/repo/client/templates/3xui.sh|overlay/3xui.sh
$PHOBOS_DIR/server/phobos-warp.sh|server/phobos-warp.sh
$PHOBOS_DIR/server/phobos-health.sh|server/phobos-health.sh
$PHOBOS_DIR/server/phobos-self-check.sh|server/phobos-self-check.sh
$PHOBOS_DIR/server/phobos-pull.sh|server/phobos-pull.sh
$PHOBOS_DIR/server/phobos-router-watchdog.py|server/phobos-router-watchdog.py
$PHOBOS_DIR/server/api.py|server/api.py
$PHOBOS_DIR/server/secondary-setup.sh|server/secondary-setup.sh
$PHOBOS_DIR/server/phobos-backup.sh|server/phobos-backup.sh
$PHOBOS_DIR/server/phobos-guard.sh|server/phobos-guard.sh
$PHOBOS_DIR/server/phobos-cascade.sh|server/phobos-cascade.sh
$PHOBOS_DIR/server/phobos-domain.sh|server/phobos-domain.sh
$PHOBOS_DIR/server/phobos-limit.sh|server/phobos-limit.sh
$PHOBOS_DIR/server/phobos-speedtest.sh|server/phobos-speedtest.sh
$PHOBOS_DIR/server/update.sh|update.sh
LIST
}

run_self_check() {
    if [ -x "$PHOBOS_DIR/server/phobos-self-check.sh" ]; then
        ln -sf "$PHOBOS_DIR/server/phobos-self-check.sh" /usr/local/bin/phobos-self-check 2>/dev/null || true
        "$PHOBOS_DIR/server/phobos-self-check.sh" --fix
    else
        echo "  WARN: phobos-self-check.sh не найден"
    fi
    [ -x "$PHOBOS_DIR/server/phobos-backup.sh" ] && ln -sf "$PHOBOS_DIR/server/phobos-backup.sh" /usr/local/bin/phobos-backup 2>/dev/null || true
    [ -x "$PHOBOS_DIR/server/phobos-warp.sh" ] && ln -sf "$PHOBOS_DIR/server/phobos-warp.sh" /usr/local/bin/phobos-warp 2>/dev/null || true
    for _n in phobos-guard phobos-cascade phobos-domain; do [ -x "$PHOBOS_DIR/server/$_n.sh" ] && ln -sf "$PHOBOS_DIR/server/$_n.sh" /usr/local/bin/$_n 2>/dev/null || true; done
}

refresh_router_packages() {
    local script="$PHOBOS_DIR/repo/server/scripts/phobos-client.sh"
    [ -x "$script" ] || return 0
    [ -d "$PHOBOS_DIR/clients" ] || return 0
    local rebuilt=0 failed=0 id
    for dir in "$PHOBOS_DIR/clients"/*; do
        [ -d "$dir" ] || continue
        id=$(basename "$dir")
        if "$script" package "$id" >/dev/null 2>&1; then
            rebuilt=$((rebuilt + 1))
        else
            failed=$((failed + 1))
            echo "  WARN: router package rebuild failed for $id"
        fi
    done
    [ "$rebuilt" = 0 ] && [ "$failed" = 0 ] || echo "Router packages rebuilt: $rebuilt, failed: $failed"
}

# fetch VERSION of a channel (public repos / or private if token present)
chan_version() {  # $1 = ref(channel)
    if is_private "$1" && [ -z "$GH_TOKEN" ]; then echo ""; return; fi
    fetch_repo_text "$1" VERSION 2>/dev/null | tr -d ' \r\n'
}
latest_version() { fetch_repo_text main VERSION 2>/dev/null | tr -d ' \r\n'; }

do_backup() {
    local dir="$BACKUPS/${CUR}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir"
    managed_files | while IFS='|' read -r lp rp; do
        [ -f "$lp" ] && install -D "$lp" "$dir/$rp" 2>/dev/null || true
    done
    echo "$CUR" > "$dir/.fromversion"
    echo "$dir"
}

apply_ref() {
    local ref="$1"
    managed_files | while IFS='|' read -r lp rp; do
        local tmp; tmp=$(mktemp)
        if fetch_repo_file "$ref" "$rp" "$tmp" && [ -s "$tmp" ]; then
            mkdir -p "$(dirname "$lp")"; mv "$tmp" "$lp"
            case "$lp" in *.sh|*.py) chmod +x "$lp" 2>/dev/null || true;; esac
        else
            rm -f "$tmp"; echo "  WARN: не удалось скачать $rp (пропуск)"
        fi
    done
}

ensure_runtime_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass python3-pip >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-flask-sock >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-asyncssh >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-websocket >/dev/null 2>&1 || true
    fi
    python3 - <<'PY' >/dev/null 2>&1 || python3 -m pip install flask-sock asyncssh websocket-client >/dev/null 2>&1 || python3 -m pip install --break-system-packages flask-sock asyncssh websocket-client >/dev/null 2>&1 || true
import flask_sock, asyncssh, websocket
PY
    mkdir -p "$PANEL_DIR/static"
    curl -fsSL -m20 https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css -o "$PANEL_DIR/static/xterm.min.css" 2>/dev/null || true
    curl -fsSL -m20 https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js -o "$PANEL_DIR/static/xterm.min.js" 2>/dev/null || true
    curl -fsSL -m20 https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js -o "$PANEL_DIR/static/xterm-addon-fit.min.js" 2>/dev/null || true
    if [ -f /etc/systemd/system/phobos-panel.service ]; then
        if grep -q 'ExecStart=/usr/bin/gunicorn -w 1 -b ' /etc/systemd/system/phobos-panel.service; then
            sed -i 's#ExecStart=/usr/bin/gunicorn -w 1 -b #ExecStart=/usr/bin/gunicorn -w 1 --threads 20 -b #' /etc/systemd/system/phobos-panel.service
            systemctl daemon-reload 2>/dev/null || true
        fi
        if grep -q '0.0.0.0:8443 app:app' /etc/systemd/system/phobos-panel.service && [ -s "$PANEL_DIR/.port" ]; then
            port=$(cat "$PANEL_DIR/.port" 2>/dev/null || echo 8443)
            sed -i "s#0.0.0.0:8443 app:app#0.0.0.0:${port} app:app#" /etc/systemd/system/phobos-panel.service
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi
}

ref_exists() {
    local tmp rc
    tmp=$(mktemp)
    fetch_repo_file "$1" app.py "$tmp" >/dev/null 2>&1; rc=$?
    rm -f "$tmp"
    return "$rc"
}

case "${1:-}" in
  --version|-v|--check)
    echo "Установлено:    $CUR"
    echo "Стабильная:     $(latest_version)   [открытый]"
    echo "Бета (beta):    $(chan_version beta)"
    echo "Разработка(dev):$(chan_version dev)"
    ;;
  --versions|--tags)
    echo "Версии (теги):"
    curl -fsSL -m10 "${PCA_GIT%/*/*}/api/v1/repos/${PCA_GIT#*://*/}/tags?limit=100" 2>/dev/null \
      | grep -oE '"name": *"[^"]+"' | sed 's/.*"name": *"\(.*\)"/  \1/' || echo "  (нет данных)"
    ;;
  --list)
    echo "Бэкапы (для отката):"
    ls -dt "$BACKUPS"/*/ 2>/dev/null | sed 's#.*/updates/##' || echo "  нет"
    ;;
  --rollback)
    last=$(ls -dt "$BACKUPS"/*/ 2>/dev/null | head -1)
    [ -z "$last" ] && { echo "Нет бэкапа для отката."; exit 1; }
    fromver=$(cat "$last/.fromversion" 2>/dev/null || echo "?")
    echo "Откат на $fromver  ($last)"
    managed_files | while IFS='|' read -r lp rp; do
        [ -f "$last/$rp" ] && { mkdir -p "$(dirname "$lp")"; cp "$last/$rp" "$lp"; chmod +x "$lp" 2>/dev/null || true; }
    done
    echo "$fromver" > "$VERFILE"
    run_self_check
    restart_panel_service
    refresh_router_packages
    echo "Откат выполнен -> $fromver"
    ;;
  *)
    ref="${1:-main}"
    case "$ref" in latest|stable) ref="main";; esac
    # Каналы beta/dev — приватный репозиторий, нужен токен подписчика
    if is_private "$ref" && [ -z "$GH_TOKEN" ]; then
        echo "Канал '$ref' закрыт (бета/разработка) — приватный репозиторий."
        echo "Нужен read-only токен подписчика:"
        echo "  GH_TOKEN=ваш_токен phobos-update $ref"
        echo "Токен — по подписке: https://boosty.to/andrey27 . Стабильная (без токена): phobos-update stable"
        exit 1
    fi
    if ! ref_exists "$ref"; then
        echo "Версия/ветка '$ref' не найдена (или токен неверный). Обновление отменено (текущая $CUR не тронута)."
        echo "Доступные: phobos-update --versions  ·  стабильная: $(latest_version)"
        exit 1
    fi
    # сохранить токен для будущих обновлений приватного канала
    if is_private "$ref" && [ -n "$GH_TOKEN" ]; then
        ( umask 077; printf %s "$GH_TOKEN" > "$PANEL_DIR/.gh_token" )
    fi
    repo_ref="$ref"
    # run the TARGET version's updater: its file list knows the new files
    if [ -z "${PHOBOS_UPDATE_REEXEC:-}" ]; then
        _new=$(mktemp)
        if fetch_repo_file "$ref" update.sh "$_new" && head -1 "$_new" | grep -q '^#!' && ! cmp -s "$_new" "$0"; then
            chmod +x "$_new"
            PHOBOS_UPDATE_REEXEC=1 GH_TOKEN="$GH_TOKEN" exec bash "$_new" "$@"
        fi
        rm -f "$_new"
    fi
    target=$(fetch_repo_text "$ref" VERSION 2>/dev/null | tr -d ' \r\n'); [ -z "$target" ] && target="$ref"
    echo "Текущая: $CUR  ->  целевая: $target  ($ref)"
    b=$(do_backup); echo "Бэкап: $b"
    apply_ref "$ref"
    ensure_runtime_deps
    run_self_check
    refresh_router_packages
    echo "$target" > "$VERFILE"
    restart_panel_service
    echo "Обновлено до $target. Откат: phobos-update --rollback"
    ;;
esac
