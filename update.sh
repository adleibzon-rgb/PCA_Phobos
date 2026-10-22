#!/bin/bash
# ============================================================
#  PCA Phobos — updater / rollback
#
#    phobos-update                 # обновить до стабильной (канал stable / main)
#    phobos-update stable          # стабильный канал (публичный, без токена)
#    GH_TOKEN=... phobos-update beta   # бета-канал (приватный, по токену подписчика)
#    GH_TOKEN=... phobos-update dev    # канал разработки (приватный, по токену)
#    phobos-update v1.2.4          # конкретная версия (git tag)
#    phobos-update --rollback      # откатить на предыдущую версию (из бэкапа)
#    phobos-update --check         # установленная + версии всех каналов
#    phobos-update --list          # список бэкапов для отката
#
#  Каналы:
#    stable -> публичный репозиторий andrey271192/PCA_Phobos  (открыт)
#    beta / dev -> приватный andrey271192/PCA_Phobos-dev      (только подписчики)
#  Для beta/dev нужен read-only токен подписчика: env GH_TOKEN или файл
#  $PANEL_DIR/.gh_token (сохраняется при установке закрытого канала).
#
#  Обновляет ТОЛЬКО PCA-слой (панель + скрипты). НЕ трогает ключи WireGuard,
#  server.env, клиентов. Перед каждым обновлением — бэкап; откат восстанавливает.
# ============================================================
set -e
PHOBOS_DIR=/opt/Phobos
PANEL_DIR=/opt/phobos-panel
PUB_REPO=andrey271192/PCA_Phobos
DEV_REPO=andrey271192/PCA_Phobos-dev
PHOBOSWG_APK_TAG="v1.3.0-beta"
PHOBOSWG_APK_SHA256="5399de7c576d56e491a01ab9b52d53c08d30a34d1156c1cb0f4520bf34821e02"
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

# repo for a ref/channel: beta/dev/*-beta/*-dev -> private, остальное -> public
repo_for() { case "$1" in beta|dev|*-beta|*-dev) echo "$DEV_REPO";; *) echo "$PUB_REPO";; esac; }
is_private() { case "$1" in beta|dev|*-beta|*-dev) return 0;; *) return 1;; esac; }
# curl with token header only when ref is a private channel
gh_curl() {  # $1=ref, rest=curl args
    local ref="$1"; shift
    if is_private "$ref" && [ -n "$GH_TOKEN" ]; then
        curl -H "Authorization: token $GH_TOKEN" "$@"
    else
        curl "$@"
    fi
}

fetch_repo_file() {  # $1=ref $2=repo_path $3=output
    local ref="$1" rp="$2" out="$3" repo
    repo=$(repo_for "$ref")
    if is_private "$ref" && [ -n "$GH_TOKEN" ]; then
        curl -fsSL -m25 -H "Authorization: token $GH_TOKEN" \
            -H "Accept: application/vnd.github.raw" \
            "https://api.github.com/repos/$repo/contents/$rp?ref=$ref" -o "$out"
    else
        gh_curl "$ref" -fsSL -m25 \
            "https://raw.githubusercontent.com/$repo/$ref/$rp?cb=$(date +%s)" -o "$out"
    fi
}

fetch_repo_text() {  # $1=ref $2=repo_path
    local tmp rc
    tmp=$(mktemp)
    fetch_repo_file "$1" "$2" "$tmp"; rc=$?
    if [ "$rc" = 0 ]; then cat "$tmp"; fi
    rm -f "$tmp"
    return "$rc"
}

refresh_phoboswg_apk() {  # $1=ref/channel
    local ref="${1:-}"
    is_private "$ref" || return 0
    [ -n "$GH_TOKEN" ] || return 0
    local apk="$PHOBOS_DIR/www/app/PhobosWG.apk"
    mkdir -p "$PHOBOS_DIR/www/app"
    local cur_sha
    cur_sha="$(sha256sum "$apk" 2>/dev/null | awk '{print $1}')"
    if [ "$cur_sha" = "$PHOBOSWG_APK_SHA256" ]; then
        echo "[APK] PhobosWG.apk current"
        return 0
    fi
    echo "[APK] Refreshing PhobosWG.apk from release $PHOBOSWG_APK_TAG..."
    local apk_api_url
    apk_api_url="$(curl -fsSL -m15 -H "Authorization: token $GH_TOKEN" \
        "https://api.github.com/repos/$DEV_REPO/releases/tags/$PHOBOSWG_APK_TAG" 2>/dev/null \
        | grep -B8 '"name": "PhobosWG.apk"' | grep '"url"' | head -1 | cut -d'"' -f4)"
    if [ -n "$apk_api_url" ] && curl -fsSL -m120 -H "Authorization: token $GH_TOKEN" \
        -H "Accept: application/octet-stream" "$apk_api_url" -o "$apk"; then
        local new_sha
        new_sha="$(sha256sum "$apk" 2>/dev/null | awk '{print $1}')"
        if [ "$new_sha" = "$PHOBOSWG_APK_SHA256" ]; then
            echo "[APK] Downloaded PhobosWG.apk: $(ls -lh "$apk" | awk '{print $5}')"
        else
            rm -f "$apk"
            echo "[APK] SHA mismatch after download (non-fatal)"
        fi
    else
        echo "[APK] Download failed (non-fatal)"
    fi
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
latest_version() { curl -fsSL -m10 "https://raw.githubusercontent.com/$PUB_REPO/main/VERSION" 2>/dev/null | tr -d ' \r\n'; }

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
    b=$(chan_version beta); d=$(chan_version dev)
    if [ -n "$GH_TOKEN" ]; then
        [ -n "$b" ] && echo "Бета (beta):    $b   [приватный, токен ок]"
        [ -n "$d" ] && echo "Разработка(dev):$d   [приватный, токен ок]"
    else
        echo "Бета (beta):    —   [приватный: нужен GH_TOKEN подписчика]"
        echo "Разработка(dev):—   [приватный: нужен GH_TOKEN подписчика]"
    fi
    ;;
  --versions|--tags)
    echo "Стабильные версии (публичные теги):"
    curl -fsSL -m10 "https://api.github.com/repos/$PUB_REPO/tags?per_page=100" 2>/dev/null \
      | grep -oE '"name": *"[^"]+"' | sed 's/.*"name": *"\(.*\)"/  \1/' || echo "  (нет данных)"
    if [ -n "$GH_TOKEN" ]; then
        echo "Закрытые версии (приватные теги, beta/dev):"
        curl -fsSL -m10 -H "Authorization: token $GH_TOKEN" "https://api.github.com/repos/$DEV_REPO/tags?per_page=100" 2>/dev/null \
          | grep -oE '"name": *"[^"]+"' | sed 's/.*"name": *"\(.*\)"/  \1/' || echo "  (нет данных)"
    fi
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
    refresh_phoboswg_apk "$ref"
    run_self_check
    refresh_router_packages
    echo "$target" > "$VERFILE"
    restart_panel_service
    echo "Обновлено до $target. Откат: phobos-update --rollback"
    ;;
esac
