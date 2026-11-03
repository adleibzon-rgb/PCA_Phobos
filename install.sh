#!/bin/bash
# ============================================================
#  PCA Phobos — TURNKEY installer (primary / panel node)
#
#  One command, all dependencies, from a clean VPS:
#    bash <(curl -fsSL https://git.bobyrev.com/PCA/PCA_Phobos/raw/branch/main/install.sh)
#
#  Installs, in order:
#    deps -> wg-obfuscator (Ground-Zerro) -> WireGuard wg0 ->
#    obfuscator services -> Phobos repo (onboarding scripts) +
#    PCA patches -> web panel -> nginx (/init,/packages) ->
#    server-side router watchdog.
#
#  Env (all optional):
#    PANEL_PORT   random 10000-59999   web panel port
#    PANEL_TLS_CERT / PANEL_TLS_KEY     enable native HTTPS for panel
#    PANEL_PASS   OcAdmin2026!         panel admin password
#    API_KEY      random               shared key (agents + router pull token)
#    OBF_PORTS    2083,5443,993        obfuscator listen ports
#    TG_TOKEN / TG_CHAT                Telegram alerts
#    PCA_BRANCH   main                 branch to pull PCA files from
# ============================================================
set -e

PANEL_PASS="${PANEL_PASS:-OcAdmin2026!}"
PANEL_TLS_CERT="${PANEL_TLS_CERT:-}"
PANEL_TLS_KEY="${PANEL_TLS_KEY:-}"
PANEL_SCHEME="${PANEL_SCHEME:-http}"
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT="${TG_CHAT:-}"
OBF_PORTS="${OBF_PORTS:-2083,5443,993}"
# Уже есть wg0.conf (переустановка) — подсеть берём из него, иначе server.env разойдётся с интерфейсом
if [ -z "${SERVER_WG_IPV4_NETWORK:-}" ] && [ -f /etc/wireguard/wg0.conf ]; then
    SERVER_WG_IPV4_NETWORK="$(python3 - <<'PY' 2>/dev/null
import ipaddress, re
for ln in open("/etc/wireguard/wg0.conf"):
    m = re.match(r"\s*Address\s*=\s*([^,\s]+)", ln)
    if m:
        print(ipaddress.ip_interface(m.group(1)).network); break
PY
)" || SERVER_WG_IPV4_NETWORK=""
fi
# Подсеть клиентов: env SERVER_WG_IPV4_NETWORK или вопрос в терминале (Enter = 10.25.0.0/16)
if [ -z "${SERVER_WG_IPV4_NETWORK:-}" ] && [ -r /dev/tty ] && [ -t 1 ]; then
    printf '\n!!! Это ВТОРОЙ сервер к уже работающей панели? Тогда прервите (Ctrl+C) и ставьте командой из панели\n    «Серверы -> Как добавить второй сервер» (secondary-setup.sh), подсеть там по умолчанию.\n    Своя подсеть нужна только для НЕЗАВИСИМОЙ панели (например 10.25.11.0/24, не пересекается с первой);\n    смена сервера у клиентов между независимыми панелями не работает.\n\n' > /dev/tty
    printf 'Подсеть VPN-клиентов [10.25.0.0/16]: ' > /dev/tty
    read -r -t 60 SERVER_WG_IPV4_NETWORK < /dev/tty || true
fi
SERVER_WG_IPV4_NETWORK="${SERVER_WG_IPV4_NETWORK:-10.25.0.0/16}"
SERVER_WG_IPV4_NETWORK="$(python3 - "$SERVER_WG_IPV4_NETWORK" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1].strip(), strict=True)
except ValueError:
    # «10.25.11.0/16» — биты хоста заданы: раньше молча превращалось в 10.25.0.0/16
    # (две установки с одинаковой подсетью → одинаковые IP клиентов, конфликт на роутере).
    # Считаем, что нужна подсеть этого адреса, и берём /24.
    try:
        net = ipaddress.ip_network(sys.argv[1].strip().split("/")[0] + "/24", strict=False)
        sys.stderr.write("NOTICE: subnet %s has host bits set, using %s\n" % (sys.argv[1], net))
    except ValueError:
        sys.exit("ERROR: bad subnet " + sys.argv[1])
if net.version != 4 or not net.is_private or net.prefixlen > 29:
    sys.exit("ERROR: subnet must be private IPv4, /8../29 (e.g. 10.25.1.0/24)")
print(net)
PY
)" || exit 1
# Источник: Gitea git.bobyrev.com (основной), GitHub — запасной.
# Каналы stable/beta/dev — ветки main/beta/dev одного публичного репозитория.
PCA_GIT="${PCA_GIT:-https://git.bobyrev.com/PCA/PCA_Phobos}"
GH_RAW="${GH_RAW:-https://raw.githubusercontent.com/andrey271192/PCA_Phobos}"
CHANNEL="${CHANNEL:-stable}"
case "$CHANNEL" in
  stable|main|"") PCA_BRANCH="${PCA_BRANCH:-main}";;
  *)              PCA_BRANCH="${PCA_BRANCH:-$CHANNEL}";;
esac
case "$PCA_BRANCH" in v[0-9]*) _kind=tag;; *) _kind=branch;; esac
PHOBOS_DIR="/opt/Phobos"
PANEL_DIR="/opt/phobos-panel"
RAW="$PCA_GIT/raw/$_kind/$PCA_BRANCH"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }

if [ -z "$PANEL_PORT" ]; then
    PANEL_PORT=$(shuf -i 10000-59999 -n 1 2>/dev/null || awk 'BEGIN{srand(); print int(10000+rand()*50000)}')
fi
if [ -n "$PANEL_TLS_CERT" ] || [ -n "$PANEL_TLS_KEY" ]; then
    [ -f "$PANEL_TLS_CERT" ] || { echo "ERROR: PANEL_TLS_CERT not found: $PANEL_TLS_CERT"; exit 1; }
    [ -f "$PANEL_TLS_KEY" ] || { echo "ERROR: PANEL_TLS_KEY not found: $PANEL_TLS_KEY"; exit 1; }
    PANEL_SCHEME="https"
fi
case "$PANEL_SCHEME" in http|https) ;; *) echo "ERROR: PANEL_SCHEME must be http or https"; exit 1;; esac
API_KEY="${API_KEY:-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)}"
WG_SERVER_IPV4="$(python3 - "$SERVER_WG_IPV4_NETWORK" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
print(next(net.hosts()))
PY
)"
WG_PREFIXLEN="$(python3 - "$SERVER_WG_IPV4_NETWORK" <<'PY'
import ipaddress, sys
print(ipaddress.ip_network(sys.argv[1], strict=False).prefixlen)
PY
)"

SERVER_IP=$(curl -s -m8 https://api.ipify.org || hostname -I | awk '{print $1}')
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1)
IFACE="${IFACE:-eth0}"
ARCH=$(uname -m)

echo "============================================"
echo "  PCA Phobos - turnkey primary install"
echo "  IP=$SERVER_IP iface=$IFACE arch=$ARCH"
echo "  panel port=$PANEL_PORT  obf ports=$OBF_PORTS"
echo "============================================"

# ── 1. dependencies ──
echo "[1/9] dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools iptables jq curl git ca-certificates \
    python3 python3-flask python3-pip gunicorn nginx cron python3-qrcode sshpass >/dev/null
apt-get install -y -qq python3-flask-sock >/dev/null 2>&1 || true
apt-get install -y -qq python3-asyncssh >/dev/null 2>&1 || true
apt-get install -y -qq python3-websocket >/dev/null 2>&1 || true
python3 - <<'PY' >/dev/null 2>&1 || python3 -m pip install flask-sock asyncssh websocket-client >/dev/null 2>&1 || python3 -m pip install --break-system-packages flask-sock asyncssh websocket-client >/dev/null
import flask_sock, asyncssh, websocket
PY
mkdir -p "$PANEL_DIR/static"
curl -fsSL -m20 https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css -o "$PANEL_DIR/static/xterm.min.css" 2>/dev/null || true
curl -fsSL -m20 https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js -o "$PANEL_DIR/static/xterm.min.js" 2>/dev/null || true
curl -fsSL -m20 https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js -o "$PANEL_DIR/static/xterm-addon-fit.min.js" 2>/dev/null || true
systemctl enable cron -q 2>/dev/null || true; systemctl start cron 2>/dev/null || true

# ── 2. wg-obfuscator binary (Ground-Zerro) ──
echo "[2/9] wg-obfuscator..."
mkdir -p "$PHOBOS_DIR"/{server,clients,bin,tokens,www/init,www/packages,packages}
OBF_ARCH="$ARCH"
[ "$OBF_ARCH" = "amd64" ] && OBF_ARCH="x86_64"
[ "$OBF_ARCH" = "arm64" ] && OBF_ARCH="aarch64"
if [ ! -x /usr/local/bin/wg-obfuscator ]; then
    R=/tmp/phobos-obf; rm -rf "$R"; mkdir -p "$R"; cd "$R"
    git init -q; git remote add origin https://github.com/Ground-Zerro/Phobos.git
    git config core.sparseCheckout true; echo "wg-obfuscator" > .git/info/sparse-checkout
    git pull origin main -q
    cp -f "wg-obfuscator/bin/"wg-obfuscator-* "$PHOBOS_DIR/bin/" 2>/dev/null || true
    chmod +x "$PHOBOS_DIR/bin/"wg-obfuscator-* 2>/dev/null || true
    ln -sf "$PHOBOS_DIR/bin/wg-obfuscator-${OBF_ARCH}" /usr/local/bin/wg-obfuscator 2>/dev/null || true
    cd /; rm -rf "$R"
fi
_OBF_TAG=$(curl -fsSL -m10 https://api.github.com/repos/ClusterM/wg-obfuscator/releases/latest 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
_CB="https://github.com/ClusterM/wg-obfuscator/releases/download/${_OBF_TAG}"
for _am in "x86_64:linux-x64" "aarch64:linux-arm64" "mipsel:linux-mipsel-mips32" "mips:linux-mips-mips32" "armv7:linux-armv7-hf"; do
  _da="${_am%%:*}"; _ss="${_am##*:}"
  if [ ! -f "$PHOBOS_DIR/bin/wg-obfuscator-${_da}" ] && [ -n "$_OBF_TAG" ]; then
    _t=$(mktemp -d)
    curl -fsSL -m30 "${_CB}/wg-obfuscator-${_OBF_TAG}-${_ss}.tar.gz" -o "$_t/o.tgz" 2>/dev/null &&
      tar -xzf "$_t/o.tgz" -C "$_t" 2>/dev/null &&
      _b=$(find "$_t" -name "wg-obfuscator" -type f | head -1) &&
      [ -n "$_b" ] && cp "$_b" "$PHOBOS_DIR/bin/wg-obfuscator-${_da}" && chmod +x "$PHOBOS_DIR/bin/wg-obfuscator-${_da}" && echo "  +wg-obfuscator-${_da} (ClusterM ${_OBF_TAG})"
    rm -rf "$_t"
  fi
done
[ -x /usr/local/bin/wg-obfuscator ] || ln -sf "$PHOBOS_DIR/bin/wg-obfuscator-${OBF_ARCH}" /usr/local/bin/wg-obfuscator 2>/dev/null || true
[ -x /usr/local/bin/wg-obfuscator ] || { echo "ERROR: obfuscator binary for $ARCH missing"; exit 1; }
echo "  bins: $(ls $PHOBOS_DIR/bin/ | tr '\n' ' ')"

# ── 3. Phobos repo (onboarding scripts) ──
echo "[3/9] Phobos repo (onboarding scripts)..."
R="$PHOBOS_DIR/repo"; rm -rf "$R"; mkdir -p "$R"; cd "$R"
git init -q; git remote add origin https://github.com/Ground-Zerro/Phobos.git
git config core.sparseCheckout true
printf 'server\nclient\n' > .git/info/sparse-checkout
git pull origin main -q; rm -rf .git
find "$R" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
cd /

# ── 4. WireGuard wg0 (primary) ──
echo "[4/9] WireGuard wg0..."
if [ ! -f /etc/wireguard/wg0.conf ]; then
    WG_PRIV=$(wg genkey); WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
    cat > /etc/wireguard/wg0.conf <<WG
[Interface]
Address = ${WG_SERVER_IPV4}/${WG_PREFIXLEN}
ListenPort = 51820
PrivateKey = $WG_PRIV
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
WG
    chmod 600 /etc/wireguard/wg0.conf
else
    WG_PRIV=$(grep '^PrivateKey' /etc/wireguard/wg0.conf | cut -d= -f2- | tr -d ' ')
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
fi
sysctl -w net.ipv4.ip_forward=1 -q
grep -q '^net.ipv4.ip_forward = 1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
systemctl enable wg-quick@wg0 -q 2>/dev/null || true
systemctl restart wg-quick@wg0

# ── 5. obfuscator services (multi-port) ──
echo "[5/9] obfuscator services..."
OBF_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
# Block direct WG (force obfuscation) unless ALLOW_PLAIN_WG=1 (e.g. for iOS WireGuard)
if [ -z "${ALLOW_PLAIN_WG:-}" ]; then
    iptables -C INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP 2>/dev/null \
        || iptables -A INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP
else
    iptables -D INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP 2>/dev/null || true
fi
IFS=',' read -ra PORTS <<< "$OBF_PORTS"
for PORT in "${PORTS[@]}"; do
    cat > "$PHOBOS_DIR/server/wg-obfuscator-${PORT}.conf" <<EOF
[instance]
source-if = 0.0.0.0
source-lport = ${PORT}
target = 127.0.0.1:51820
key = ${OBF_KEY}
masking = AUTO
verbose = INFO
idle-timeout = 300
max-dummy = 50
EOF
    cat > /etc/systemd/system/wg-obfuscator-${PORT}.service <<EOF
[Unit]
Description=WireGuard Obfuscator (port ${PORT})
After=network.target wg-quick@wg0.service
[Service]
Type=simple
ExecStart=/usr/local/bin/wg-obfuscator --config ${PHOBOS_DIR}/server/wg-obfuscator-${PORT}.conf
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
done
systemctl daemon-reload
for PORT in "${PORTS[@]}"; do systemctl enable wg-obfuscator-${PORT} -q; systemctl restart wg-obfuscator-${PORT}; done

# server.env (primary)
cat > "$PHOBOS_DIR/server/server.env" <<EOF
SERVER_WG_PRIVATE_KEY=$WG_PRIV
SERVER_WG_PUBLIC_KEY=$WG_PUB
SERVER_PUBLIC_IP_V4=$SERVER_IP
SERVER_WG_IPV4_NETWORK=$SERVER_WG_IPV4_NETWORK
SERVER_WG_IPV4_ADDRESS=${WG_SERVER_IPV4}/${WG_PREFIXLEN}
OBFUSCATOR_KEY=$OBF_KEY
OBFUSCATOR_PORTS=$OBF_PORTS
CLIENT_WG_PORT=51820
ROLE=primary
EOF

# ── 6. PCA patches over onboarding scripts + server-side helpers ──
echo "[6/9] PCA patches (tunnel-pull, self-heal, watchdog, 403 fix)..."
fetch() {
    mkdir -p "$(dirname "$2")"
    # ponytail: файл из архива рядом с install.sh — не ходим в сеть.
    if [ -f "$SRC/$1" ]; then cp -f "$SRC/$1" "$2" && return 0; fi
    curl -fsSL -m20 "$RAW/$1?cb=$(date +%s)" -o "$2" && return 0
    curl -fsSL -m20 "$GH_RAW/$PCA_BRANCH/$1?cb=$(date +%s)" -o "$2" && return 0
    echo "  WARN: fetch $1 failed"; return 1
}
fetch overlay/lib-core.sh                      "$PHOBOS_DIR/repo/server/scripts/lib-core.sh"             && chmod +x "$PHOBOS_DIR/repo/server/scripts/lib-core.sh"
fetch overlay/phobos-client.sh                 "$PHOBOS_DIR/repo/server/scripts/phobos-client.sh"        && chmod +x "$PHOBOS_DIR/repo/server/scripts/phobos-client.sh"
fetch overlay/install-router.sh.template       "$PHOBOS_DIR/repo/client/templates/install-router.sh.template"
fetch overlay/lib-client.sh                    "$PHOBOS_DIR/repo/client/templates/lib-client.sh"         && chmod +x "$PHOBOS_DIR/repo/client/templates/lib-client.sh"
fetch overlay/install-obfuscator.sh            "$PHOBOS_DIR/repo/client/templates/install-obfuscator.sh" && chmod +x "$PHOBOS_DIR/repo/client/templates/install-obfuscator.sh"
fetch overlay/install-wireguard.sh             "$PHOBOS_DIR/repo/client/templates/install-wireguard.sh"  && chmod +x "$PHOBOS_DIR/repo/client/templates/install-wireguard.sh"
fetch overlay/router-configure-wireguard.sh    "$PHOBOS_DIR/repo/client/templates/router-configure-wireguard.sh" && chmod +x "$PHOBOS_DIR/repo/client/templates/router-configure-wireguard.sh"
fetch overlay/router-configure-wireguard-openwrt.sh "$PHOBOS_DIR/repo/client/templates/router-configure-wireguard-openwrt.sh" && chmod +x "$PHOBOS_DIR/repo/client/templates/router-configure-wireguard-openwrt.sh"
fetch overlay/phobos-pull.sh                    "$PHOBOS_DIR/repo/client/templates/phobos-pull.sh"        && chmod +x "$PHOBOS_DIR/repo/client/templates/phobos-pull.sh"
fetch overlay/phobos-ttyd.sh                     "$PHOBOS_DIR/repo/client/templates/phobos-ttyd.sh"       && chmod +x "$PHOBOS_DIR/repo/client/templates/phobos-ttyd.sh" && cp "$PHOBOS_DIR/repo/client/templates/phobos-ttyd.sh" "$PHOBOS_DIR/www/phobos-ttyd.sh" 2>/dev/null || true
fetch overlay/phobos-uninstall.sh              "$PHOBOS_DIR/repo/client/templates/phobos-uninstall.sh"   && chmod +x "$PHOBOS_DIR/repo/client/templates/phobos-uninstall.sh"
fetch overlay/3xui.sh                          "$PHOBOS_DIR/repo/client/templates/3xui.sh"               && chmod +x "$PHOBOS_DIR/repo/client/templates/3xui.sh"
fetch server/phobos-warp.sh                    "$PHOBOS_DIR/server/phobos-warp.sh"                       && chmod +x "$PHOBOS_DIR/server/phobos-warp.sh" && ln -sf "$PHOBOS_DIR/server/phobos-warp.sh" /usr/local/bin/phobos-warp
fetch server/phobos-guard.sh                "$PHOBOS_DIR/server/phobos-guard.sh"              && chmod +x "$PHOBOS_DIR/server/phobos-guard.sh" && ln -sf "$PHOBOS_DIR/server/phobos-guard.sh" /usr/local/bin/phobos-guard
fetch server/phobos-cascade.sh              "$PHOBOS_DIR/server/phobos-cascade.sh"            && chmod +x "$PHOBOS_DIR/server/phobos-cascade.sh" && ln -sf "$PHOBOS_DIR/server/phobos-cascade.sh" /usr/local/bin/phobos-cascade
fetch server/phobos-domain.sh               "$PHOBOS_DIR/server/phobos-domain.sh"             && chmod +x "$PHOBOS_DIR/server/phobos-domain.sh" && ln -sf "$PHOBOS_DIR/server/phobos-domain.sh" /usr/local/bin/phobos-domain
fetch server/phobos-limit.sh                "$PHOBOS_DIR/server/phobos-limit.sh"              && chmod +x "$PHOBOS_DIR/server/phobos-limit.sh"
fetch server/phobos-speedtest.sh            "$PHOBOS_DIR/server/phobos-speedtest.sh"          && chmod +x "$PHOBOS_DIR/server/phobos-speedtest.sh"
fetch server/phobos-tcp.sh                  "$PHOBOS_DIR/server/phobos-tcp.sh"                && chmod +x "$PHOBOS_DIR/server/phobos-tcp.sh" && ln -sf "$PHOBOS_DIR/server/phobos-tcp.sh" /usr/local/bin/phobos-tcp
fetch "udptcp/bin/udptcp-$OBF_ARCH"         "$PHOBOS_DIR/bin/udptcp"                          && chmod +x "$PHOBOS_DIR/bin/udptcp"
fetch server/phobos-health.sh                   "$PHOBOS_DIR/server/phobos-health.sh"                     && chmod +x "$PHOBOS_DIR/server/phobos-health.sh"
fetch server/phobos-self-check.sh               "$PHOBOS_DIR/server/phobos-self-check.sh"                 && chmod +x "$PHOBOS_DIR/server/phobos-self-check.sh" && ln -sf "$PHOBOS_DIR/server/phobos-self-check.sh" /usr/local/bin/phobos-self-check
fetch server/phobos-pull.sh                     "$PHOBOS_DIR/server/phobos-pull.sh"                       && chmod +x "$PHOBOS_DIR/server/phobos-pull.sh"
fetch server/phobos-router-watchdog.py          "$PHOBOS_DIR/server/phobos-router-watchdog.py"
fetch server/api.py                             "$PHOBOS_DIR/server/api.py"
fetch server/secondary-setup.sh                 "$PHOBOS_DIR/server/secondary-setup.sh"                  && chmod +x "$PHOBOS_DIR/server/secondary-setup.sh"
fetch update.sh                                 "$PHOBOS_DIR/server/update.sh"             && chmod +x "$PHOBOS_DIR/server/update.sh" && ln -sf "$PHOBOS_DIR/server/update.sh" /usr/local/bin/phobos-update
fetch server/phobos-backup.sh                   "$PHOBOS_DIR/server/phobos-backup.sh"      && chmod +x "$PHOBOS_DIR/server/phobos-backup.sh" && ln -sf "$PHOBOS_DIR/server/phobos-backup.sh" /usr/local/bin/phobos-backup
mkdir -p "$PANEL_DIR"; fetch VERSION "$PANEL_DIR/.version" 2>/dev/null || true
[ -f "$PHOBOS_DIR/tokens/tokens.json" ] || echo '[]' > "$PHOBOS_DIR/tokens/tokens.json"
"$PHOBOS_DIR/server/phobos-self-check.sh" --fix

# ── 7. web panel ──
echo "[7/9] web panel..."
mkdir -p "$PANEL_DIR"
fetch app.py "$PANEL_DIR/app.py" || { echo "ERROR: panel app.py fetch failed"; exit 1; }
if [ ! -f "$PANEL_DIR/settings.json" ]; then
    cat > "$PANEL_DIR/settings.json" <<EOF
{
  "admin_pass": "$PANEL_PASS",
  "tg_bot_token": "$TG_TOKEN",
  "tg_chat_id": "$TG_CHAT",
  "monitor_interval": 30,
  "server_api_key": "$API_KEY",
  "labels": {},
  "subscriptions": {},
  "router_access": {},
  "client_assignments": {}
}
EOF
fi
echo "$PANEL_PORT" > "$PANEL_DIR/.port"
echo "$PANEL_SCHEME" > "$PANEL_DIR/.scheme"
TLS_ARGS=""
if [ "$PANEL_SCHEME" = "https" ]; then
    TLS_ARGS="--certfile $PANEL_TLS_CERT --keyfile $PANEL_TLS_KEY"
fi
cat > /etc/systemd/system/phobos-panel.service <<EOF
[Unit]
Description=Phobos VPN Web Panel
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service
[Service]
Type=simple
WorkingDirectory=$PANEL_DIR
ExecStart=/usr/bin/gunicorn -w 1 --threads 20 $TLS_ARGS -b 0.0.0.0:$PANEL_PORT app:app
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=PANEL_SCHEME=$PANEL_SCHEME
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable phobos-panel -q; systemctl restart phobos-panel

# TCP fallback for clients whose UDP is cut (port 443/8443/... picked automatically)
"$PHOBOS_DIR/server/phobos-tcp.sh" enable || echo "  WARN: TCP fallback not enabled"

# ── 8. nginx (serve /init + /packages over plain HTTP for routers) ──
echo "[8/9] nginx..."
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
cat > /etc/nginx/sites-available/phobos <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    location /init/     { alias /opt/Phobos/www/init/;     default_type application/x-sh; }
    location /packages/ { alias /opt/Phobos/www/packages/; default_type application/octet-stream; }
    location /app/      { alias /opt/Phobos/www/app/;      default_type application/octet-stream; }
    location / { return 404; }
}
NGINX
ln -sf /etc/nginx/sites-available/phobos /etc/nginx/sites-enabled/phobos
mkdir -p /opt/Phobos/www/app; chmod 755 /opt/Phobos/www /opt/Phobos/www/init /opt/Phobos/www/packages /opt/Phobos/www/app
nginx -t >/dev/null 2>&1 && systemctl enable nginx -q 2>/dev/null && systemctl restart nginx || echo "  WARN: nginx config test failed"

# ── 9. router watchdog (auto reboot-recovery) ──
echo "[9/9] router watchdog..."
if [ -f "$PHOBOS_DIR/server/phobos-router-watchdog.py" ]; then
    # set -e safe: grep -v on an empty crontab returns 1, so guard with || true
    CRON_CUR=$(crontab -l 2>/dev/null | grep -v phobos-router-watchdog || true)
    printf '%s\n%s\n' "$CRON_CUR" \
      "*/3 * * * * /usr/bin/python3 $PHOBOS_DIR/server/phobos-router-watchdog.py >/dev/null 2>&1" \
      | grep -v '^[[:space:]]*$' | crontab -
fi

sleep 2

# persist channel so phobos-update follows it
mkdir -p "$PANEL_DIR"
echo "$CHANNEL" > "$PANEL_DIR/.channel" 2>/dev/null || true

echo ""
echo "============================================"
echo "  Installation complete"
echo "  Panel : $PANEL_SCHEME://$SERVER_IP:$PANEL_PORT"
echo "  Login : admin"
echo "  Pass  : $PANEL_PASS"
echo "  API key (agents+pull): $API_KEY"
echo "  WG pub: $WG_PUB"
echo "============================================"
echo "Status:"
for s in wg-quick@wg0 phobos-panel nginx; do printf "  %-18s %s\n" "$s" "$(systemctl is-active $s 2>/dev/null)"; done
for PORT in "${PORTS[@]}"; do printf "  %-18s %s\n" "wg-obfuscator-$PORT" "$(systemctl is-active wg-obfuscator-$PORT 2>/dev/null)"; done
