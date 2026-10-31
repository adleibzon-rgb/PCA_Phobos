#!/bin/bash
# ============================================================
#  Phobos Secondary Server Setup
#  Deploys WG + obfuscator + mini-API (no web panel)
#
#  Usage:
#    MAIN_PROTO=http MAIN_SERVER=203.0.113.10 MAIN_PORT=10514 MAIN_API_KEY=secret123 \
#    bash <(curl -fsSL http://203.0.113.10:10514/server/secondary-setup.sh)
#
#  Uninstall:
#    bash /opt/Phobos/server/phobos-secondary-uninstall.sh
# ============================================================

set -e

MAIN_SERVER="${MAIN_SERVER:?Set MAIN_SERVER=ip_of_main_server}"
MAIN_API_KEY="${MAIN_API_KEY:?Set MAIN_API_KEY=your_api_key}"
MAIN_PROTO="${MAIN_PROTO:-http}"
MAIN_PORT="${MAIN_PORT:-8443}"
OBF_PORTS="${OBF_PORTS:-2083,5443,993}"
# Подсеть клиентов: env SERVER_WG_IPV4_NETWORK или вопрос в терминале (Enter = 10.25.0.0/16)
if [ -z "${SERVER_WG_IPV4_NETWORK:-}" ] && [ -r /dev/tty ] && [ -t 1 ]; then
    printf 'Подсеть VPN-клиентов [10.25.0.0/16]: ' > /dev/tty
    read -r -t 60 SERVER_WG_IPV4_NETWORK < /dev/tty || true
fi
SERVER_WG_IPV4_NETWORK="${SERVER_WG_IPV4_NETWORK:-10.25.0.0/16}"
SERVER_WG_IPV4_NETWORK="$(python3 - "$SERVER_WG_IPV4_NETWORK" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1].strip(), strict=False)
except ValueError:
    sys.exit("ERROR: bad subnet " + sys.argv[1])
if net.version != 4 or not net.is_private or net.prefixlen > 29:
    sys.exit("ERROR: subnet must be private IPv4, /8../29 (e.g. 10.25.1.0/24)")
print(net)
PY
)" || exit 1
PHOBOS_DIR="/opt/Phobos"
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

SERVER_IP="${SERVER_IP:-$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')}"
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1)
IFACE="${IFACE:-eth0}"
case "$MAIN_PROTO" in http|https) ;; *) echo "ERROR: MAIN_PROTO must be http or https"; exit 1;; esac

# ── Pre-flight safety checks ──
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║    Phobos Secondary Server — Pre-flight Check        ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Server IP   : $SERVER_IP"
echo "║  Interface   : $IFACE"
echo "║  Main server : $MAIN_SERVER"
echo "║  Main proto  : $MAIN_PROTO"
echo "║  Main port   : $MAIN_PORT"
echo "║  OBF ports   : $OBF_PORTS"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

WARNINGS=0

# Check existing WireGuard
if [ -f /etc/wireguard/wg0.conf ]; then
    echo "⚠  EXISTING wg0.conf found at /etc/wireguard/wg0.conf"
    echo "   Current peers: $(grep -c '^\[Peer\]' /etc/wireguard/wg0.conf 2>/dev/null || echo 0)"
    WARNINGS=$((WARNINGS + 1))
fi

if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
    echo "⚠  WireGuard wg0 is RUNNING"
    WARNINGS=$((WARNINGS + 1))
fi

# Check existing Phobos installation
if [ -d "$PHOBOS_DIR/clients" ] && [ "$(ls -A $PHOBOS_DIR/clients 2>/dev/null)" ]; then
    CLIENT_COUNT=$(ls -d $PHOBOS_DIR/clients/*/ 2>/dev/null | wc -l)
    echo "⚠  EXISTING Phobos client data: $CLIENT_COUNT client(s) in $PHOBOS_DIR/clients/"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -f "$PHOBOS_DIR/server/server.env" ]; then
    echo "⚠  EXISTING server.env found (previous Phobos installation)"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -f "$PHOBOS_DIR/tokens/tokens.json" ] && [ "$(cat $PHOBOS_DIR/tokens/tokens.json 2>/dev/null)" != "[]" ]; then
    echo "⚠  EXISTING tokens.json with active tokens"
    WARNINGS=$((WARNINGS + 1))
fi

# Check port conflicts
IFS=',' read -ra PORTS <<< "$OBF_PORTS"
for PORT in "${PORTS[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
        PROC=$(ss -tlnp 2>/dev/null | grep ":${PORT} " | awk '{print $NF}')
        echo "⚠  PORT $PORT already in use by: $PROC"
        WARNINGS=$((WARNINGS + 1))
    fi
done

if ss -tlnp 2>/dev/null | grep -q ":51820 "; then
    echo "⚠  PORT 51820 (WireGuard) already in use"
    WARNINGS=$((WARNINGS + 1))
fi

if ss -tlnp 2>/dev/null | grep -q ":8444 "; then
    echo "⚠  PORT 8444 (mini-API) already in use"
    WARNINGS=$((WARNINGS + 1))
fi

# Check conflicting services
for SVC in wg-obfuscator phobos-api; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
        echo "⚠  Service $SVC is already running"
        WARNINGS=$((WARNINGS + 1))
    fi
done

for PORT in "${PORTS[@]}"; do
    if systemctl is-active --quiet "wg-obfuscator-${PORT}" 2>/dev/null; then
        echo "⚠  Service wg-obfuscator-${PORT} is already running"
        WARNINGS=$((WARNINGS + 1))
    fi
done

if [ "$WARNINGS" -gt 0 ]; then
    echo ""
    echo "Found $WARNINGS warning(s). Existing configs will be preserved where possible."
    echo "Press Enter to continue or Ctrl+C to abort..."
    [ -t 0 ] && read -r < /dev/tty 2>/dev/null || true
fi

echo ""
echo "Starting installation..."

# ── 1. Backup existing configs ──
BACKUP_DIR="$PHOBOS_DIR/backup/$(date +%Y%m%d_%H%M%S)"
BACKED_UP=0
if [ -f /etc/wireguard/wg0.conf ] || [ -f "$PHOBOS_DIR/server/server.env" ] || [ -f "$PHOBOS_DIR/tokens/tokens.json" ]; then
    echo "[0/7] Backing up existing configs..."
    mkdir -p "$BACKUP_DIR"
    [ -f /etc/wireguard/wg0.conf ] && cp /etc/wireguard/wg0.conf "$BACKUP_DIR/" && BACKED_UP=$((BACKED_UP + 1))
    [ -f "$PHOBOS_DIR/server/server.env" ] && cp "$PHOBOS_DIR/server/server.env" "$BACKUP_DIR/" && BACKED_UP=$((BACKED_UP + 1))
    [ -f "$PHOBOS_DIR/tokens/tokens.json" ] && cp "$PHOBOS_DIR/tokens/tokens.json" "$BACKUP_DIR/" && BACKED_UP=$((BACKED_UP + 1))
    [ -d "$PHOBOS_DIR/clients" ] && cp -r "$PHOBOS_DIR/clients" "$BACKUP_DIR/" 2>/dev/null && BACKED_UP=$((BACKED_UP + 1))
    echo "   Backed up $BACKED_UP item(s) to $BACKUP_DIR"
fi

# ── 1. Dependencies ──
echo "[1/7] Installing dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard wireguard-tools iptables jq curl git ca-certificates python3 python3-flask gunicorn 2>/dev/null

# ── 2. Phobos binaries ──
echo "[2/7] Getting Phobos binaries..."
mkdir -p "$PHOBOS_DIR"/{server,clients,bin}

if [ ! -f /usr/local/bin/wg-obfuscator ]; then
    ARCH="$(uname -m)"
    OBF_ARCH="$ARCH"
    [ "$OBF_ARCH" = "amd64" ] && OBF_ARCH="x86_64"
    [ "$OBF_ARCH" = "arm64" ] && OBF_ARCH="aarch64"
    REPO_DIR="/tmp/phobos-repo"
    rm -rf "$REPO_DIR"
    mkdir -p "$REPO_DIR"
    cd "$REPO_DIR"
    git init -q
    git remote add origin https://github.com/Ground-Zerro/Phobos.git
    git config core.sparseCheckout true
    echo "wg-obfuscator" > .git/info/sparse-checkout
    git pull origin main -q 2>/dev/null
    cp -f wg-obfuscator/bin/wg-obfuscator-* "$PHOBOS_DIR/bin/" 2>/dev/null || true
    chmod +x "$PHOBOS_DIR/bin/"wg-obfuscator-* 2>/dev/null || true
    ln -sf "$PHOBOS_DIR/bin/wg-obfuscator-${OBF_ARCH}" /usr/local/bin/wg-obfuscator 2>/dev/null || true
    rm -rf "$REPO_DIR"

    if [ ! -x /usr/local/bin/wg-obfuscator ]; then
        OBF_TAG=$(curl -fsSL -m10 https://api.github.com/repos/ClusterM/wg-obfuscator/releases/latest 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
        CB="https://github.com/ClusterM/wg-obfuscator/releases/download/${OBF_TAG}"
        for MAP in "x86_64:linux-x64" "aarch64:linux-arm64" "mipsel:linux-mipsel-mips32" "mips:linux-mips-mips32" "armv7:linux-armv7-hf"; do
            DA="${MAP%%:*}"
            SS="${MAP##*:}"
            [ "$DA" = "$OBF_ARCH" ] || continue
            [ -n "$OBF_TAG" ] || continue
            TMP_DIR=$(mktemp -d)
            if curl -fsSL -m30 "${CB}/wg-obfuscator-${OBF_TAG}-${SS}.tar.gz" -o "$TMP_DIR/o.tgz" 2>/dev/null &&
               tar -xzf "$TMP_DIR/o.tgz" -C "$TMP_DIR" 2>/dev/null; then
                BIN_PATH=$(find "$TMP_DIR" -name "wg-obfuscator" -type f | head -1)
                if [ -n "$BIN_PATH" ]; then
                    cp "$BIN_PATH" "$PHOBOS_DIR/bin/wg-obfuscator-${DA}"
                    chmod +x "$PHOBOS_DIR/bin/wg-obfuscator-${DA}"
                    ln -sf "$PHOBOS_DIR/bin/wg-obfuscator-${DA}" /usr/local/bin/wg-obfuscator
                fi
            fi
            rm -rf "$TMP_DIR"
        done
    fi

    [ -x /usr/local/bin/wg-obfuscator ] || { echo "ERROR: obfuscator binary for $ARCH missing"; exit 1; }
    echo "   Obfuscator installed."
else
    echo "   Obfuscator already installed, skipping."
fi

# ── 3. WireGuard ──
echo "[3/7] Configuring WireGuard..."
if [ -f /etc/wireguard/wg0.conf ]; then
    echo "   Existing wg0.conf preserved (backed up to $BACKUP_DIR)"
    WG_PRIV=$(grep '^PrivateKey' /etc/wireguard/wg0.conf | cut -d= -f2- | tr -d ' ')
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
else
    WG_PRIV=$(wg genkey)
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)

    cat > /etc/wireguard/wg0.conf << WGEOF
[Interface]
Address = ${WG_SERVER_IPV4}/${WG_PREFIXLEN}
ListenPort = 51820
PrivateKey = $WG_PRIV
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
WGEOF
fi

sysctl -w net.ipv4.ip_forward=1 -q
grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

systemctl enable wg-quick@wg0 -q 2>/dev/null || true
systemctl restart wg-quick@wg0
echo "   WireGuard running."

# ── 4. Obfuscator (multi-port) ──
echo "[4/7] Setting up obfuscator..."
OBF_KEY=$(head -c 32 /dev/urandom | base64 | tr -d "/+=" | head -c 32)

# Block direct WG access
iptables -C INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP 2>/dev/null \
    || iptables -A INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP

IFS=',' read -ra PORTS <<< "$OBF_PORTS"
for PORT in "${PORTS[@]}"; do
    cat > "$PHOBOS_DIR/server/wg-obfuscator-${PORT}.conf" << EOF
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

    cat > /etc/systemd/system/wg-obfuscator-${PORT}.service << EOF
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
for PORT in "${PORTS[@]}"; do
    systemctl enable "wg-obfuscator-${PORT}" -q
    systemctl start "wg-obfuscator-${PORT}"
done
echo "   Obfuscator running on ports: $OBF_PORTS"

# ── 5. Save config ──
echo "[5/7] Saving config..."
cat > "$PHOBOS_DIR/server/server.env" << EOF
SERVER_WG_PRIVATE_KEY=$WG_PRIV
SERVER_WG_PUBLIC_KEY=$WG_PUB
SERVER_PUBLIC_IP_V4=$SERVER_IP
SERVER_WG_IPV4_NETWORK=$SERVER_WG_IPV4_NETWORK
SERVER_WG_IPV4_ADDRESS=${WG_SERVER_IPV4}/${WG_PREFIXLEN}
OBFUSCATOR_KEY=$OBF_KEY
OBFUSCATOR_PORTS=$OBF_PORTS
MAIN_SERVER=$MAIN_SERVER
MAIN_PROTO=$MAIN_PROTO
MAIN_API_KEY=$MAIN_API_KEY
MAIN_PORT=$MAIN_PORT
ROLE=secondary
EOF

# ── 6. Mini-API ──
echo "[6/7] Setting up mini-API..."
# Mini-API (fetched from the main panel first, then PCA GitHub fallback)
PCA_BRANCH="${PCA_BRANCH:-main}"
RAW="${PCA_RAW_BASE:-https://git.bobyrev.com/PCA/PCA_Phobos/raw/branch/${PCA_BRANCH}}"
PANEL_BOOTSTRAP="${MAIN_PROTO}://${MAIN_SERVER}:${MAIN_PORT}/server/api.py"
curl -kfsSL "$PANEL_BOOTSTRAP" -o "$PHOBOS_DIR/server/api.py" \
    || curl -fsSL "$RAW/server/api.py" -o "$PHOBOS_DIR/server/api.py" \
    || curl -fsSL "https://raw.githubusercontent.com/andrey271192/PCA_Phobos/${PCA_BRANCH}/server/api.py" -o "$PHOBOS_DIR/server/api.py"
[ -s "$PHOBOS_DIR/server/api.py" ] || { echo "ERROR: api.py fetch failed"; exit 1; }

cat > /etc/systemd/system/phobos-api.service << EOF
[Unit]
Description=Phobos Secondary API
After=network.target wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=/opt/Phobos/server
ExecStart=/usr/bin/gunicorn -w 1 -b 0.0.0.0:8444 api:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phobos-api -q
systemctl start phobos-api

# ── 7. Uninstall script ──
echo "[7/7] Creating uninstall script..."
cat > "$PHOBOS_DIR/server/phobos-secondary-uninstall.sh" << 'UNINSTEOF'
#!/bin/bash
# Phobos Secondary Server — Clean Uninstall
set -e

PHOBOS_DIR="/opt/Phobos"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║    Phobos Secondary Server — Uninstall               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "This will remove:"
echo "  - WireGuard interface wg0"
echo "  - All wg-obfuscator instances"
echo "  - Phobos mini-API"
echo "  - Phobos config files"
echo ""
echo "Backups (if any) in $PHOBOS_DIR/backup/ will be KEPT."
echo ""
echo "Press Enter to continue or Ctrl+C to abort..."
[ -t 0 ] && read -r < /dev/tty 2>/dev/null || true

echo "Stopping services..."
# Stop obfuscator instances
for svc in /etc/systemd/system/wg-obfuscator-*.service; do
    [ -f "$svc" ] || continue
    name=$(basename "$svc" .service)
    systemctl stop "$name" 2>/dev/null || true
    systemctl disable "$name" 2>/dev/null || true
    rm -f "$svc"
    echo "  Removed $name"
done

# Stop mini-API
systemctl stop phobos-api 2>/dev/null || true
systemctl disable phobos-api 2>/dev/null || true
rm -f /etc/systemd/system/phobos-api.service
echo "  Removed phobos-api"

# Stop WireGuard
systemctl stop wg-quick@wg0 2>/dev/null || true
systemctl disable wg-quick@wg0 2>/dev/null || true
echo "  Stopped WireGuard wg0"

systemctl daemon-reload

# Remove iptables rule
iptables -D INPUT -p udp --dport 51820 ! -s 127.0.0.1 -j DROP 2>/dev/null || true

echo ""
echo "Removing files..."

# Remove WG config
rm -f /etc/wireguard/wg0.conf
echo "  Removed /etc/wireguard/wg0.conf"

# Remove obfuscator binary (only the symlink)
rm -f /usr/local/bin/wg-obfuscator
echo "  Removed /usr/local/bin/wg-obfuscator"

# Keep backups, remove the rest
if [ -d "$PHOBOS_DIR/backup" ]; then
    echo "  Preserving $PHOBOS_DIR/backup/"
    # Remove everything except backup dir
    find "$PHOBOS_DIR" -mindepth 1 -maxdepth 1 ! -name 'backup' -exec rm -rf {} \;
else
    rm -rf "$PHOBOS_DIR"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         Uninstall Complete                           ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  WireGuard   : removed                               ║"
echo "║  Obfuscator  : removed                               ║"
echo "║  Mini-API    : removed                               ║"
if [ -d "$PHOBOS_DIR/backup" ]; then
echo "║  Backups     : preserved in $PHOBOS_DIR/backup/     ║"
fi
echo "╚══════════════════════════════════════════════════════╝"
echo ""
UNINSTEOF
chmod +x "$PHOBOS_DIR/server/phobos-secondary-uninstall.sh"

# ── Register with main server ──
echo ""
echo "Registering with main server..."
REG_DATA=$(cat << EOF
{
    "ip": "$SERVER_IP",
    "wg_public_key": "$WG_PUB",
    "obfuscator_key": "$OBF_KEY",
    "ports": "$(echo $OBF_PORTS)"
}
EOF
)
curl -ks -X POST "${MAIN_PROTO}://${MAIN_SERVER}:${MAIN_PORT}/api/servers/register" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${MAIN_API_KEY}" \
    -d "$REG_DATA" || echo "   (Registration will be done manually via panel)"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         Secondary Server Ready!                      ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Server IP     : $SERVER_IP"
echo "║  WG Public Key : $WG_PUB"
echo "║  OBF Key       : $OBF_KEY"
echo "║  OBF Ports     : $OBF_PORTS"
echo "║  API           : http://$SERVER_IP:8444"
echo "║  Main server   : $MAIN_SERVER"
echo "║                                                      ║"
echo "║  Uninstall: bash $PHOBOS_DIR/server/phobos-secondary-uninstall.sh"
echo "╚══════════════════════════════════════════════════════╝"
if [ -d "$PHOBOS_DIR/backup" ]; then
echo "  Backups: $BACKUP_DIR"
fi
echo ""
