#!/usr/bin/env bash
# PCA Phobos — TCP fallback: clients whose UDP is cut reach the obfuscator over TCP.
# udptcp -s 0.0.0.0:<TCP_PORT> -> 127.0.0.1:<first obfuscator port> (UDP).
#   phobos-tcp.sh enable [port]   pick a free port (443, 8443, 2096) unless given; idempotent
#   phobos-tcp.sh disable | status
set -uo pipefail
PHOBOS_DIR=/opt/Phobos
ENV="$PHOBOS_DIR/server/server.env"
BIN="$PHOBOS_DIR/bin/udptcp"

env_get() { grep -E "^$1=" "$ENV" 2>/dev/null | tail -1 | cut -d= -f2-; }
env_set() {
    grep -v -E "^$1=" "$ENV" > "$ENV.tmp" 2>/dev/null || true
    echo "$1=$2" >> "$ENV.tmp" && mv "$ENV.tmp" "$ENV"
}
port_busy() { ss -lntH "sport = :$1" 2>/dev/null | grep -q .; }

enable() {
    [ -x "$BIN" ] || { echo "udptcp binary missing: $BIN (phobos-update)" >&2; exit 1; }
    local port="${1:-$(env_get TCP_PORT)}" obf
    obf=$(env_get OBFUSCATOR_PORTS | cut -d, -f1); obf="${obf:-2083}"
    # keep our own port if the service already holds it
    if [ -z "$port" ] || { port_busy "$port" && ! systemctl is-active -q phobos-tcp; }; then
        port=""
        for p in 443 8443 2096 4433; do port_busy "$p" || { port=$p; break; }; done
    fi
    [ -n "$port" ] || { echo "no free TCP port (443/8443/2096/4433)" >&2; exit 1; }
    env_set TCP_PORT "$port"
    cat > /etc/systemd/system/phobos-tcp.service <<EOF
[Unit]
Description=PCA Phobos TCP fallback (udptcp -> obfuscator :$obf)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$BIN -s 0.0.0.0:$port 127.0.0.1:$obf
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable -q phobos-tcp
    systemctl restart phobos-tcp
    sleep 1
    status
}

disable() {
    systemctl disable --now phobos-tcp >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/phobos-tcp.service
    systemctl daemon-reload
    echo "tcp fallback: disabled"
}

status() {
    printf '{"enabled": %s, "port": "%s"}\n' \
        "$(systemctl is-active -q phobos-tcp && echo true || echo false)" "$(env_get TCP_PORT)"
}

case "${1:-status}" in
    enable)  enable "${2:-}" ;;
    disable) disable ;;
    status)  status ;;
    *) echo "usage: $0 enable [port]|disable|status"; exit 2 ;;
esac
