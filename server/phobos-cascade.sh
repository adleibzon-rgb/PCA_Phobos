#!/usr/bin/env bash
# PCA Phobos — cascade relay. Run on an ENTRY VPS (e.g. in Russia, "white" IP):
# clients connect to this server, UDP obfuscator ports are forwarded to the EXIT
# Phobos server abroad. The entry box needs no Phobos, no keys, no panel.
#   bash <(curl -fsSL .../server/phobos-cascade.sh) enable <exit_host> [ports]
#   phobos-cascade.sh disable | status | apply
# Then in the exit server panel: Settings -> "Адрес для клиентов" -> entry IP/domain.
set -uo pipefail
STATE=/etc/phobos-cascade.env
BIN=/usr/local/sbin/phobos-cascade
SELF_URL="${SELF_URL:-https://git.bobyrev.com/PCA/PCA_Phobos/raw/branch/main/server/phobos-cascade.sh}"
TAG="phobos-cascade"

clear_rules() {
    local t
    for t in nat filter; do
        iptables -t $t -S 2>/dev/null | grep -- "--comment $TAG" | sed 's/^-A /-D /' | \
            while read -r rule; do eval iptables -t $t $rule 2>/dev/null; done
    done
}

apply() {
    [ -f "$STATE" ] || { echo "cascade: not configured"; return 0; }
    . "$STATE"
    local ip p
    ip=$(getent ahostsv4 "$EXIT_HOST" | awk 'NR==1{print $1}')
    [ -n "$ip" ] || { echo "cascade: cannot resolve $EXIT_HOST" >&2; return 1; }
    sysctl -qw net.ipv4.ip_forward=1
    clear_rules
    for p in ${PORTS//,/ }; do
        iptables -t nat -A PREROUTING -p udp --dport "$p" -m comment --comment $TAG -j DNAT --to-destination "$ip:$p"
        iptables -t nat -A POSTROUTING -p udp -d "$ip" --dport "$p" -m comment --comment $TAG -j MASQUERADE
        iptables -I FORWARD -p udp -d "$ip" --dport "$p" -m comment --comment $TAG -j ACCEPT
        iptables -I FORWARD -p udp -s "$ip" --sport "$p" -m comment --comment $TAG -j ACCEPT
    done
    echo "cascade: udp ${PORTS} -> ${EXIT_HOST} (${ip})"
}

enable() {
    local host="${1:-}" ports="${2:-2083,5443,993}"
    [ -n "$host" ] || { echo "usage: $0 enable <exit_host> [ports]" >&2; exit 2; }
    [[ "$ports" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "bad ports: $ports" >&2; exit 2; }
    command -v iptables >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables >/dev/null
    printf 'EXIT_HOST=%s\nPORTS=%s\n' "$host" "$ports" > "$STATE"
    # bash <(curl ...) gives a pipe as $0 -> fetch a real copy for the systemd unit
    if [ "$(readlink -f "$0")" != "$BIN" ]; then
        if [ -f "$0" ]; then cp "$0" "$BIN"; else curl -kfsSL -m30 "$SELF_URL" -o "$BIN" || { echo "cannot save $BIN" >&2; exit 1; }; fi
        chmod +x "$BIN"
    fi
    cat > /etc/systemd/system/phobos-cascade.service <<EOF
[Unit]
Description=PCA Phobos cascade relay
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN apply
ExecStop=$BIN stop
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable phobos-cascade.service >/dev/null 2>&1
    systemctl restart phobos-cascade.service
    apply >/dev/null
    status
}

disable() {
    systemctl disable --now phobos-cascade.service >/dev/null 2>&1 || true
    clear_rules
    rm -f /etc/systemd/system/phobos-cascade.service "$STATE"
    systemctl daemon-reload
    echo "cascade: disabled"
}

status() {
    local host="" ports="" rules
    [ -f "$STATE" ] && . "$STATE" && host="$EXIT_HOST" && ports="$PORTS"
    rules=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -c -- "--comment $TAG")
    printf '{"enabled": %s, "exit_host": "%s", "ports": "%s", "rules": %s}\n' \
        "$([ "$rules" -gt 0 ] && echo true || echo false)" "$host" "$ports" "$rules"
}

case "${1:-status}" in
    enable)  enable "${2:-}" "${3:-}" ;;
    apply)   apply ;;
    stop)    clear_rules ;;
    disable) disable ;;
    status)  status ;;
    *) echo "usage: $0 enable <exit_host> [ports]|disable|status"; exit 2 ;;
esac
