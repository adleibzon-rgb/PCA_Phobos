#!/usr/bin/env bash
# PCA Phobos — guard: drop RKN probes / scanner subnets before they reach the server.
# Idea and IP list: github.com/Loorrr293/Auto_IPtables (list: Loorrr293/blocklist).
# We only download the IP list (data), never third-party code.
#   phobos-guard.sh enable [list_url]   install nft table + daily timer
#   phobos-guard.sh update              refresh the list now
#   phobos-guard.sh disable             remove table + timer
#   phobos-guard.sh status              JSON
set -uo pipefail
STATE=/etc/phobos-guard.env
DEFAULT_URL="https://raw.githubusercontent.com/Loorrr293/blocklist/main/blocklist.txt"
TABLE="inet phobos_guard"
SELF="$(readlink -f "$0")"

list_url() { [ -f "$STATE" ] && . "$STATE"; echo "${GUARD_URL:-$DEFAULT_URL}"; }

ensure_nft() {
    command -v nft >/dev/null 2>&1 && return 0
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null 2>&1
}

update_list() {
    local url tmp nf
    url="$(list_url)"
    tmp="$(mktemp)"; nf="$(mktemp)"
    curl -fsSL -m60 "$url" -o "$tmp" || { rm -f "$tmp" "$nf"; echo "download failed: $url" >&2; return 1; }
    nft add table $TABLE 2>/dev/null || true
    nft add set $TABLE v4 '{ type ipv4_addr; flags interval; auto-merge; }' 2>/dev/null || true
    nft add set $TABLE v6 '{ type ipv6_addr; flags interval; auto-merge; }' 2>/dev/null || true
    nft add chain $TABLE input '{ type filter hook input priority raw; policy accept; }' 2>/dev/null || true
    nft list chain $TABLE input | grep -q '@v4' || nft add rule $TABLE input ip saddr @v4 counter drop
    nft list chain $TABLE input | grep -q '@v6' || nft add rule $TABLE input ip6 saddr @v6 counter drop
    # collapse + skip private/loopback so a bad list can never cut LAN/tunnel/admin
    python3 - "$tmp" > "$nf" <<'PY'
import ipaddress, sys
v4, v6 = [], []
for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    for tok in line.split("#", 1)[0].split():
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if n.is_private or n.is_loopback or n.is_link_local or n.prefixlen == 0:
            continue
        (v6 if n.version == 6 else v4).append(n)
print("flush set inet phobos_guard v4")
print("flush set inet phobos_guard v6")
for name, nets in (("v4", v4), ("v6", v6)):
    nets = list(ipaddress.collapse_addresses(nets))
    for i in range(0, len(nets), 2000):
        print("add element inet phobos_guard %s { %s }" % (name, ", ".join(map(str, nets[i:i + 2000]))))
PY
    local rc=0
    nft -f "$nf" || rc=1
    rm -f "$tmp" "$nf"
    [ "$rc" = 0 ] && echo "guard: list loaded from $url"
    return "$rc"
}

enable() {
    ensure_nft || { echo "nftables install failed" >&2; exit 1; }
    [ -n "${1:-}" ] && echo "GUARD_URL=$1" > "$STATE" || touch "$STATE"
    cat > /etc/systemd/system/phobos-guard.service <<EOF
[Unit]
Description=PCA Phobos guard (RKN scanner blocklist)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$SELF update
EOF
    cat > /etc/systemd/system/phobos-guard.timer <<'EOF'
[Unit]
Description=Refresh PCA Phobos guard list daily
[Timer]
OnBootSec=1min
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now phobos-guard.timer >/dev/null 2>&1
    update_list
}

disable() {
    systemctl disable --now phobos-guard.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/phobos-guard.service /etc/systemd/system/phobos-guard.timer "$STATE"
    systemctl daemon-reload
    nft delete table $TABLE 2>/dev/null || true
    echo "guard: disabled"
}

status() {
    local on=false n4=0 drops=0
    if nft list table $TABLE >/dev/null 2>&1; then
        on=true
        n4=$(nft list set $TABLE v4 2>/dev/null | grep -o '[0-9.]*/[0-9]*\|[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | wc -l)
        drops=$(nft list chain $TABLE input 2>/dev/null | grep -o 'packets [0-9]*' | awk '{s+=$2} END {print s+0}')
    fi
    printf '{"enabled": %s, "networks": %s, "dropped_packets": %s, "timer": "%s", "url": "%s"}\n' \
        "$on" "$n4" "$drops" "$(systemctl is-active phobos-guard.timer 2>/dev/null)" "$(list_url)"
}

case "${1:-status}" in
    enable)  enable "${2:-}" ;;
    update)  update_list ;;
    disable) disable ;;
    status)  status ;;
    *) echo "usage: $0 enable [url]|update|disable|status"; exit 2 ;;
esac
