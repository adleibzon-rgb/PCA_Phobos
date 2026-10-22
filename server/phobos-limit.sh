#!/usr/bin/env bash
# PCA Phobos — per-client speed limit on wg0 (tc).
# limits file: one line per client "<tunnel_ip> <mbit>"  (download = upload = mbit)
#   phobos-limit.sh apply [file]   rebuild tc from file (default below)
#   phobos-limit.sh clear | status
set -uo pipefail
DEV="${WG_DEV:-wg0}"
FILE="${2:-/opt/Phobos/server/limits.conf}"

clear_tc() {
    tc qdisc del dev "$DEV" root 2>/dev/null
    tc qdisc del dev "$DEV" ingress 2>/dev/null
    return 0
}

apply() {
    ip link show "$DEV" >/dev/null 2>&1 || { echo "limit: $DEV is down"; return 0; }
    clear_tc
    [ -s "$FILE" ] || { echo "limit: no limits"; return 0; }
    tc qdisc add dev "$DEV" root handle 1: htb default 9999 r2q 1000
    tc class add dev "$DEV" parent 1: classid 1:9999 htb rate 10gbit 2>/dev/null
    tc qdisc add dev "$DEV" handle ffff: ingress
    local n=10 ip mbit count=0
    while read -r ip mbit _; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && "$mbit" =~ ^[0-9]+$ && "$mbit" -gt 0 ]] || continue
        # download (server -> client): shaped, packets queue instead of dropping
        tc class add dev "$DEV" parent 1: classid 1:$n htb rate "${mbit}mbit" ceil "${mbit}mbit" burst 64k
        tc qdisc add dev "$DEV" parent 1:$n fq_codel 2>/dev/null
        tc filter add dev "$DEV" parent 1: protocol ip prio 1 u32 match ip dst "$ip/32" flowid 1:$n
        # upload (client -> server): policed on ingress
        tc filter add dev "$DEV" parent ffff: protocol ip prio 1 u32 match ip src "$ip/32" \
            police rate "${mbit}mbit" burst $(( mbit * 64 + 256 ))k drop flowid :1
        n=$((n + 1)); count=$((count + 1))
    done < "$FILE"
    echo "limit: $count client(s) limited on $DEV"
}

status() {
    local cnt
    cnt=$(tc class show dev "$DEV" 2>/dev/null | grep -c 'htb 1:[1-9][0-9]* ' )
    cnt=$((cnt > 0 ? cnt - 1 : 0))
    printf '{"device": "%s", "limited": %s, "file": "%s"}\n' "$DEV" "$cnt" "$FILE"
}

case "${1:-status}" in
    apply)  apply ;;
    clear)  clear_tc; echo "limit: cleared" ;;
    status) status ;;
    *) echo "usage: $0 apply [file]|clear|status"; exit 2 ;;
esac
