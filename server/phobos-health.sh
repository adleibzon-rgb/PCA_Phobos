#!/bin/sh
# ============================================================
#  Phobos Health Monitor v2 — Keenetic Edition
#  Uses ndmc/RCI instead of wg-tools. Connectivity-based failover.
#  Runs via cron every 60 seconds
# ============================================================

PHOBOS_DIR="/opt/etc/Phobos"
CONF="$PHOBOS_DIR/failover.conf"
STATE="$PHOBOS_DIR/state"
LOG="$PHOBOS_DIR/health.log"
OBF_CONF="$PHOBOS_DIR/wg-obfuscator.conf"
LOCKFILE="/tmp/phobos-health.lock"
WG_IF="Wireguard3"

MAX_LOG_LINES=200
# Thresholds (seconds)
HANDSHAKE_WARN=150
HANDSHAKE_PORT_HOP=300
HANDSHAKE_SERVER_SWITCH=600
PRIMARY_CHECK_INTERVAL=300
# Primary-alive probe: servers block ICMP and busybox `nc -z` is unreliable,
# so reachability is tested with curl against the panel's obfuscator-health
# endpoint on the primary VPS. It returns http 200 ONLY when all
# wg-obfuscator-* services are active — the bare panel port stays up even
# when the tunnel path is dead, so we must NOT switch back on panel liveness
# alone (that caused premature switchback to a dead primary).
PRIMARY_PROBE_SCHEME="${PRIMARY_PROBE_SCHEME:-$(cat "$PHOBOS_DIR/panel_scheme" 2>/dev/null)}"
PRIMARY_PROBE_SCHEME="${PRIMARY_PROBE_SCHEME:-http}"
PRIMARY_PROBE_PORT="${PRIMARY_PROBE_PORT:-$(cat "$PHOBOS_DIR/panel_port" 2>/dev/null)}"
PRIMARY_PROBE_PORT="${PRIMARY_PROBE_PORT:-8443}"
PRIMARY_PROBE_PATH="/api/obf-health"
# Connectivity check targets (logged for context only)
CHECK_HOST_1="8.8.8.8"
CHECK_HOST_2="1.1.1.1"

log() {
    echo "$(date '+%H:%M:%S') $1" >> "$LOG"
    if [ "$(wc -l < "$LOG" 2>/dev/null)" -gt "$MAX_LOG_LINES" ]; then
        tail -n 100 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
    fi
}

# Prevent concurrent runs
if [ -f "$LOCKFILE" ]; then
    pid=$(cat "$LOCKFILE" 2>/dev/null)
    if kill -0 "$pid" 2>/dev/null; then
        exit 0
    fi
fi
echo $$ > "$LOCKFILE"
trap 'rm -f "$LOCKFILE"' EXIT

mkdir -p "$STATE"

# ── Detect WG interface ──
detect_wg_interface() {
    for i in 0 1 2 3 4 5 6 7 8 9; do
        desc=$(ndmc -c "show interface Wireguard${i}" 2>/dev/null | grep description | head -1)
        if echo "$desc" | grep -qi phobos; then
            WG_IF="Wireguard${i}"
            return 0
        fi
    done
    return 1
}

# ── Read failover config ──
if [ ! -f "$CONF" ]; then
    log "ERROR: no failover.conf"
    exit 1
fi

SERVER_COUNT=0
idx=1
while true; do
    val=$(grep "^SERVER_${idx}=" "$CONF" 2>/dev/null | cut -d= -f2-)
    [ -z "$val" ] && break
    eval "SERVER_${idx}_HOST=$(echo "$val" | cut -d: -f1)"
    eval "SERVER_${idx}_PORTS=$(echo "$val" | cut -d: -f2-)"
    eval "SERVER_${idx}_KEY=$(grep "^KEY_${idx}=" "$CONF" 2>/dev/null | cut -d= -f2-)"
    eval "SERVER_${idx}_WGKEY=$(grep "^WGKEY_${idx}=" "$CONF" 2>/dev/null | cut -d= -f2-)"
    SERVER_COUNT=$idx
    idx=$((idx + 1))
done

if [ "$SERVER_COUNT" -eq 0 ]; then
    log "ERROR: no servers in failover.conf"
    exit 1
fi

# Read state
CURRENT_SERVER=$(cat "$STATE/current_server" 2>/dev/null || echo "1")
CURRENT_PORT_IDX=$(cat "$STATE/current_port_idx" 2>/dev/null || echo "0")
FAIL_COUNT=$(cat "$STATE/fail_count" 2>/dev/null || echo "0")
PRIMARY_CHECK_TS=$(cat "$STATE/primary_check_ts" 2>/dev/null || echo "0")

# ── Detect Phobos WG interface (non-fatal, fallback to Wireguard3) ──
detect_wg_interface || {
    log "WARN: detect failed, using default $WG_IF"
}

# ── Get handshake age via ndmc ──
# A peer switch can leave the removed peer's stale handshake listed in ndmc
# output (often a huge sentinel like 2147483647). Take the FRESHEST (minimum
# positive, sane) handshake across all peers — that is the live tunnel.
get_handshake_age() {
    hs=$(ndmc -c "show interface $WG_IF" 2>/dev/null \
        | grep "last-handshake" \
        | awk '{v=$2} v>0 && v<86400 {print v}' \
        | sort -n | head -1)
    if [ -z "$hs" ]; then
        echo "9999"
    else
        echo "$hs"
    fi
}

# ── Check real connectivity ──
check_connectivity() {
    ping -c 1 -W 3 "$CHECK_HOST_1" >/dev/null 2>&1 && return 0
    ping -c 1 -W 3 "$CHECK_HOST_2" >/dev/null 2>&1 && return 0
    return 1
}

# ── Get port by index ──
get_port() {
    server_idx=$1; port_idx=$2
    eval "ports=\$SERVER_${server_idx}_PORTS"
    echo "$ports" | tr ',' '\n' | sed -n "$((port_idx + 1))p"
}

get_port_count() {
    server_idx=$1
    eval "ports=\$SERVER_${server_idx}_PORTS"
    echo "$ports" | tr ',' '\n' | wc -l
}

# ── Keys currently on the interface (includes the interface's OWN key) ──
# WG public keys are 43 base64 chars + '='. The interface's own public-key is
# also matched here — callers must only act on KNOWN server WGKEYs so the
# local key is never touched.
list_iface_keys() {
    ndmc -c "show interface $WG_IF" 2>/dev/null \
        | grep -oE '[A-Za-z0-9+/]{43}=' | sort -u
}

# Count how many KNOWN server WGKEYs are currently attached as peers.
count_server_peers() {
    present=$(list_iface_keys)
    n=0
    i=1
    while [ "$i" -le "$SERVER_COUNT" ]; do
        eval "wk=\$SERVER_${i}_WGKEY"
        if [ -n "$wk" ] && echo "$present" | grep -q "^${wk}$"; then
            n=$((n + 1))
        fi
        i=$((i + 1))
    done
    echo "$n"
}

# ── Switch WG peer so EXACTLY ONE server peer (new_key) remains ──
# Failover adds a new peer; the RCI "remove" is unreliable on Keenetic and
# leaves dead peers behind. Multiple peers each with allow-ips 0.0.0.0/0 make
# egress routing ambiguous. We hard-purge every OTHER known server key via the
# ndmc CLI (reliable) — never the interface's own key — then ensure new_key.
switch_wg_peer() {
    new_key=$1

    if [ -z "$new_key" ]; then
        log "WARN: no WGKEY for target server, skip peer switch"
        return 1
    fi

    present=$(list_iface_keys)

    # Purge any OTHER known server key that is attached
    i=1
    while [ "$i" -le "$SERVER_COUNT" ]; do
        eval "wk=\$SERVER_${i}_WGKEY"
        if [ -n "$wk" ] && [ "$wk" != "$new_key" ] && echo "$present" | grep -q "^${wk}$"; then
            log "WG PEER purge: $wk"
            ndmc -c "interface $WG_IF no wireguard peer $wk" >/dev/null 2>&1
        fi
        i=$((i + 1))
    done

    # Add the target peer if it is not already present
    if ! echo "$present" | grep -q "^${new_key}$"; then
        log "WG PEER add: $new_key"
        curl -s -X POST "http://localhost:79/rci/" \
            -H "Content-Type: application/json" \
            -d "{\"interface\":{\"${WG_IF}\":{\"wireguard\":{\"peer\":{\"key\":\"${new_key}\",\"comment\":\"Phobos VPS Server\",\"endpoint\":{\"address\":\"127.0.0.1:13255\"},\"keepalive-interval\":{\"interval\":25},\"allow-ips\":[{\"address\":\"0.0.0.0\",\"mask\":\"0.0.0.0\"},{\"address\":\"::\",\"mask\":\"0\"}]}}}}}" >/dev/null 2>&1
    fi

    # Persist config
    ndmc -c "system configuration save" >/dev/null 2>&1
    return 0
}

# ── Switch to specific server:port ──
switch_endpoint() {
    server_idx=$1
    port_idx=$2

    eval "host=\$SERVER_${server_idx}_HOST"
    eval "obf_key=\$SERVER_${server_idx}_KEY"
    eval "wg_key=\$SERVER_${server_idx}_WGKEY"
    port=$(get_port "$server_idx" "$port_idx")

    if [ -z "$host" ] || [ -z "$port" ]; then
        log "ERROR: invalid server $server_idx port_idx $port_idx"
        return 1
    fi

    log "SWITCH → server $server_idx ($host:$port)"

    # 1. Switch WG peer key if different server
    switch_wg_peer "$wg_key"

    # 2. Update obfuscator config
    if [ -f "$OBF_CONF" ]; then
        sed -i "s|^target = .*|target = ${host}:${port}|" "$OBF_CONF"
        if [ -n "$obf_key" ]; then
            sed -i "s|^key = .*|key = ${obf_key}|" "$OBF_CONF"
        fi
    fi

    # 3. Restart obfuscator
    if [ -f /opt/etc/init.d/S49wg-obfuscator ]; then
        /opt/etc/init.d/S49wg-obfuscator restart >/dev/null 2>&1
    else
        killall wg-obfuscator 2>/dev/null
        sleep 1
        wg-obfuscator --config "$OBF_CONF" &
    fi

    # 4. Save state (fail_count is managed by the caller, NOT reset here —
    #    resetting on a port-hop would prevent escalation to server failover)
    echo "$server_idx" > "$STATE/current_server"
    echo "$port_idx" > "$STATE/current_port_idx"
}

# ── Try next port on current server ──
try_next_port() {
    port_count=$(get_port_count "$CURRENT_SERVER")
    next_idx=$(( (CURRENT_PORT_IDX + 1) % port_count ))
    [ "$next_idx" -eq 0 ] && return 1

    log "PORT HOP → port idx $next_idx on server $CURRENT_SERVER"
    switch_endpoint "$CURRENT_SERVER" "$next_idx"
    return 0
}

# ── Try next server ──
try_next_server() {
    next=$((CURRENT_SERVER + 1))
    [ "$next" -gt "$SERVER_COUNT" ] && next=1
    [ "$next" -eq "$CURRENT_SERVER" ] && return 1

    log "FAILOVER → server $next"
    switch_endpoint "$next" "0"
    return 0
}

# ── Check if primary is back ──
check_primary() {
    [ "$CURRENT_SERVER" -eq 1 ] && return

    now=$(date +%s)
    elapsed=$((now - PRIMARY_CHECK_TS))
    [ "$elapsed" -lt "$PRIMARY_CHECK_INTERVAL" ] && return
    echo "$now" > "$STATE/primary_check_ts"

    eval "host=\$SERVER_1_HOST"
    # Probe the obfuscator-health endpoint: http 200 ONLY when the primary's
    # obfuscator path is actually up. Anything else (000 no-response, 503
    # obf-down, redirects) means the tunnel path is NOT viable → stay put.
    ok_url=""
    last_code=""
    for url in "${PRIMARY_PROBE_SCHEME}://${host}:${PRIMARY_PROBE_PORT}${PRIMARY_PROBE_PATH}" "http://${host}:8444${PRIMARY_PROBE_PATH}"; do
        code=$(curl -k -s -m 4 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
        last_code="$code"
        if [ "$code" = "200" ]; then
            ok_url="$url"
            break
        fi
    done
    if [ -n "$ok_url" ]; then
        log "PRIMARY ($ok_url http=200) alive, switching back"
        switch_endpoint 1 0
        echo "0" > "$STATE/fail_count"
    else
        log "PRIMARY still down (obf-health http=${last_code:-none}), staying on server $CURRENT_SERVER"
    fi
}

# ── LAN routing self-heal ──────────────────────
# A router REBOOT silently drops the per-device `ip hotspot host <mac> policy`
# binding and can reset the WG interface security-level, so LAN clients leak to
# WAN (no VPN). This:
#   1) ensures WG_IF security-level = public (needed for masquerade),
#   2) LEARNS current host->policy bindings into state/lan-hosts (append-only),
#   3) RE-APPLIES any learned binding that is currently missing.
# Append-only learning means a reboot (which clears live bindings) never erases
# the record, so the next run restores them. ndmc show running-config is heavy,
# so the caller gates this to run only every few minutes.
heal_lan_routing() {
    LANHOSTS="$STATE/lan-hosts"
    rc=$(ndmc -c "show running-config" 2>/dev/null)
    [ -z "$rc" ] && return 0

    # 1) WG interface must be public
    sl=$(echo "$rc" | awk -v ifc="interface $WG_IF" '$0~ifc{f=1} f&&/security-level/{print $2; exit}')
    if [ -n "$sl" ] && [ "$sl" != "public" ]; then
        ndmc -c "interface $WG_IF security-level public" >/dev/null 2>&1
        ndmc -c "system configuration save" >/dev/null 2>&1
        log "HEAL: $WG_IF security-level -> public"
    fi

    # 2) learn live bindings (append-only) into lan-hosts
    touch "$LANHOSTS"
    echo "$rc" | grep -oE "host [0-9a-f:]+ policy [A-Za-z0-9_]+" | while read -r _h mac _p pol; do
        grep -q "^$mac " "$LANHOSTS" 2>/dev/null || echo "$mac $pol" >> "$LANHOSTS"
    done

    # 3) re-apply any learned binding that is missing live
    changed=0
    while read -r mac pol; do
        [ -z "$mac" ] && continue
        case "$mac" in \#*) continue;; esac
        if ! echo "$rc" | grep -q "host $mac policy $pol"; then
            ndmc -c "ip hotspot host $mac policy $pol" >/dev/null 2>&1
            log "HEAL: re-bound host $mac -> $pol"
            changed=1
        fi
    done < "$LANHOSTS"
    [ "$changed" = 1 ] && ndmc -c "system configuration save" >/dev/null 2>&1
}

# ══════════════════════════════════════════════
#  Explicit apply hook (used by phobos-pull.sh after a config change).
#  `phobos-health.sh apply-server N` re-points the tunnel to SERVER_N
#  immediately, skipping the failure-escalation logic. Reuses
#  switch_endpoint so the WG-peer/obfuscator/state changes stay identical
#  to a normal failover. Resets fail_count so the new server starts clean.
# ══════════════════════════════════════════════
if [ "$1" = "apply-server" ]; then
    idx="${2:-1}"
    eval "ahost=\$SERVER_${idx}_HOST"
    if [ -z "$ahost" ]; then
        log "APPLY: server $idx not in conf, ignore"
        exit 1
    fi
    log "APPLY: pull requested server $idx ($ahost)"
    switch_endpoint "$idx" "0"
    echo "0" > "$STATE/fail_count"
    echo "$idx" > "$STATE/current_server"
    exit 0
fi

# ══════════════════════════════════════════════
#  Pre-check: fix desync (obfuscator targeting wrong server)
# ══════════════════════════════════════════════
if [ -f "$OBF_CONF" ]; then
    cur_target=$(grep "^target = " "$OBF_CONF" 2>/dev/null | sed 's/target = //')
    eval "expected_host=\$SERVER_${CURRENT_SERVER}_HOST"
    if [ -n "$cur_target" ] && [ -n "$expected_host" ]; then
        echo "$cur_target" | grep -q "$expected_host" || {
            log "DESYNC: obf=$cur_target state=server${CURRENT_SERVER}($expected_host). Resync."
            switch_endpoint "$CURRENT_SERVER" "$CURRENT_PORT_IDX"
            sleep 5
        }
    fi
fi

# ── LAN routing self-heal (gated ~5 min; a reboot drops host->policy bindings) ──
HEAL_TS=$(cat "$STATE/heal_ts" 2>/dev/null || echo 0)
now_heal=$(date +%s)
if [ $((now_heal - HEAL_TS)) -ge 300 ]; then
    echo "$now_heal" > "$STATE/heal_ts"
    heal_lan_routing
fi

# ── Peer hygiene: keep exactly ONE WG peer = current server's key ──
# Failovers can leave dead/duplicate peers; multiple 0.0.0.0/0 peers cause
# ambiguous egress routing. Self-heal here every run (cheap when already clean).
eval "cur_wgkey=\$SERVER_${CURRENT_SERVER}_WGKEY"
if [ -n "$cur_wgkey" ]; then
    peer_n=$(count_server_peers)
    if [ "$peer_n" -gt 1 ]; then
        log "HYGIENE: $peer_n server peers present, purging to server${CURRENT_SERVER}"
        switch_wg_peer "$cur_wgkey"
    fi
fi

# ══════════════════════════════════════════════
#  Main logic
#  Tunnel health = WireGuard handshake age (authoritative: a fresh
#  handshake only happens through the full obfuscator→server→WG path).
#  WAN ping is logged for context ONLY — it does NOT gate decisions,
#  because the router's default route is not the tunnel, so WAN can be
#  up while the tunnel is dead (and a WAN blip must not cause failover).
# ══════════════════════════════════════════════
AGE=$(get_handshake_age)
WAN=$(check_connectivity && echo "yes" || echo "no")

# Tunnel healthy = fresh handshake
if [ "$AGE" -lt "$HANDSHAKE_WARN" ]; then
    if [ "$FAIL_COUNT" -gt 0 ]; then
        log "OK: tunnel up (handshake=${AGE}s, server=$CURRENT_SERVER, wan=$WAN)"
        echo "0" > "$STATE/fail_count"
    fi
    check_primary
    exit 0
fi

# Stale handshake = tunnel down → escalate.
# fail_count is MONOTONIC: it climbs across stages and is only reset by the
# OK branch (real recovery) or after a successful failover to a NEW server
# (so the new server gets a fresh restart→port-hop→failover cycle).
FAIL_COUNT=$((FAIL_COUNT + 1))
echo "$FAIL_COUNT" > "$STATE/fail_count"
log "STALE: handshake=${AGE}s wan=${WAN} server=$CURRENT_SERVER port=$CURRENT_PORT_IDX fails=$FAIL_COUNT"

# Stage 1 (fail 1): Restart obfuscator
if [ "$FAIL_COUNT" -eq 1 ]; then
    log "ACTION: restart obfuscator"
    if [ -f /opt/etc/init.d/S49wg-obfuscator ]; then
        /opt/etc/init.d/S49wg-obfuscator restart >/dev/null 2>&1
    else
        killall wg-obfuscator 2>/dev/null
        sleep 1
        wg-obfuscator --config "$OBF_CONF" &
    fi
    exit 0
fi

# Stage 2 (fail 2): Port hop to an alternate port on the SAME server
if [ "$FAIL_COUNT" -eq 2 ]; then
    if try_next_port; then
        exit 0
    fi
    # only one port → fall through to server failover
    log "single port, escalate to failover"
fi

# Stage 3 (fail 3+): Server failover. Reset fail_count so the new server
# gets its own restart→port-hop→failover cycle next ticks.
log "ACTION: server failover (fail $FAIL_COUNT)"
if try_next_server; then
    echo "0" > "$STATE/fail_count"
else
    # Only one server — cycle back to port 0 and restart escalation
    echo "0" > "$STATE/fail_count"
    switch_endpoint "$CURRENT_SERVER" "0"
fi
