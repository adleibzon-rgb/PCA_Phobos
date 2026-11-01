#!/bin/sh
# ============================================================
#  Phobos Config Pull — NAT-friendly management channel.
#  Runs ON the router via cron (every 2 min). OUTBOUND ONLY:
#  fetches this client's failover.conf from the panel over
#  HTTPS/HTTP and applies it. No inbound SSH needed, so it works
#  behind any NAT and regardless of which Phobos server is active.
#
#  Why pull (not panel->router SSH):
#   - routers sit behind NAT with no public IP (KeenDNS is HTTP-
#     only, no port 22),
#   - WG3 must be security-level PUBLIC for LAN client routing,
#     which blocks inbound SSH on the tunnel,
#   - on failover the router's 10.25.0.2 moves to another server's
#     wg0, so a fixed panel host cannot reach it.
#  Pulling sidesteps all three.
#
#  Files (written by installer / bootstrap):
#    /opt/etc/Phobos/client_id    -> this router's client id (e.g. home)
#    /opt/etc/Phobos/pull_token   -> shared secret for the panel endpoint
#    PANEL env or default below    -> panel base URL
# ============================================================
PHOBOS_DIR="/opt/etc/Phobos"
CONF="$PHOBOS_DIR/failover.conf"
HEALTH="$PHOBOS_DIR/phobos-health.sh"
LOG="$PHOBOS_DIR/health.log"
# Config sources, tried in order. TUNNEL FIRST: panel_tunnel_ip is the wg0 of
# whatever server the tunnel currently terminates on, so management rides the
# same obfuscated channel as data — survives a public-IP ban and follows
# failover.
#   - panel_tunnel_ip:8444   -> secondary server agent (phobos-api)
#   - panel_tunnel_ip:<panel_port> -> primary server panel
#   - public panel IP  -> bootstrap / if tunnel is down
PANEL_TUNNEL_IP="${PANEL_TUNNEL_IP:-$(cat "$PHOBOS_DIR/panel_tunnel_ip" 2>/dev/null)}"
[ -n "$PANEL_TUNNEL_IP" ] || PANEL_TUNNEL_IP="10.25.0.1"
PANEL="${PANEL:-$(cat "$PHOBOS_DIR/panel_url" 2>/dev/null)}"
PANEL_URLS="${PANEL_URLS:-$(cat "$PHOBOS_DIR/panel_urls" 2>/dev/null)}"
[ -n "$PANEL_URLS" ] || PANEL_URLS="http://${PANEL_TUNNEL_IP}:8444 $PANEL"
CLIENT_ID=$(cat "$PHOBOS_DIR/client_id" 2>/dev/null || echo "home")
TOKEN=$(cat "$PHOBOS_DIR/pull_token" 2>/dev/null)
TMP="/tmp/failover.conf.pull"
LOCK="/tmp/phobos-pull.lock"

log() { echo "$(date '+%H:%M:%S') $1" >> "$LOG"; }

# single instance
if [ -f "$LOCK" ]; then
    pid=$(cat "$LOCK" 2>/dev/null)
    kill -0 "$pid" 2>/dev/null && exit 0
fi
echo $$ > "$LOCK"
trap 'rm -f "$LOCK"' EXIT

[ -z "$TOKEN" ] && exit 0

detect_tunnel_iface() {
    ip route get "$PANEL_TUNNEL_IP" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1
}

fetch_config() {
    base="$1"
    url="${base}/api/router-config/${CLIENT_ID}?token=${TOKEN}"
    case "$base" in
        "http://${PANEL_TUNNEL_IP}:"*|"https://${PANEL_TUNNEL_IP}:"*)
            iface=$(detect_tunnel_iface)
            if [ -n "$iface" ] && command -v curl >/dev/null; then
                curl -k --interface "$iface" -s -m 8 -o "$TMP" "$url" 2>/dev/null && return 0
            fi
            ;;
    esac
    if command -v curl >/dev/null; then
        curl -k -s -m 8 -o "$TMP" "$url" 2>/dev/null && return 0
    fi
    wget -T 8 --no-check-certificate -q -O "$TMP" "$url" 2>/dev/null || wget -T 8 -q -O "$TMP" "$url" 2>/dev/null
}

# One fetch + compare + apply pass. Returns 0 always (best-effort).
do_pull() {
    # Try each source (tunnel first); accept first that returns a valid conf.
    got=0
    for base in $PANEL_URLS; do
        fetch_config "$base" || continue
        if grep -q "^SERVER_1=" "$TMP" 2>/dev/null; then got=1; break; fi
    done
    [ "$got" = 1 ] || { rm -f "$TMP"; return 0; }

    new=$(md5sum "$TMP" 2>/dev/null | cut -d' ' -f1)
    old=$(md5sum "$CONF" 2>/dev/null | cut -d' ' -f1)
    if [ "$new" = "$old" ]; then
        rm -f "$TMP"
        return 0
    fi

    old_s1=$(grep "^SERVER_1=" "$CONF" 2>/dev/null | cut -d= -f2- | cut -d: -f1)
    new_s1=$(grep "^SERVER_1=" "$TMP"  2>/dev/null | cut -d= -f2- | cut -d: -f1)

    cp "$CONF" "$CONF.prev" 2>/dev/null
    mv "$TMP" "$CONF"
    log "PULL: failover.conf updated (SERVER_1 ${old_s1:-?} -> ${new_s1:-?})"

    # apply the new primary now (only if it actually changed)
    if [ "$old_s1" != "$new_s1" ] && [ -f "$HEALTH" ]; then
        sh "$HEALTH" apply-server 1
    fi
}

# Inner loop: cron fires this every 60s, but we poll ~4x per minute so a
# panel "Set" applies within ~12-15s instead of up to a full minute. The
# loop stays UNDER 60s and exits so the next cron tick takes over cleanly
# (the lockfile blocks any overlap). POLL_INTERVAL/POLL_PASSES overridable.
POLL_INTERVAL="${POLL_INTERVAL:-12}"
POLL_PASSES="${POLL_PASSES:-4}"
i=1
while [ "$i" -le "$POLL_PASSES" ]; do
    do_pull
    [ "$i" -lt "$POLL_PASSES" ] && sleep "$POLL_INTERVAL"
    i=$((i + 1))
done
