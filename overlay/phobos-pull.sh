#!/bin/sh
export PATH=/opt/bin:/opt/sbin:/opt/usr/bin:$PATH  # cron без /opt/bin -> busybox wget висел вечно (09.29)
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
# 02.11.2026: доп. учётки — PHOBOS_ACC=$PHOBOS_DIR/acc/<клиент> (см. phobos-health.sh)
ACC_DIR="${PHOBOS_ACC:-$PHOBOS_DIR}"
CONF="$ACC_DIR/failover.conf"
HEALTH="$PHOBOS_DIR/phobos-health.sh"
LOG="$ACC_DIR/health.log"
# Config sources, tried in order. TUNNEL FIRST: panel_tunnel_ip is the wg0 of
# whatever server the tunnel currently terminates on, so management rides the
# same obfuscated channel as data — survives a public-IP ban and follows
# failover.
#   - panel_tunnel_ip:8444   -> secondary server agent (phobos-api)
#   - panel_tunnel_ip:<panel_port> -> primary server panel
#   - public panel IP  -> bootstrap / if tunnel is down
PANEL_TUNNEL_IP="${PANEL_TUNNEL_IP:-$(cat "$ACC_DIR/panel_tunnel_ip" 2>/dev/null)}"
[ -n "$PANEL_TUNNEL_IP" ] || PANEL_TUNNEL_IP="10.25.0.1"
PANEL="${PANEL:-$(cat "$ACC_DIR/panel_url" 2>/dev/null)}"
PANEL_URLS="${PANEL_URLS:-$(cat "$ACC_DIR/panel_urls" 2>/dev/null)}"
[ -n "$PANEL_URLS" ] || PANEL_URLS="http://${PANEL_TUNNEL_IP}:8444 $PANEL"
# + public URLs the panel announced in failover.conf (second IP etc., 09.33)
_extra=$(grep "^PANEL_URLS_EXTRA=" "$CONF" 2>/dev/null | cut -d= -f2-)
for _u in $_extra; do case " $PANEL_URLS " in *" $_u "*) ;; *) PANEL_URLS="$PANEL_URLS $_u" ;; esac; done
CLIENT_ID=$(cat "$ACC_DIR/client_id" 2>/dev/null || echo "home")
TOKEN=$(cat "$ACC_DIR/pull_token" 2>/dev/null)
TMP="/tmp/failover.conf.pull${PHOBOS_ACC:+-$CLIENT_ID}"
LOCK="/tmp/phobos-pull${PHOBOS_ACC:+-$CLIENT_ID}.lock"

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

# TCP channel for routers (1.5.0): the guard needs /opt/bin/udptcp when failover.conf has TCP_N.
ensure_udptcp() {
    [ -x /opt/bin/udptcp ] && return 0
    grep -q "^TCP_[0-9]*=" "$CONF" 2>/dev/null || return 0
    case "$(uname -m)" in aarch64) a=aarch64 ;; mips*) a=mipsel ;; *) return 0 ;; esac
    command -v curl >/dev/null || return 0
    { curl -fsSL -m 30 -o /opt/bin/udptcp.tmp "https://raw.githubusercontent.com/adleibzon-rgb/PCA_Phobos/main/udptcp/bin/udptcp-$a" 2>/dev/null \
      || curl -fsSL -m 30 -o /opt/bin/udptcp.tmp "https://git.bobyrev.com/PCA/PCA_Phobos/raw/branch/main/udptcp/bin/udptcp-$a" 2>/dev/null; } \
        && [ -s /opt/bin/udptcp.tmp ] && chmod 755 /opt/bin/udptcp.tmp && mv /opt/bin/udptcp.tmp /opt/bin/udptcp \
        && log "PULL: udptcp installed ($a)" || rm -f /opt/bin/udptcp.tmp
}

# One fetch + compare + apply pass. Returns 0 always (best-effort).
do_pull() {
    ensure_udptcp
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

    apply_obf_params
}

# Apply obfuscator params (masking/max-dummy/idle) delivered in failover.conf.
apply_obf_params() {
    M=$(grep "^OBF_MASKING=" "$CONF" 2>/dev/null | cut -d= -f2-)
    [ -z "$M" ] && return 0
    D=$(grep "^OBF_MAX_DUMMY=" "$CONF" 2>/dev/null | cut -d= -f2-)
    I=$(grep "^OBF_IDLE=" "$CONF" 2>/dev/null | cut -d= -f2-)
    changed=0
    # только свой обфускатор: у других учёток свои failover.conf
    own=""
    for l in "$PHOBOS_DIR"/wg-obfuscator*.link; do
        [ "$(cat "$l" 2>/dev/null)" = "$CLIENT_ID" ] && own="${l%.link}.conf"
    done
    [ -z "$own" ] && [ -z "$PHOBOS_ACC" ] && own="$PHOBOS_DIR/wg-obfuscator*.conf"
    for OBF in $own; do
        [ -f "$OBF" ] || continue
        cur=$(grep "^masking = " "$OBF" 2>/dev/null | sed 's/masking = //')
        [ "$cur" != "$M" ] && { sed -i "s/^masking = .*/masking = $M/" "$OBF"; changed=1; }
        if [ -n "$D" ]; then
            cur=$(grep "^max-dummy = " "$OBF" 2>/dev/null | sed 's/max-dummy = //')
            [ "$cur" != "$D" ] && { sed -i "s/^max-dummy = .*/max-dummy = $D/" "$OBF"; changed=1; }
        fi
        if [ -n "$I" ]; then
            cur=$(grep "^idle-timeout = " "$OBF" 2>/dev/null | sed 's/idle-timeout = //')
            [ "$cur" != "$I" ] && { sed -i "s/^idle-timeout = .*/idle-timeout = $I/" "$OBF"; changed=1; }
        fi
    done
    [ "$changed" = 0 ] && return 0
    log "PULL: obf params applied (masking=$M dummy=${D:-} idle=${I:-}), restart obfuscator"
    if ls /opt/etc/init.d/S*obfuscator* >/dev/null 2>&1; then
        for sc in /opt/etc/init.d/S*obfuscator*; do
            for OBF in $own; do grep -q "/$(basename "$OBF")\"\$" "$sc" && [ -x "$sc" ] && "$sc" restart >/dev/null 2>&1; done
        done
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl restart 'wg-obfuscator*' >/dev/null 2>&1 || true
    else
        killall wg-obfuscator 2>/dev/null; sleep 1
        for OBF in "$PHOBOS_DIR"/wg-obfuscator*.conf; do [ -f "$OBF" ] && wg-obfuscator --config "$OBF" >/dev/null 2>&1 & done
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
