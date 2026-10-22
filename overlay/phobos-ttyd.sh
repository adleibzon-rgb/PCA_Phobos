#!/bin/sh
# ============================================================
#  PCA Phobos — ttyd web-terminal на роутере Keenetic
#
#    phobos-ttyd.sh <client_id> <token> [server_tunnel_ip]
#
#  Ставит ttyd (web pty), открывает порт на WG-интерфейсе ТОЛЬКО для панели
#  (server tunnel IP), создаёт init-сервис (переживает перезагрузку).
#  Панель проксирует терминал к роутеру через WG-туннель (за NAT, без SSH).
# ============================================================
CID="${1:?usage: phobos-ttyd.sh <client_id> <token> [server_ip]}"
TOKEN="${2:?token required}"
SRV_IP="${3:-$(cat /opt/etc/Phobos/panel_tunnel_ip 2>/dev/null)}"
[ -n "$SRV_IP" ] || SRV_IP="10.25.0.1"
PORT="${TTYD_PORT:-7681}"
SHELL_BIN="$( [ -x /opt/bin/bash ] && echo /opt/bin/bash || echo sh )"

# WG tunnel netdev (best effort: interface holding RFC1918 or explicit panel route)
WGDEV=$(ip route get "$SRV_IP" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -1)
[ -z "$WGDEV" ] && WGDEV=nwg3

opkg update >/dev/null 2>&1
opkg install ttyd >/dev/null 2>&1
opkg install iptables >/dev/null 2>&1
TTYD_BIN="$(command -v ttyd || echo /opt/bin/ttyd)"
[ -x "$TTYD_BIN" ] || { echo "ERROR: ttyd not installed"; exit 1; }

mkdir -p /opt/etc/Phobos
echo "$TOKEN" > /opt/etc/Phobos/ttyd_token
chmod 600 /opt/etc/Phobos/ttyd_token

# init.d service: opens firewall for panel + runs ttyd (base-path + basic auth)
cat > /opt/etc/init.d/S51phobos-ttyd <<EOF
#!/bin/sh
PORT=$PORT
WGDEV=$WGDEV
SRV_IP=$SRV_IP
CID=$CID
TTYD=$TTYD_BIN
SH=$SHELL_BIN
TOKEN=\$(cat /opt/etc/Phobos/ttyd_token 2>/dev/null)
start() {
    # firewall: allow ONLY the panel (server tunnel IP) to reach ttyd over WG
    iptables -D INPUT -i "\$WGDEV" -s "\$SRV_IP" -p tcp --dport "\$PORT" -j ACCEPT 2>/dev/null
    iptables -I INPUT -i "\$WGDEV" -s "\$SRV_IP" -p tcp --dport "\$PORT" -j ACCEPT
    pkill -f "ttyd -p \$PORT" 2>/dev/null; sleep 1
    # busybox has no setsid/nohup; plain background detaches fine on Entware.
    # no -i flag => ttyd binds all interfaces (0.0.0.0).
    "\$TTYD" -p "\$PORT" -b "/ttyd/\$CID" -c "phobos:\$TOKEN" --writable "\$SH" >/tmp/phobos-ttyd.log 2>&1 &
    sleep 1
    echo "ttyd started on \$PORT (base /ttyd/\$CID, panel-only via \$SRV_IP)"
}
stop() {
    pkill -f "ttyd -p \$PORT" 2>/dev/null
    iptables -D INPUT -i "\$WGDEV" -s "\$SRV_IP" -p tcp --dport "\$PORT" -j ACCEPT 2>/dev/null
}
case "\$1" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  *) echo "usage: \$0 {start|stop|restart}" ;;
esac
EOF
chmod +x /opt/etc/init.d/S51phobos-ttyd
/opt/etc/init.d/S51phobos-ttyd restart

echo "OK: ttyd на роутере, base-path /ttyd/$CID, порт $PORT (только для $SRV_IP по $WGDEV)."
