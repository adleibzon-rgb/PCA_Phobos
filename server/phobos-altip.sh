#!/bin/sh
# PCA Phobos — второй/запасной IP сервера (09.33).
# wg-obfuscator и udptcp слушают 0.0.0.0, но отвечают с основного IP, а провайдер
# клиента может резать именно основной. DNAT «второй IP:порт → основной IP:порт»
# заставляет ответ уходить с того адреса, на который пришёл запрос.
#   phobos-altip apply     — правила для всех доп. IPv4 сервера (служба делает это при старте)
#   phobos-altip status    — что настроено
#   phobos-altip enable    — поставить службу phobos-altip
ENV=/opt/Phobos/server/server.env
[ -f "$ENV" ] || ENV=/opt/Phobos/server.env
get() { grep -E "^$1=" "$ENV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'"'"; }
MAIN=$(get SERVER_PUBLIC_IP_V4)
PORTS=$(get OBFUSCATOR_PORTS); [ -n "$PORTS" ] || PORTS=2083,5443,993
TCP=$(get TCP_PORT)
alts() { ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]}' | grep -vxF "$MAIN" | grep -v '^10\.\|^172\.\(1[6-9]\|2[0-9]\|3[01]\)\.\|^192\.168\.'; }
rule() { # $1 proto $2 alt $3 port
    iptables -t nat -C PREROUTING -d "$2" -p "$1" --dport "$3" -j DNAT --to-destination "$MAIN:$3" 2>/dev/null \
      || iptables -t nat -I PREROUTING -d "$2" -p "$1" --dport "$3" -j DNAT --to-destination "$MAIN:$3"
}
case "$1" in
  apply)
    [ -n "$MAIN" ] || { echo "SERVER_PUBLIC_IP_V4 not set"; exit 1; }
    for a in $(alts); do
        for p in $(echo "$PORTS" | tr ',' ' '); do rule udp "$a" "$p"; done
        [ -n "$TCP" ] && rule tcp "$a" "$TCP"
        echo "alt $a -> $MAIN (udp $PORTS${TCP:+, tcp $TCP})"
    done ;;
  status) echo "main: $MAIN"; echo "alt: $(alts | tr '\n' ' ')"; iptables -t nat -S PREROUTING | grep -- "--to-destination $MAIN:" ;;
  enable)
    cat > /etc/systemd/system/phobos-altip.service <<UNIT
[Unit]
Description=PCA Phobos: second IP answers from itself (DNAT)
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh $(readlink -f "$0") apply
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload && systemctl enable --now phobos-altip ;;
  *) echo "usage: $0 apply|status|enable"; exit 1 ;;
esac
