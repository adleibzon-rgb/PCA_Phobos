#!/bin/bash
set -euo pipefail

SERVER_ENV="/opt/Phobos/server/server.env"
WARP_DIR="/opt/Phobos/server/warp"
WGCF_BIN="/usr/local/bin/wgcf"
WARP_IF="warp"
WARP_CONF="/etc/wireguard/${WARP_IF}.conf"
WARP_TABLE="51820"
WARP_RULE_PRIO="11930"
STATE_FILE="${WARP_DIR}/state.env"
FREE_PROFILE="${WARP_DIR}/wgcf-profile.conf"
CUSTOM_PROFILE="${WARP_DIR}/custom-profile.conf"
LICENSE_FILE="${WARP_DIR}/license.key"
RELAY_TAG_PREFIX="PHOBOS_WARP_RELAY"

load_env() {
  if [ -f "$SERVER_ENV" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        ''|\#*) continue ;;
      esac
      k="${line%%=*}"
      v="${line#*=}"
      case "$k" in
        ''|\#*) continue ;;
      esac
      export "$k=$v"
    done < "$SERVER_ENV"
  fi
}

load_state() {
  STATE_MODE=""
  STATE_PROFILE_SOURCE=""
  STATE_RELAY_PORTS=""
  STATE_RELAY_TARGET=""
  STATE_RELAY_TARGET_IP=""
  STATE_CLIENTS=""
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    STATE_MODE="${MODE:-}"
    STATE_PROFILE_SOURCE="${PROFILE_SOURCE:-}"
    STATE_RELAY_PORTS="${RELAY_PORTS:-}"
    STATE_RELAY_TARGET="${RELAY_TARGET:-}"
    STATE_RELAY_TARGET_IP="${RELAY_TARGET_IP:-}"
    STATE_CLIENTS="${CLIENTS:-}"
  fi
}

save_state() {
  mkdir -p "$WARP_DIR"
  cat > "$STATE_FILE" <<EOF
MODE=${1:-}
PROFILE_SOURCE=${2:-}
RELAY_PORTS=${3:-}
RELAY_TARGET=${4:-}
RELAY_TARGET_IP=${5:-}
CLIENTS=${6:-}
EOF
}

server_public_ip() {
  if [ -n "${SERVER_PUBLIC_IP_V4:-}" ]; then
    printf '%s\n' "$SERVER_PUBLIC_IP_V4"
  else
    curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}'
  fi
}

wg_subnet() {
  if [ -n "${SERVER_WG_IPV4_NETWORK:-}" ]; then
    printf '%s\n' "$SERVER_WG_IPV4_NETWORK"
    return
  fi
  if [ -f /etc/wireguard/wg0.conf ]; then
    python3 - <<'PY' /etc/wireguard/wg0.conf
import ipaddress, re, sys
for raw in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"^Address\s*=\s*(.+)$", raw.strip())
    if not m:
        continue
    value = m.group(1).split(",", 1)[0].strip()
    print(ipaddress.ip_interface(value).network)
    break
PY
    return
  fi
  printf '10.25.0.0/16\n'
}

arch_name() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l) echo "armv7" ;;
    *) echo "" ;;
  esac
}

ensure_wgcf() {
  if [ -x "$WGCF_BIN" ]; then
    return
  fi
  local arch version url
  arch="$(arch_name)"
  [ -n "$arch" ] || { echo "unsupported architecture: $(uname -m)"; exit 1; }
  version="2.2.26"
  url="https://github.com/ViRb3/wgcf/releases/download/v${version}/wgcf_${version}_linux_${arch}"
  curl -fsSL "$url" -o "$WGCF_BIN"
  chmod +x "$WGCF_BIN"
}

ensure_free_profile() {
  local license_key=""
  mkdir -p "$WARP_DIR"
  cd "$WARP_DIR"
  ensure_wgcf
  if [ ! -f "${WARP_DIR}/wgcf-account.toml" ]; then
    "$WGCF_BIN" register --accept-tos >/tmp/phobos-warp-register.log 2>&1
  fi
  if [ -s "$LICENSE_FILE" ]; then
    license_key="$(tr -d '\r\n' < "$LICENSE_FILE")"
    if [ -n "$license_key" ]; then
      "$WGCF_BIN" update --license "$license_key" >/tmp/phobos-warp-license.log 2>&1 || {
        echo "failed to apply WARP+ license key" >&2
        cat /tmp/phobos-warp-license.log >&2 || true
        exit 1
      }
      rm -f "$FREE_PROFILE"
    fi
  fi
  if [ ! -f "$FREE_PROFILE" ] || [ ! -s "$FREE_PROFILE" ]; then
    "$WGCF_BIN" generate >/tmp/phobos-warp-generate.log 2>&1 || {
      echo "failed to generate wgcf profile" >&2
      cat /tmp/phobos-warp-generate.log >&2 || true
      exit 1
    }
  fi
}

ensure_custom_profile() {
  [ -s "$CUSTOM_PROFILE" ] || { echo "custom profile not found: $CUSTOM_PROFILE" >&2; exit 1; }
}

profile_path_for() {
  case "${1:-free}" in
    custom) ensure_custom_profile; printf '%s\n' "$CUSTOM_PROFILE" ;;
    *) ensure_free_profile; printf '%s\n' "$FREE_PROFILE" ;;
  esac
}

profile_endpoint() {
  awk -F'= *' '/^Endpoint *=/{print $2; exit}' "$1" | tr -d ' '
}

resolve_host_ipv4() {
  getent ahostsv4 "$1" | awk 'NR==1{print $1}'
}

build_warp_conf() {
  local profile_path subnet
  profile_path="$1"
  subnet="$(wg_subnet)"
  python3 - "$profile_path" "$WARP_CONF" "$subnet" "$WARP_TABLE" "$WARP_RULE_PRIO" <<'PY'
import sys
from pathlib import Path

profile_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
subnet = sys.argv[3]
table = sys.argv[4]
prio = sys.argv[5]

section = None
data = {"Interface": {}, "Peer": {}}
for raw in profile_path.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("[") and line.endswith("]"):
        section = line.strip("[]")
        continue
    if "=" not in line or section not in data:
        continue
    k, v = [x.strip() for x in line.split("=", 1)]
    data[section][k] = v

iface = data["Interface"]
peer = data["Peer"]

post_up = (
    "sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
    f"ip route replace {subnet} dev wg0 table {table}; "
    f"ip route replace default dev %i table {table}; "
    "iptables -t mangle -C FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || "
    "iptables -t mangle -A FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; "
    "iptables -C FORWARD -i wg0 -o %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -o %i -j ACCEPT; "
    "iptables -C FORWARD -i %i -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || "
    "iptables -I FORWARD 1 -i %i -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; "
    f"iptables -t nat -C POSTROUTING -s {subnet} -o %i -j MASQUERADE 2>/dev/null || "
    f"iptables -t nat -A POSTROUTING -s {subnet} -o %i -j MASQUERADE"
)
post_down = (
    f"ip route del {subnet} dev wg0 table {table} 2>/dev/null || true; "
    f"ip route del default dev %i table {table} 2>/dev/null || true; "
    "iptables -t mangle -D FORWARD -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; "
    "iptables -D FORWARD -i wg0 -o %i -j ACCEPT 2>/dev/null || true; "
    "iptables -D FORWARD -i %i -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; "
    f"iptables -t nat -D POSTROUTING -s {subnet} -o %i -j MASQUERADE 2>/dev/null || true"
)

lines = [
    "[Interface]",
    f"PrivateKey = {iface.get('PrivateKey', '')}",
    f"Address = {iface.get('Address', '')}",
    "MTU = 1280",
    "Table = off",
    f"PostUp = {post_up}",
    f"PostDown = {post_down}",
    "",
    "[Peer]",
    f"PublicKey = {peer.get('PublicKey', '')}",
    f"AllowedIPs = {peer.get('AllowedIPs', '0.0.0.0/0, ::/0')}",
    f"Endpoint = {peer.get('Endpoint', '')}",
    f"PersistentKeepalive = {peer.get('PersistentKeepalive', '25')}",
    "",
]

out_path.write_text("\n".join(lines))
PY
  chmod 600 "$WARP_CONF"
}

clear_egress() {
  systemctl disable --now "wg-quick@${WARP_IF}" >/dev/null 2>&1 || true
  ip route del "$(wg_subnet)" dev wg0 table "$WARP_TABLE" 2>/dev/null || true
  ip route del default dev "$WARP_IF" table "$WARP_TABLE" 2>/dev/null || true
  iptables -t mangle -D FORWARD -o "$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -D FORWARD -i wg0 -o "$WARP_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WARP_IF" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$(wg_subnet)" -o "$WARP_IF" -j MASQUERADE 2>/dev/null || true
}

clear_legacy_subnet_rule() {
  local subnet
  subnet="$(wg_subnet)"
  ip rule del from "$subnet" table "$WARP_TABLE" priority "$WARP_RULE_PRIO" 2>/dev/null || true
  ip rule del from "$subnet" lookup "$WARP_TABLE" 2>/dev/null || true
}

client_rule_prio() {
  python3 - "$1" "$WARP_RULE_PRIO" <<'PY'
import sys
ip = sys.argv[1].split('/')[0].strip()
base = int(sys.argv[2])
parts = [int(x) for x in ip.split('.')]
value = ((parts[2] << 8) + parts[3]) % 5000
print(base + 1 + value)
PY
}

normalize_client_ip() {
  printf '%s\n' "${1%%/*}" | tr -d ' '
}

state_clients_csv_add() {
  local ip csv
  ip="$(normalize_client_ip "$1")"
  csv="${2:-}"
  python3 - "$ip" "$csv" <<'PY'
import sys
ip = sys.argv[1]
items = [x for x in sys.argv[2].split(',') if x]
if ip not in items:
    items.append(ip)
print(",".join(items))
PY
}

state_clients_csv_del() {
  local ip csv
  ip="$(normalize_client_ip "$1")"
  csv="${2:-}"
  python3 - "$ip" "$csv" <<'PY'
import sys
ip = sys.argv[1]
items = [x for x in sys.argv[2].split(',') if x and x != ip]
print(",".join(items))
PY
}

clear_client_rules() {
  load_state
  local ip prio
  IFS=',' read -r -a __clients <<< "${STATE_CLIENTS:-}"
  for ip in "${__clients[@]}"; do
    [ -n "$ip" ] || continue
    prio="$(client_rule_prio "$ip")"
    ip rule del from "${ip}/32" table "$WARP_TABLE" priority "$prio" 2>/dev/null || true
  done
}

reapply_client_rules() {
  local csv="${1:-}" ip prio
  IFS=',' read -r -a __clients <<< "$csv"
  for ip in "${__clients[@]}"; do
    [ -n "$ip" ] || continue
    prio="$(client_rule_prio "$ip")"
    ip rule add from "${ip}/32" table "$WARP_TABLE" priority "$prio" 2>/dev/null || true
  done
}

relay_ports_array() {
  local raw="${1:-4500}"
  raw="${raw// /}"
  IFS=',' read -r -a RELAY_PORTS_ARRAY <<< "$raw"
}

relay_rule_tag() {
  printf '%s:%s:%s:%s\n' "$RELAY_TAG_PREFIX" "$1" "$2" "$3"
}

clear_relay() {
  load_state
  local lines line cmd
  lines="$(iptables-save -t nat 2>/dev/null | grep -F "$RELAY_TAG_PREFIX" || true)"
  if [ -n "$lines" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      case "$line" in
        -A\ *) cmd="iptables -t nat ${line/-A /-D }"; eval "$cmd" >/dev/null 2>&1 || true ;;
      esac
    done <<EOF
$lines
EOF
  fi
  lines="$(iptables-save 2>/dev/null | grep -F "$RELAY_TAG_PREFIX" || true)"
  if [ -n "$lines" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      case "$line" in
        -A\ FORWARD\ *) cmd="iptables ${line/-A /-D }"; eval "$cmd" >/dev/null 2>&1 || true ;;
      esac
    done <<EOF
$lines
EOF
  fi
}

disable_all() {
  clear_legacy_subnet_rule
  clear_client_rules
  clear_egress
  clear_relay
}

relay_enabled() {
  iptables-save 2>/dev/null | grep -q "$RELAY_TAG_PREFIX"
}

warp_handshake_age() {
  local ts
  ts="$(wg show "$WARP_IF" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
  [ -n "$ts" ] && [ "$ts" != "0" ] && echo $(( $(date +%s) - ts )) || echo -1
}

# Cloudflare UDP to engage.cloudflareclient.com:2408 is often cut on the way:
# try the profile endpoint first, then known WARP IP:port pairs, keep the first with a handshake.
pick_warp_endpoint() {
  local pub ep cur i age
  pub="$(wg show "$WARP_IF" peers 2>/dev/null | head -1)"
  [ -n "$pub" ] || return 0
  cur="$(awk -F'= *' '/^Endpoint *=/{print $2; exit}' "$WARP_CONF" | tr -d ' ')"
  for ep in "$cur" 162.159.192.1:2408 162.159.193.1:2408 162.159.192.1:500 162.159.192.1:1701 162.159.192.1:4500 162.159.195.1:2408 188.114.97.1:2408; do
    [ -n "$ep" ] || continue
    wg set "$WARP_IF" peer "$pub" endpoint "$ep" 2>/dev/null || continue
    for i in 1 2 3 4 5 6; do
      ping -c1 -W1 -I "$WARP_IF" 1.1.1.1 >/dev/null 2>&1 || true
      age="$(warp_handshake_age)"
      if [ "$age" -ge 0 ] && [ "$age" -lt 30 ]; then
        [ "$ep" = "$cur" ] || sed -i "s|^Endpoint *=.*|Endpoint = ${ep}|" "$WARP_CONF"
        echo "WARP endpoint: $ep" >&2
        return 0
      fi
    done
  done
  echo "WARP: no handshake on any endpoint (UDP to Cloudflare blocked?)" >&2
}

enable_egress() {
  local profile_source profile_path existing_clients
  load_env
  load_state
  existing_clients="${STATE_CLIENTS:-}"
  profile_source="${1:-free}"
  disable_all
  profile_path="$(profile_path_for "$profile_source")"
  build_warp_conf "$profile_path"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  systemctl enable "wg-quick@${WARP_IF}" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@${WARP_IF}"
  pick_warp_endpoint
  clear_legacy_subnet_rule
  reapply_client_rules "$existing_clients"
  save_state "egress" "$profile_source" "" "" "" "$existing_clients"
  status_json
}

enable_relay() {
  local profile_source ports target profile_path endpoint host port_num target_ip server_ip port tag
  load_env
  profile_source="${1:-free}"
  ports="${2:-4500}"
  target="${3:-}"
  disable_all
  profile_path="$(profile_path_for "$profile_source")"
  endpoint="${target:-$(profile_endpoint "$profile_path")}"
  [ -n "$endpoint" ] || { echo "relay target endpoint is empty" >&2; exit 1; }
  host="${endpoint%:*}"
  port_num="${endpoint##*:}"
  target_ip="$(resolve_host_ipv4 "$host")"
  [ -n "$target_ip" ] || { echo "failed to resolve endpoint host: $host" >&2; exit 1; }
  server_ip="$(server_public_ip)"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  relay_ports_array "$ports"
  for port in "${RELAY_PORTS_ARRAY[@]}"; do
    [ -n "$port" ] || continue
    tag="$(relay_rule_tag "$port" "$target_ip" "$port_num")"
    iptables -t nat -C PREROUTING -d "$server_ip" -p udp --dport "$port" -m comment --comment "$tag" -j DNAT --to-destination "$target_ip:$port_num" 2>/dev/null \
      || iptables -t nat -A PREROUTING -d "$server_ip" -p udp --dport "$port" -m comment --comment "$tag" -j DNAT --to-destination "$target_ip:$port_num"
    iptables -t nat -C POSTROUTING -p udp -d "$target_ip" --dport "$port_num" -m comment --comment "$tag" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -p udp -d "$target_ip" --dport "$port_num" -m comment --comment "$tag" -j MASQUERADE
    iptables -C FORWARD -p udp -d "$target_ip" --dport "$port_num" -m comment --comment "$tag" -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -p udp -d "$target_ip" --dport "$port_num" -m comment --comment "$tag" -j ACCEPT
    iptables -C FORWARD -p udp -s "$target_ip" --sport "$port_num" -m comment --comment "$tag" -j ACCEPT 2>/dev/null \
      || iptables -A FORWARD -p udp -s "$target_ip" --sport "$port_num" -m comment --comment "$tag" -j ACCEPT
  done
  save_state "relay" "$profile_source" "$ports" "$endpoint" "$target_ip" ""
  status_json
}

client_enable() {
  local ip prio updated
  ip="$(normalize_client_ip "${1:-}")"
  [ -n "$ip" ] || { echo "client ip required" >&2; exit 1; }
  load_state
  [ "${STATE_MODE:-}" = "egress" ] || { echo "WARP egress mode is not active" >&2; exit 1; }
  systemctl is-active --quiet "wg-quick@${WARP_IF}" || { echo "WARP interface is not active" >&2; exit 1; }
  prio="$(client_rule_prio "$ip")"
  ip rule add from "${ip}/32" table "$WARP_TABLE" priority "$prio" 2>/dev/null || true
  updated="$(state_clients_csv_add "$ip" "${STATE_CLIENTS:-}")"
  save_state "${STATE_MODE:-egress}" "${STATE_PROFILE_SOURCE:-free}" "${STATE_RELAY_PORTS:-}" "${STATE_RELAY_TARGET:-}" "${STATE_RELAY_TARGET_IP:-}" "$updated"
  status_json
}

client_disable() {
  local ip prio updated
  ip="$(normalize_client_ip "${1:-}")"
  [ -n "$ip" ] || { echo "client ip required" >&2; exit 1; }
  load_state
  prio="$(client_rule_prio "$ip")"
  ip rule del from "${ip}/32" table "$WARP_TABLE" priority "$prio" 2>/dev/null || true
  updated="$(state_clients_csv_del "$ip" "${STATE_CLIENTS:-}")"
  save_state "${STATE_MODE:-}" "${STATE_PROFILE_SOURCE:-}" "${STATE_RELAY_PORTS:-}" "${STATE_RELAY_TARGET:-}" "${STATE_RELAY_TARGET_IP:-}" "$updated"
  status_json
}

status_json() {
  load_env
  load_state
  local subnet service configured endpoint pubkey egress enabled mode profile_source relay_on handshake=-1
  subnet="$(wg_subnet)"
  service="$(systemctl is-active "wg-quick@${WARP_IF}" 2>/dev/null || true)"
  mode="${STATE_MODE:-}"
  profile_source="${STATE_PROFILE_SOURCE:-}"
  configured=false
  endpoint=""
  pubkey=""
  egress=""
  relay_on=false

  if [ "$service" = "active" ]; then
    mode="${mode:-egress}"
    configured=true
    endpoint="$(awk -F'= *' '/^Endpoint *=/{print $2; exit}' "$WARP_CONF" 2>/dev/null || true)"
    pubkey="$(wg show "${WARP_IF}" public-key 2>/dev/null || true)"
    egress="$(curl -4 --interface "${WARP_IF}" -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
    handshake="$(warp_handshake_age)"
    [ -n "$profile_source" ] || profile_source="$( [ -s "$CUSTOM_PROFILE" ] && echo custom || echo free )"
  fi

  if relay_enabled; then
    relay_on=true
    [ -n "$mode" ] || mode="relay"
    configured=true
    [ -n "$endpoint" ] || endpoint="${STATE_RELAY_TARGET:-}"
    [ -n "$profile_source" ] || profile_source="$( [ -s "$CUSTOM_PROFILE" ] && echo custom || echo free )"
  fi

  enabled=false
  if [ "$service" = "active" ] || [ "$relay_on" = true ]; then
    enabled=true
  fi

  python3 - "$enabled" "$configured" "$service" "$subnet" "$endpoint" "$pubkey" "$egress" "$mode" "$profile_source" "${STATE_RELAY_PORTS:-}" "${STATE_RELAY_TARGET:-}" "${STATE_RELAY_TARGET_IP:-}" "$( [ -s "$CUSTOM_PROFILE" ] && echo true || echo false )" "$relay_on" "$( [ -s "$LICENSE_FILE" ] && echo true || echo false )" "${STATE_CLIENTS:-}" "$handshake" <<'PY'
import json, sys
enabled, configured, service, subnet, endpoint, pubkey, egress, mode, profile_source, relay_ports, relay_target, relay_target_ip, custom_saved, relay_on, license_saved, clients_csv, handshake = sys.argv[1:]
if relay_on == "true" and service != "active":
    service = "relay"
print(json.dumps({
    "enabled": enabled == "true",
    "configured": configured == "true",
    "service": service or "inactive",
    "mode": mode or "off",
    "profile_source": profile_source or "free",
    "subnet": subnet,
    "endpoint": endpoint,
    "public_key": pubkey,
    "egress_ipv4": egress,
    "handshake_age": int(handshake),
    "relay_enabled": relay_on == "true",
    "relay_ports": relay_ports,
    "relay_target": relay_target,
    "relay_target_ip": relay_target_ip,
    "clients": [x for x in clients_csv.split(",") if x],
    "custom_profile_saved": custom_saved == "true",
    "license_key_saved": license_saved == "true",
}, ensure_ascii=False))
PY
}

disable_warp() {
  disable_all
  save_state "" "" "" "" "" ""
  status_json
}

case "${1:-status}" in
  enable|up)
    case "${2:-egress}" in
      relay) enable_relay "${3:-free}" "${4:-4500}" "${5:-}" ;;
      *) enable_egress "${3:-free}" ;;
    esac
    ;;
  client-enable) client_enable "${2:-}" ;;
  client-disable) client_disable "${2:-}" ;;
  disable|down) disable_warp ;;
  status|check|--json) status_json ;;
  *)
    echo "usage: $0 {status|enable [egress|relay] [free|custom] [ports] [endpoint]|client-enable <ip>|client-disable <ip>|disable}" >&2
    exit 1
    ;;
esac
