#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE[0]}")/lib-core.sh"

check_root
load_env
ensure_dirs

# server.env stores OBFUSCATOR_PORTS (plural, comma list). Client obfuscator
# must target an ACTUAL listening port. lib-core load_env defaults OBFUSCATOR_PORT
# to 51821 (NOT listened on) -> handshake failed. Override unconditionally from
# the real port list when present.
[ -n "${OBFUSCATOR_PORTS:-}" ] && export OBFUSCATOR_PORT="$(echo "$OBFUSCATOR_PORTS" | cut -d',' -f1)"

CMD="${1:-help}"
CLIENT_ARG="${2:-}"
EXTRA_ARG="${3:-}"

resolve_client() {
  local name="$1"
  local id=$(echo "$name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')
  
  if [[ -d "$CLIENTS_DIR/$id" ]]; then
    echo "$id"
    return 0
  fi
  return 1
}

action_add() {
  local name="$CLIENT_ARG"
  local manual_ip="$EXTRA_ARG"
  
  if [[ -z "$name" ]]; then die "Использование: $0 add <client_name> [ip]"; fi
  
  local id=$(echo "$name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')
  local dir="$CLIENTS_DIR/$id"
  
  if [[ -d "$dir" ]]; then die "Клиент $id уже существует."; fi

  if [[ -z "$SERVER_WG_PUBLIC_KEY" ]]; then
    die "Публичный ключ сервера не найден в server.env. Запустите установку."
  fi

  local server_pub="$SERVER_WG_PUBLIC_KEY"
  local server_ip_v4="${SERVER_PUBLIC_IP_V4:-}"
  local server_ip_v6="${SERVER_PUBLIC_IP_V6:-}"
  local server_wg_network="${SERVER_WG_IPV4_NETWORK:-10.25.0.0/16}"
  
  local client_ip_v4="$manual_ip"
  local ipv6_prefix_main=$(echo "${SERVER_WG_IPV6_NETWORK:-fd00:10:25::/48}" | cut -d'/' -f1 | sed 's/::.*//')

  if [[ -z "$client_ip_v4" ]]; then
    log_info "Поиск свободного IP..."
    local used_ips=""
    for d in "$CLIENTS_DIR"/*; do
      if [[ -d "$d" ]] && [[ -f "$d/metadata.json" ]]; then
        local ip=$(jq -r '.tunnel_ip_v4 // empty' "$d/metadata.json" 2>/dev/null | cut -d/ -f1)
        [[ -n "$ip" ]] && used_ips="${used_ips}${ip}\n"
      fi
    done

    client_ip_v4="$(USED_IPS="$(printf "%b" "$used_ips")" python3 - "$server_wg_network" <<'PY'
import ipaddress
import os
import sys

net = ipaddress.ip_network(sys.argv[1], strict=False)
used = {line.strip() for line in os.environ.get("USED_IPS", "").splitlines() if line.strip()}
hosts = net.hosts()
reserved_first = True
for candidate in hosts:
    ip = str(candidate)
    if reserved_first:
        reserved_first = False
        continue
    if ip not in used:
        print(ip)
        raise SystemExit(0)
raise SystemExit(1)
PY
)" || die "Нет свободных IP в подсети."
  fi
  
  local oct3=$(echo "$client_ip_v4" | cut -d. -f3)
  local oct4=$(echo "$client_ip_v4" | cut -d. -f4)
  local hex_part=$(printf "%x:%x" "$oct3" "$oct4")
  local client_ip_v6=""
  [[ -n "$server_ip_v6" ]] && client_ip_v6="${ipv6_prefix_main}::${hex_part}"
  
  log_info "Назначен IP: $client_ip_v4 $([[ -n $client_ip_v6 ]] && echo "/ $client_ip_v6")"
  
  mkdir -p "$dir"
  umask 077
  wg genkey > "$dir/client_private.key"
  wg pubkey < "$dir/client_private.key" > "$dir/client_public.key"
  local priv_key=$(cat "$dir/client_private.key")
  local pub_key=$(cat "$dir/client_public.key")
  
  local allowed_ips="0.0.0.0/0"
  local addr_str="$client_ip_v4/32"
  if [[ -n "$client_ip_v6" ]]; then
    allowed_ips="0.0.0.0/0, ::/0"
    addr_str="$client_ip_v4/32, $client_ip_v6/128"
  fi
  
  cat > "$dir/${id}.conf" <<EOF
[Interface]
PrivateKey = $priv_key
Address = $addr_str
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $server_pub
Endpoint = 127.0.0.1:${CLIENT_WG_PORT:-13255}
AllowedIPs = $allowed_ips
PersistentKeepalive = 25
EOF
  chmod 600 "$dir/${id}.conf"
  
  cat > "$dir/wg-obfuscator.conf" <<EOF
[instance]
source-if = 127.0.0.1
source-lport = ${CLIENT_WG_PORT:-13255}
target = ${CLIENT_ENDPOINT:-$SERVER_PUBLIC_IP_V4}:${OBFUSCATOR_PORT:-51821}
key = ${OBFUSCATOR_KEY:-KEY}
masking = ${OBFUSCATOR_MASKING:-AUTO}
verbose = INFO
idle-timeout = ${OBFUSCATOR_IDLE:-300}
max-dummy = ${OBFUSCATOR_DUMMY:-4}
EOF
  chmod 600 "$dir/wg-obfuscator.conf"
  
  cat > "$dir/metadata.json" <<EOF
{
  "client_id": "$id",
  "client_name": "$name",
  "tunnel_ip_v4": "$client_ip_v4",
  "tunnel_ip_v6": "$client_ip_v6",
  "public_key": "$pub_key",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "obfuscator_key": "${OBFUSCATOR_KEY:-}",
  "obfuscator_dummy": "${OBFUSCATOR_DUMMY:-4}",
  "obfuscator_idle": "${OBFUSCATOR_IDLE:-300}",
  "server_ip_v4": "$SERVER_PUBLIC_IP_V4",
  "server_port": "${OBFUSCATOR_PORT:-}"
}
EOF
  chmod 600 "$dir/metadata.json"
  
  local peer_ips="$client_ip_v4/32"
  [[ -n "$client_ip_v6" ]] && peer_ips="$peer_ips, $client_ip_v6/128"
  
  cat >> "$WG_CONFIG" <<EOF

[Peer]
PublicKey = $pub_key
AllowedIPs = $peer_ips
EOF
  
  wg syncconf wg0 <(wg-quick strip wg0 2>/dev/null) 2>/dev/null
  log_success "Клиент $name создан."

  CLIENT_ARG="$id"
  action_package
  action_link
}

action_remove() {
  local id=$(resolve_client "$CLIENT_ARG")
  if [[ -z "$id" ]]; then die "Клиент не найден."; fi
  local dir="$CLIENTS_DIR/$id"
  
  log_info "Удаление клиента $id..."
  
  if [[ -f "$dir/client_public.key" ]]; then
    local pub=$(cat "$dir/client_public.key")
    if grep -qF "$pub" "$WG_CONFIG"; then
       awk -v key="$pub" '
         BEGIN {RS=""; ORS="\n\n"}
         index($0, key) == 0 {print $0}
       ' "$WG_CONFIG" > "$WG_CONFIG.tmp" && mv "$WG_CONFIG.tmp" "$WG_CONFIG"

       sed -i '/^$/N;/^\n$/D' "$WG_CONFIG"
       
       wg syncconf wg0 <(wg-quick strip wg0 2>/dev/null) 2>/dev/null
       log_success "Peer удален из конфигурации."
    fi
  fi
  
  rm -rf "$dir"
  rm -f "$PACKAGES_DIR/phobos-$id.tar.gz"

  if [[ -f "$TOKENS_FILE" ]] && command -v jq >/dev/null; then
    local tokens=$(jq -r ".[] | select(.client == \"$id\") | .token" "$TOKENS_FILE")
    for t in $tokens; do
       rm -f "$WWW_DIR/init/$t.sh"
       rm -rf "$WWW_DIR/packages/$t"
    done
    jq "map(select(.client != \"$id\"))" "$TOKENS_FILE" > "$TOKENS_FILE.tmp" && mv "$TOKENS_FILE.tmp" "$TOKENS_FILE"
  fi
  
  log_success "Клиент $id полностью удален."
}

action_package() {
  local id=$(resolve_client "$CLIENT_ARG")
  if [[ -z "$id" ]]; then die "Клиент не найден."; fi
  
  log_info "Сборка пакета для $id..."
  local dir="$CLIENTS_DIR/$id"
  local tmp=$(mktemp -d)
  local pkg_root="$tmp/phobos-$id"
  
  mkdir -p "$PHOBOS_DIR/bin"
  mkdir -p "$pkg_root/bin"
  
  cp "$dir/${id}.conf" "$pkg_root/${id}.conf"
  cp "$dir/wg-obfuscator.conf" "$pkg_root/wg-obfuscator.conf"

  # Fetch missing router-arch binaries from ClusterM on-demand
  local _tag; _tag=$(curl -fsSL -m10 https://api.github.com/repos/ClusterM/wg-obfuscator/releases/latest 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
  local _cb="https://github.com/ClusterM/wg-obfuscator/releases/download/${_tag}"
  declare -A _am=([aarch64]="linux-arm64" [mipsel]="linux-mipsel-mips32" [mips]="linux-mips-mips32" [armv7]="linux-armv7-hf" [x86_64]="linux-x64")
  for _arch in aarch64 mipsel mips armv7 x86_64; do
    if [[ ! -f "$PHOBOS_DIR/bin/wg-obfuscator-$_arch" ]] && [[ -n "$_tag" ]]; then
      local _t; _t=$(mktemp -d)
      if curl -fsSL -m30 "${_cb}/wg-obfuscator-${_tag}-${_am[$_arch]}.tar.gz" -o "$_t/o.tgz" 2>/dev/null; then
        tar -xzf "$_t/o.tgz" -C "$_t" 2>/dev/null || true
        local _b; _b=$(find "$_t" -name "wg-obfuscator" -type f | head -1)
        [[ -n "$_b" ]] && cp "$_b" "$PHOBOS_DIR/bin/wg-obfuscator-$_arch" && chmod +x "$PHOBOS_DIR/bin/wg-obfuscator-$_arch" && log_info "+wg-obfuscator-$_arch (ClusterM ${_tag})"
      fi
      rm -rf "$_t"
    fi
    [[ -f "$PHOBOS_DIR/bin/wg-obfuscator-$_arch" ]] && cp "$PHOBOS_DIR/bin/wg-obfuscator-$_arch" "$pkg_root/bin/"
  done

  local tpl_dir="$REPO_DIR/client/templates"

  if [[ -d "$tpl_dir" ]]; then
     for required in install-router.sh.template lib-client.sh install-obfuscator.sh install-wireguard.sh; do
       [[ -f "$tpl_dir/$required" ]] || die "Обязательный шаблон $required не найден в $tpl_dir. Выполни phobos-update и пересоздай пакет."
     done
     cp "$tpl_dir/install-router.sh.template" "$pkg_root/install-router.sh"
     sed -i "s|{{CLIENT_NAME}}|${id}|g" "$pkg_root/install-router.sh"
     chmod +x "$pkg_root/install-router.sh"
     cp "$tpl_dir/lib-client.sh" "$pkg_root/lib-client.sh"
     cp "$tpl_dir/install-obfuscator.sh" "$pkg_root/install-obfuscator.sh"
     cp "$tpl_dir/install-wireguard.sh" "$pkg_root/install-wireguard.sh"
     chmod +x "$pkg_root/lib-client.sh" "$pkg_root/install-obfuscator.sh" "$pkg_root/install-wireguard.sh"
     for f in router-configure-wireguard router-configure-wireguard-openwrt phobos-uninstall 3xui; do
       [[ -f "$tpl_dir/$f.sh" ]] && cp "$tpl_dir/$f.sh" "$pkg_root/$f.sh" && chmod +x "$pkg_root/$f.sh"
     done
  else
     log_warn "Шаблоны не найдены в $tpl_dir"
  fi

  echo "Phobos Client Package for $id" > "$pkg_root/README.txt"
  echo "Date: $(date)" >> "$pkg_root/README.txt"

  # Health monitor + failover
  if [[ -f "$PHOBOS_DIR/server/phobos-health.sh" ]]; then
    cp "$PHOBOS_DIR/server/phobos-health.sh" "$pkg_root/phobos-health.sh"
    chmod +x "$pkg_root/phobos-health.sh"
  fi
  # Pull agent: panel -> router config sync (NAT-friendly). Token = panel
  # server_api_key (the /api/router-config endpoint accepts it as a fallback).
  for src in "$tpl_dir/phobos-pull.sh" "$PHOBOS_DIR/server/phobos-pull.sh"; do
    if [[ -f "$src" ]]; then cp "$src" "$pkg_root/phobos-pull.sh"; chmod +x "$pkg_root/phobos-pull.sh"; break; fi
  done
  local PULL_TOKEN=""
  command -v jq >/dev/null && PULL_TOKEN=$(jq -r '.server_api_key // empty' /opt/phobos-panel/settings.json 2>/dev/null)
  [[ -n "$PULL_TOKEN" ]] && echo "$PULL_TOKEN" > "$pkg_root/pull_token"
  # Generate failover.conf with current server data
  source "$PHOBOS_DIR/server/server.env"
  local panel_port="${HTTP_PORT:-}"
  if [[ -z "$panel_port" && -f /opt/phobos-panel/.port ]]; then
    panel_port=$(cat /opt/phobos-panel/.port 2>/dev/null || true)
  fi
  panel_port="${panel_port:-8443}"
  local panel_scheme="${PANEL_SCHEME:-}"
  if [[ -z "$panel_scheme" && -f /opt/phobos-panel/.scheme ]]; then
    panel_scheme=$(cat /opt/phobos-panel/.scheme 2>/dev/null || true)
  fi
  case "$panel_scheme" in http|https) ;; *) panel_scheme="http";; esac
  local panel_tunnel_ip=""
  panel_tunnel_ip="$(python3 - "${SERVER_WG_IPV4_ADDRESS:-}" "${SERVER_WG_IPV4_NETWORK:-10.25.0.0/16}" <<'PY'
import ipaddress, sys
iface = (sys.argv[1] or "").strip()
network = (sys.argv[2] or "10.25.0.0/16").strip()
if iface:
    try:
        print(ipaddress.ip_interface(iface).ip)
        raise SystemExit(0)
    except Exception:
        pass
net = ipaddress.ip_network(network, strict=False)
print(next(net.hosts()))
PY
)"
  [[ -n "$panel_tunnel_ip" ]] && echo "$panel_tunnel_ip" > "$pkg_root/panel_tunnel_ip"
  echo "$panel_port" > "$pkg_root/panel_port"
  echo "$panel_scheme" > "$pkg_root/panel_scheme"
  echo "${panel_scheme}://${SERVER_PUBLIC_IP_V4}:${panel_port}" > "$pkg_root/panel_url"
  printf 'http://%s:8444 %s://%s:%s %s://%s:%s\n' \
    "$panel_tunnel_ip" "$panel_scheme" "$panel_tunnel_ip" "$panel_port" \
    "$panel_scheme" "$SERVER_PUBLIC_IP_V4" "$panel_port" > "$pkg_root/panel_urls"
  cat > "$pkg_root/failover.conf" <<FAILEOF
# Phobos Failover Configuration
SERVER_1=${CLIENT_ENDPOINT:-$SERVER_PUBLIC_IP_V4}:${OBFUSCATOR_PORTS:-51821,51822,51823}
KEY_1=${OBFUSCATOR_KEY:-}
FAILEOF
  
  find "$pkg_root" -type f ! -path "*/bin/*" -exec sed -i 's/\r$//' {} \;

  tar -C "$tmp" -czf "$PACKAGES_DIR/phobos-$id.tar.gz" "phobos-$id"
  rm -rf "$tmp"
  
  log_success "Пакет создан: $PACKAGES_DIR/phobos-$id.tar.gz"
}

action_check() {
  local id=$(resolve_client "$CLIENT_ARG")
  if [[ -z "$id" ]]; then die "Клиент не найден."; fi

  local dir="$CLIENTS_DIR/$id"
  local changes=()

  if [[ ! -f "$dir/metadata.json" ]]; then
    echo "metadata_missing"
    return 1
  fi

  local client_server_ip=$(jq -r '.server_ip_v4 // ""' "$dir/metadata.json")
  local client_obf_key=$(jq -r '.obfuscator_key // ""' "$dir/metadata.json")
  local client_obf_port=$(jq -r '.server_port // ""' "$dir/metadata.json")
  local client_obf_dummy=$(jq -r '.obfuscator_dummy // "4"' "$dir/metadata.json")
  local client_obf_idle=$(jq -r '.obfuscator_idle // "300"' "$dir/metadata.json")

  local client_wg_pubkey=""
  if [[ -f "$dir/${id}.conf" ]]; then
    client_wg_pubkey=$(grep "^PublicKey" "$dir/${id}.conf" | cut -d'=' -f2- | tr -d ' ')
  fi

  [[ "$client_server_ip" != "$SERVER_PUBLIC_IP_V4" ]] && changes+=("IP сервера: $client_server_ip -> $SERVER_PUBLIC_IP_V4")
  [[ "$client_obf_key" != "$OBFUSCATOR_KEY" ]] && changes+=("Ключ обфускатора: изменен")
  [[ "$client_obf_port" != "$OBFUSCATOR_PORT" ]] && changes+=("Порт обфускатора: $client_obf_port -> $OBFUSCATOR_PORT")
  [[ "$client_obf_dummy" != "$OBFUSCATOR_DUMMY" ]] && changes+=("Max dummy: изменен")
  [[ "$client_obf_idle" != "$OBFUSCATOR_IDLE" ]] && changes+=("Idle таймаут: изменен")
  [[ -n "$client_wg_pubkey" && "$client_wg_pubkey" != "$SERVER_WG_PUBLIC_KEY" ]] && changes+=("Публичный ключ WG: изменен")

  if [[ ${#changes[@]} -gt 0 ]]; then
    echo "ИЗМЕНЕНИЯ КОНФИГУРАЦИИ:"
    for c in "${changes[@]}"; do
      echo "  - $c"
    done
    return 1
  fi

  return 0
}

action_link() {
  local id=$(resolve_client "$CLIENT_ARG")
  if [[ -z "$id" ]]; then die "Клиент не найден."; fi
  local ttl="${EXTRA_ARG:-$TOKEN_TTL}"

  if ! command -v jq >/dev/null; then die "jq не установлен. Установите: apt-get install jq"; fi

  local token=$(head -c 16 /dev/urandom | md5sum | cut -d' ' -f1)
  local exp=$(($(date +%s) + ttl))

  if [[ ! -f "$TOKENS_FILE" ]]; then
    echo "[]" > "$TOKENS_FILE"
  fi

  local clean_json=$(jq "map(select(.client != \"$id\"))" "$TOKENS_FILE")
  echo "$clean_json" | jq ". + [{\"client\": \"$id\", \"token\": \"$token\", \"expires\": $exp}]" > "$TOKENS_FILE.tmp" && mv "$TOKENS_FILE.tmp" "$TOKENS_FILE"

  local link_dir="$WWW_DIR/packages/$token"
  rm -rf "$link_dir"
  mkdir -p "$link_dir"
  ln -s "$PACKAGES_DIR/phobos-$id.tar.gz" "$link_dir/phobos-$id.tar.gz"

  mkdir -p "$WWW_DIR/init"
  local panel_port="${HTTP_PORT:-}"
  if [[ -z "$panel_port" && -f /opt/phobos-panel/.port ]]; then
    panel_port=$(cat /opt/phobos-panel/.port 2>/dev/null || true)
  fi
  panel_port="${panel_port:-8443}"
  local panel_scheme="${PANEL_SCHEME:-}"
  if [[ -z "$panel_scheme" && -f /opt/phobos-panel/.scheme ]]; then
    panel_scheme=$(cat /opt/phobos-panel/.scheme 2>/dev/null || true)
  fi
  case "$panel_scheme" in http|https) ;; *) panel_scheme="http";; esac
  local primary_url="${panel_scheme}://${SERVER_PUBLIC_IP_V4}:${panel_port}/packages/$token/phobos-$id.tar.gz"
  local fallback_url="http://${SERVER_PUBLIC_IP_V4}:80/packages/$token/phobos-$id.tar.gz"

  cat > "$WWW_DIR/init/$token.sh" <<EOF
#!/bin/sh
urls="$primary_url $fallback_url"
dir="/tmp/phobos_install_\$\$"
mkdir -p "\$dir"
echo "Downloading..."
ok=0
  for url in \$urls; do
  rm -f "\$dir/package.tar.gz"
  if command -v curl >/dev/null; then
    curl -k -L -s -o "\$dir/package.tar.gz" "\$url" 2>/dev/null || continue
  else
    wget --no-check-certificate -q -O "\$dir/package.tar.gz" "\$url" 2>/dev/null || wget -q -O "\$dir/package.tar.gz" "\$url" 2>/dev/null || continue
  fi
  if grep -qi '<html' "\$dir/package.tar.gz" 2>/dev/null; then
    echo "Bad response from \$url (HTML/proxy page), trying next..."
    continue
  fi
  tar tzf "\$dir/package.tar.gz" >/dev/null 2>&1 || {
    echo "Bad package from \$url, trying next..."
    continue
  }
  ok=1
  break
done
[ "\$ok" = "1" ] || { echo "Download failed: no valid package"; exit 1; }
cd "\$dir"
tar xzf package.tar.gz
cd "phobos-$id"
chmod +x install-router.sh
./install-router.sh
EOF

  # nginx (www-data) must read these; the builder runs with a strict root umask
  # (files 600 / dirs 700) which makes the install URL return 403. Fix perms.
  chmod 755 "$WWW_DIR" "$WWW_DIR/init" "$WWW_DIR/packages" "$link_dir" 2>/dev/null
  chmod 644 "$WWW_DIR/init/$token.sh" 2>/dev/null
  chmod 755 "$PACKAGES_DIR" 2>/dev/null
  chmod 644 "$PACKAGES_DIR/phobos-$id.tar.gz" 2>/dev/null

  local init_primary="${panel_scheme}://${SERVER_PUBLIC_IP_V4}:${panel_port}/init/$token.sh"
  local init_fallback="http://${SERVER_PUBLIC_IP_V4}:80/init/$token.sh"
  local cmd="p=/tmp/phobos-init-\$\$.sh; ok=0; for u in $init_primary $init_fallback; do rm -f \$p; (wget -q -O \$p \$u || wget --no-check-certificate -q -O \$p \$u || curl -kfsSL -o \$p \$u || curl -fsSL -o \$p \$u) 2>/dev/null || continue; head -c 2 \$p | grep -q \"#!\" || continue; sh \$p && ok=1 && break; done; rm -f \$p; [ \$ok -eq 1 ] || echo ERROR_install_script_download_failed"

  echo ""
  echo "=================================================="
  echo "КОМАНДА ДЛЯ УСТАНОВКИ (Действительна $(($ttl / 3600))ч)"
  echo "=================================================="
  echo "$cmd"
  echo "=================================================="
  echo ""
}

action_list() {
  printf "% -20s % -20s % -20s\n" "CLIENT ID" "IPv4" "CREATED"
  echo "------------------------------------------------------------"
  for d in "$CLIENTS_DIR"/*; do
    if [[ -d "$d" ]]; then
       local id=$(basename "$d")
       local ip="N/A"
       local date="N/A"
       if [[ -f "$d/metadata.json" ]]; then
         ip=$(jq -r '.tunnel_ip_v4 // "N/A"' "$d/metadata.json")
         date=$(jq -r '.created_at // "N/A"' "$d/metadata.json" | cut -d'T' -f1)
       fi
       printf "% -20s % -20s % -20s\n" "$id" "$ip" "$date"
    fi
  done
}

case "$CMD" in
  add) action_add ;;
  remove) action_remove ;;
  package) action_package ;;
  link) action_link ;;
  check) action_check ;;
  list) action_list ;;
  rebuild)
     action_remove
     action_add
     ;;
  *)
    echo "Usage: $0 {add|remove|list|package|link|check|rebuild}"
    exit 1
    ;;
esac
