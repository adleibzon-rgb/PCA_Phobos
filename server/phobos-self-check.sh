#!/usr/bin/env bash
set -euo pipefail

PHOBOS_DIR="${PHOBOS_DIR:-/opt/Phobos}"
SERVER_ENV="${SERVER_ENV:-$PHOBOS_DIR/server/server.env}"
REPO_DIR="${REPO_DIR:-$PHOBOS_DIR/repo}"
WG_IFACE="${WG_IFACE:-wg0}"
FIX=0

for arg in "$@"; do
  [ "$arg" = "--fix" ] && FIX=1
done

log() { echo "[self-check] $*"; }
fail() { echo "[self-check][ERROR] $*" >&2; exit 1; }
warn() { echo "[self-check][WARN] $*" >&2; }

env_get() {
  local key="$1"
  [ -f "$SERVER_ENV" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*) printf '%s\n' "${line#*=}"; return 0 ;;
    esac
  done < "$SERVER_ENV"
}

env_set() {
  local key="$1" value="$2" tmp
  [ -f "$SERVER_ENV" ] || fail "server.env не найден: $SERVER_ENV"
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    $0 ~ "^" k "=" { print k "=" v; done=1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$SERVER_ENV" > "$tmp"
  cat "$tmp" > "$SERVER_ENV"
  rm -f "$tmp"
  chmod 600 "$SERVER_ENV" 2>/dev/null || true
}

normalize_wg_key() {
  python3 - "$1" <<'PY'
import sys
value = (sys.argv[1] or "").strip()
alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
if value and value.lower() != "none" and all(ch in alphabet for ch in value):
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    if len(padded) == 44:
        value = padded
print(value)
PY
}

check_env_key() {
  local key="$1" value normalized
  value="$(env_get "$key" || true)"
  [ -n "$value" ] || fail "$key пустой или отсутствует в server.env"
  normalized="$(normalize_wg_key "$value")"
  if [ "$normalized" != "$value" ]; then
    if [ "$FIX" = 1 ]; then
      env_set "$key" "$normalized"
      log "$key: восстановлен base64 padding"
      value="$normalized"
    else
      fail "$key имеет длину ${#value}, нужен padding. Запусти phobos-self-check --fix"
    fi
  fi
  [ "${#value}" = 44 ] || fail "$key имеет длину ${#value}, ожидается 44"
}

check_public_key_matches_wg() {
  local env_pub wg_pub
  env_pub="$(env_get SERVER_WG_PUBLIC_KEY || true)"
  wg_pub="$(wg show "$WG_IFACE" public-key 2>/dev/null || true)"
  [ -n "$wg_pub" ] || return 0
  if [ "$env_pub" != "$wg_pub" ]; then
    if [ "$FIX" = 1 ]; then
      env_set SERVER_WG_PUBLIC_KEY "$wg_pub"
      log "SERVER_WG_PUBLIC_KEY: обновлен из wg show $WG_IFACE"
    else
      fail "SERVER_WG_PUBLIC_KEY не совпадает с wg show $WG_IFACE"
    fi
  fi
}

check_router_templates() {
  local tpl="$REPO_DIR/client/templates" missing=0 file
  for file in install-router.sh.template lib-client.sh install-obfuscator.sh install-wireguard.sh; do
    if [ ! -s "$tpl/$file" ]; then
      warn "нет обязательного router helper: $tpl/$file"
      missing=1
    fi
  done
  [ "$missing" = 0 ] || fail "router package будет битый. Выполни phobos-update stable|beta|dev"
}

check_scripts_syntax() {
  local script
  for script in \
    "$REPO_DIR/server/scripts/lib-core.sh" \
    "$REPO_DIR/server/scripts/phobos-client.sh" \
    "$REPO_DIR/client/templates/install-router.sh.template" \
    "$REPO_DIR/client/templates/lib-client.sh" \
    "$REPO_DIR/client/templates/install-obfuscator.sh" \
    "$REPO_DIR/client/templates/install-wireguard.sh"; do
    [ -f "$script" ] && bash -n "$script"
  done
}

[ -f "$SERVER_ENV" ] || fail "server.env не найден: $SERVER_ENV"
check_env_key SERVER_WG_PUBLIC_KEY
check_public_key_matches_wg
check_router_templates
check_scripts_syntax
log "OK"
