#!/usr/bin/env bash
# PCA Phobos — panel domain: https://<domain>/ via nginx + Let's Encrypt.
# The panel keeps listening on its old http port, so routers/secondaries that
# already know http://IP:PORT keep working; the domain is an extra entrance.
#   phobos-domain.sh set <domain> [email]   (SELF_SIGNED=1 for LAN tests)
#   phobos-domain.sh remove | status
set -uo pipefail
PANEL_DIR=/opt/phobos-panel
SITE=/etc/nginx/sites-available/phobos-domain
WEBROOT=/var/www/phobos-acme
SS_DIR=/etc/phobos-domain

panel_port() { cat "$PANEL_DIR/.port" 2>/dev/null || echo 8443; }
panel_scheme() { cat "$PANEL_DIR/.scheme" 2>/dev/null || echo http; }

write_site() {  # $1=domain $2=cert $3=key ($2 empty -> http only, for ACME)
    local d="$1" up
    up="$(panel_scheme)://127.0.0.1:$(panel_port)"
    {
        echo "server {"
        echo "    listen 80;"
        echo "    listen [::]:80;"
        echo "    server_name $d;"
        echo "    location /.well-known/acme-challenge/ { root $WEBROOT; }"
        [ -n "$2" ] && echo "    location / { return 301 https://\$host\$request_uri; }"
        echo "}"
        if [ -n "$2" ]; then
            cat <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name $d;
    ssl_certificate $2;
    ssl_certificate_key $3;
    client_max_body_size 64m;
    location / {
        proxy_pass $up;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
EOF
        fi
    } > "$SITE"
    ln -sf "$SITE" /etc/nginx/sites-enabled/phobos-domain
    # nginx < 1.25 has no "http2 on;" -> fall back to the old listen flag
    nginx -t >/dev/null 2>&1 || sed -i -e '/http2 on;/d' -e 's/listen 443 ssl;/listen 443 ssl http2;/' -e 's/listen \[::\]:443 ssl;/listen [::]:443 ssl http2;/' "$SITE"
    nginx -t >/dev/null 2>&1 || { nginx -t; return 1; }
    systemctl reload nginx
}

set_domain() {
    local d="${1:-}" email="${2:-}" cert key
    [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$ ]] || { echo "bad domain: $d" >&2; exit 2; }
    command -v nginx >/dev/null || { echo "nginx not installed" >&2; exit 1; }
    mkdir -p "$WEBROOT"
    write_site "$d" "" "" || exit 1
    if [ "${SELF_SIGNED:-0}" = 1 ]; then
        mkdir -p "$SS_DIR"
        openssl req -x509 -nodes -newkey rsa:2048 -days 825 -subj "/CN=$d" \
            -keyout "$SS_DIR/$d.key" -out "$SS_DIR/$d.crt" >/dev/null 2>&1
        cert="$SS_DIR/$d.crt"; key="$SS_DIR/$d.key"
    else
        command -v certbot >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null
        local mail_args=(--register-unsafely-without-email)
        [ -n "$email" ] && mail_args=(-m "$email")
        certbot certonly --webroot -w "$WEBROOT" -d "$d" --agree-tos -n "${mail_args[@]}" \
            --deploy-hook "systemctl reload nginx" || {
            echo "certbot failed: check that $d points to this server and port 80 is open" >&2
            rm -f /etc/nginx/sites-enabled/phobos-domain; systemctl reload nginx; exit 1; }
        cert="/etc/letsencrypt/live/$d/fullchain.pem"; key="/etc/letsencrypt/live/$d/privkey.pem"
    fi
    write_site "$d" "$cert" "$key" || exit 1
    echo "$d" > "$PANEL_DIR/.domain"
    echo "domain: https://$d/ -> panel $(panel_scheme)://127.0.0.1:$(panel_port)"
}

remove() {
    rm -f /etc/nginx/sites-enabled/phobos-domain "$SITE" "$PANEL_DIR/.domain"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    echo "domain: removed (certificate kept in /etc/letsencrypt)"
}

status() {
    local d exp=""
    d=$(cat "$PANEL_DIR/.domain" 2>/dev/null)
    if [ -n "$d" ]; then
        exp=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$d" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    fi
    printf '{"domain": "%s", "cert_expires": "%s"}\n' "$d" "$exp"
}

case "${1:-status}" in
    set)    set_domain "${2:-}" "${3:-}" ;;
    remove) remove ;;
    status) status ;;
    *) echo "usage: $0 set <domain> [email]|remove|status"; exit 2 ;;
esac
