#!/usr/bin/env bash
# PCA Phobos — real server internet speed: download/upload actual bytes, print JSON.
# Cloudflare speed endpoints first, Hetzner/OVH files as download fallback.
#   phobos-speedtest.sh [seconds]
set -uo pipefail
T="${1:-8}"
CF="https://speed.cloudflare.com"

down_mbit() {  # $1=url -> Mbit/s
    curl -s -o /dev/null -m "$T" -w '%{speed_download}' "$1" 2>/dev/null | awk '{printf "%.1f", $1*8/1e6}'
}

ping_ms() {
    curl -s -o /dev/null -m 5 -w '%{time_connect}' "$CF/__down?bytes=0" 2>/dev/null | awk '{printf "%.0f", $1*1000}'
}

dl=$(down_mbit "$CF/__down?bytes=500000000")
src="cloudflare"
if [ -z "$dl" ] || awk "BEGIN{exit !($dl < 1)}"; then
    for u in https://speed.hetzner.de/1GB.bin https://proof.ovh.net/files/1Gb.dat; do
        dl=$(down_mbit "$u"); src="$u"
        awk "BEGIN{exit !($dl >= 1)}" && break
    done
fi
ul=$(head -c 200000000 /dev/zero | curl -s -o /dev/null -m "$T" -w '%{speed_upload}' \
     -X POST --data-binary @- "$CF/__up" 2>/dev/null | awk '{printf "%.1f", $1*8/1e6}')
printf '{"download_mbit": %s, "upload_mbit": %s, "ping_ms": %s, "source": "%s", "ts": %s}\n' \
    "${dl:-0}" "${ul:-0}" "$(ping_ms || echo 0)" "$src" "$(date +%s)"
