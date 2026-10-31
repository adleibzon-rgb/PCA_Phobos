#!/bin/sh
# Static builds for Keenetic (Entware) and Linux servers.
cd "$(dirname "$0")"; mkdir -p bin
for a in arm64:aarch64 mipsle:mipsel mips:mips amd64:x86_64; do
  GOOS=linux GOARCH=${a%%:*} GOMIPS=softfloat CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/wsgw-${a##*:} . || exit 1
done
ls -l bin
