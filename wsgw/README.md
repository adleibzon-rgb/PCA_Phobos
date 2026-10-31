# wsgw — шлюз WebSocket → UDP (транспорт «Облако» / Keenetic-облако)

Телефон без доступа к серверу → облако KeenDNS (HTTPS по SNI) → свой Keenetic → `wsgw` → UDP обфускатора сервера.
Одно бинарное WS-сообщение = один обфусцированный пакет; на каждое WS-соединение — свой UDP-сокет к `-t`.

Роутер (Entware):
```sh
cp bin/wsgw-aarch64 /opt/sbin/wsgw          # mipsel/mips — по uname -m
cp router/S80wsgw /opt/etc/init.d/ && chmod +x /opt/sbin/wsgw /opt/etc/init.d/S80wsgw
printf 'WSGW_LISTEN=192.168.1.1:18090\nWSGW_TARGET=<сервер>:<порт обфускатора>\n' > /opt/etc/wsgw.conf
/opt/etc/init.d/S80wsgw start
ndmc -c 'ip http proxy phobos'; ndmc -c 'ip http proxy phobos upstream http 192.168.1.1 18090'
ndmc -c 'ip http proxy phobos domain ndns'; ndmc -c 'ip http proxy phobos security-level public'
ndmc -c 'ndns book-name <имя> <домен> cloud'; ndmc -c 'ip http ssl acme get phobos.<имя>.<домен>'
ndmc -c 'system configuration save'
```
Требования: `ip http port 80` (иначе ACME не выпустит сертификат), WAN:443 не проброшен на другой хост
(облако шлёт TLS поддоменов на WAN:443). Если `acme get` висит в `get-pending` — перезагрузка роутера и команда ещё раз.

Клиент Android 1.4.4: канал «Облако», адрес `wss://phobos.<имя>.<домен>/` (или `# pca-ws = wss://…` в ссылке).
Сборка: `./build.sh` (Go, статические linux arm64/mipsle/mips/amd64).
