# udptcp — резервный TCP-канал PCA Phobos

UDP-пакеты (уже обфусцированные) внутри TCP: кадр = 2 байта длины + пакет.
- сервер: `udptcp -s 0.0.0.0:443 127.0.0.1:2083` (служба `phobos-tcp`, порт в server.env `TCP_PORT`);
- клиент: `udptcp -c 127.0.0.1:13256 <сервер>:443`, обфускатор клиента шлёт на 127.0.0.1:13256.
Сборка: `gcc -O2 -static -pthread -o bin/udptcp-x86_64 udptcp.c` (+ aarch64-linux-gnu-gcc), Android — NDK (см. android-client/README.md).
