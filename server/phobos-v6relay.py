#!/usr/bin/env python3
"""IPv6 -> local IPv4 UDP relay for the obfuscator (it speaks IPv4 only).

Usage: phobos-v6relay.py LISTEN_PORT [TARGET_PORT] [TARGET_HOST]
One upstream socket per IPv6 client, so the obfuscator sees a stable
client address for the whole session. Idle clients are dropped after 300 s.
"""
import selectors
import socket
import sys
import time

IDLE = 300

listen_port = int(sys.argv[1])
target = (sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1",
          int(sys.argv[2]) if len(sys.argv) > 2 else listen_port)

down = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
down.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
down.bind(("::", listen_port))

sel = selectors.DefaultSelector()
sel.register(down, selectors.EVENT_READ, None)
clients = {}   # v6 addr -> [upstream socket, last seen]

while True:
    for key, _ in sel.select(timeout=30):
        if key.data is None:
            data, addr = down.recvfrom(65535)
            c = clients.get(addr)
            if c is None:
                up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up.connect(target)
                sel.register(up, selectors.EVENT_READ, addr)
                c = clients[addr] = [up, 0]
            c[1] = time.monotonic()
            try:
                c[0].send(data)
            except OSError:
                pass
        else:
            addr = key.data
            try:
                down.sendto(key.fileobj.recv(65535), addr)
                clients[addr][1] = time.monotonic()
            except OSError:
                pass
    now = time.monotonic()
    for addr, (up, seen) in list(clients.items()):
        if now - seen > IDLE:
            sel.unregister(up)
            up.close()
            del clients[addr]
