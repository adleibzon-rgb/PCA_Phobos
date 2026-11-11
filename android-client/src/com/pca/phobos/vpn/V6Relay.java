package com.pca.phobos.vpn;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * 127.0.0.1:lport <-> [ipv6]:port over UDP: our wg-obfuscator is IPv4-only, the server side
 * listens on IPv6 through phobos-v6relay. One upstream socket, like the server's relay.
 */
final class V6Relay {
    private final DatagramSocket local, up;
    private volatile SocketAddress peer;
    private volatile boolean running = true;

    V6Relay(int lport, String host, int port) throws Exception {
        local = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), lport));
        up = new DatagramSocket();
        up.connect(new InetSocketAddress(InetAddress.getByName(host), port));
    }

    void start() {
        new Thread(() -> pump(local, true), "v6relay-out").start();
        new Thread(() -> pump(up, false), "v6relay-in").start();
    }

    private void pump(DatagramSocket from, boolean out) {
        byte[] buf = new byte[65535];
        while (running) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                from.receive(p);
                if (out) { peer = p.getSocketAddress(); up.send(new DatagramPacket(buf, p.getLength())); }
                else if (peer != null) local.send(new DatagramPacket(buf, p.getLength(), peer));
            } catch (Exception e) {
                if (!running) return;
            }
        }
    }

    void stop() {
        running = false;
        local.close();
        up.close();
    }
}
