package com.pca.phobos.vpn;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Transport "Keenetic cloud": local UDP (obfuscator) <-> wss://<keendns-subdomain>/ -> wsgw on the router -> server UDP.
 * One binary WS message = one obfuscated packet. Reconnects on drop; the tunnel itself is not restarted.
 */
final class WsRelay {
    interface Log { void log(String s); }

    private final int lport;
    private final URI uri;
    private final Log log;
    private final SecureRandom rnd = new SecureRandom();
    private volatile boolean stop;
    private volatile SSLSocket ws;
    private volatile OutputStream out;
    private volatile SocketAddress peer;
    private DatagramSocket udp;

    WsRelay(int lport, String url, Log log) {
        this.lport = lport;
        this.uri = URI.create(url.trim());
        this.log = log;
    }

    void start() throws IOException {
        udp = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), lport));
        new Thread(this::upLoop, "ws-up").start();
        new Thread(this::downLoop, "ws-down").start();
    }

    void stop() {
        stop = true;
        closeWs();
        if (udp != null) udp.close();
    }

    private synchronized void closeWs() {
        try { if (ws != null) ws.close(); } catch (IOException ignored) { }
        ws = null;
        out = null;
    }

    private synchronized OutputStream connect() throws IOException {
        if (out != null) return out;
        String host = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 443;
        SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port);
        s.setTcpNoDelay(true);
        s.setKeepAlive(true);
        s.startHandshake();
        byte[] k = new byte[16];
        rnd.nextBytes(k);
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                + "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + android.util.Base64.encodeToString(k, android.util.Base64.NO_WRAP) + "\r\n\r\n";
        OutputStream o = s.getOutputStream();
        o.write(req.getBytes(StandardCharsets.US_ASCII));
        o.flush();
        InputStream in = s.getInputStream();
        StringBuilder head = new StringBuilder();
        while (!head.toString().endsWith("\r\n\r\n")) {
            int c = in.read();
            if (c < 0 || head.length() > 8192) throw new IOException("ws: no handshake");
            head.append((char) c);
        }
        if (!head.toString().startsWith("HTTP/1.1 101")) {
            s.close();
            throw new IOException("ws: " + head.toString().split("\r\n")[0]);
        }
        ws = s;
        out = o;
        log.log("ws: connected " + uri);
        return o;
    }

    /** obfuscator -> server */
    private void upLoop() {
        byte[] buf = new byte[65535];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        while (!stop) {
            try {
                udp.receive(p);
                peer = p.getSocketAddress();
                OutputStream o = connect();
                writeFrame(o, buf, p.getLength());
            } catch (IOException e) {
                if (stop) return;
                log.log("ws up: " + e.getMessage());
                closeWs();
                sleep(1000);
            }
        }
    }

    /** server -> obfuscator */
    private void downLoop() {
        while (!stop) {
            SSLSocket s = ws;
            if (s == null) { sleep(200); continue; }
            try {
                DataInputStream in = new DataInputStream(s.getInputStream());
                while (!stop) {
                    int b0 = in.readUnsignedByte(), b1 = in.readUnsignedByte();
                    long n = b1 & 0x7f;
                    if (n == 126) n = in.readUnsignedShort();
                    else if (n == 127) n = in.readLong();
                    if (n > 65535) throw new IOException("ws: frame too big");
                    byte[] p = new byte[(int) n];
                    in.readFully(p);
                    int op = b0 & 0x0f;
                    if (op == 8) throw new IOException("ws: closed by server");
                    if ((op == 2 || op == 0) && peer != null) udp.send(new DatagramPacket(p, p.length, peer));
                }
            } catch (IOException e) {
                if (stop) return;
                if (s == ws) { log.log("ws down: " + e.getMessage()); closeWs(); }
            }
        }
    }

    /** Client frames are masked (RFC 6455). */
    private synchronized void writeFrame(OutputStream o, byte[] p, int n) throws IOException {
        byte[] f = new byte[n + 14];
        int i = 0;
        f[i++] = (byte) 0x82;
        if (n < 126) f[i++] = (byte) (0x80 | n);
        else { f[i++] = (byte) (0x80 | 126); f[i++] = (byte) (n >> 8); f[i++] = (byte) n; }
        byte[] m = new byte[4];
        rnd.nextBytes(m);
        System.arraycopy(m, 0, f, i, 4);
        i += 4;
        for (int j = 0; j < n; j++) f[i + j] = (byte) (p[j] ^ m[j & 3]);
        o.write(f, 0, i + n);
        o.flush();
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) { }
    }
}
