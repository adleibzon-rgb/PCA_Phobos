/*
 * udptcp — PCA Phobos fallback transport: UDP datagrams carried over TCP.
 * Frames on the TCP stream: 2-byte big-endian length + payload.
 *
 *   server:  udptcp -s <listen_ip:port> <udp_target_ip:port>
 *            each TCP connection gets its own UDP socket to the target
 *            (the local wg-obfuscator), so the obfuscator sees one client per conn.
 *   client:  udptcp -c <local_udp_ip:port> <tcp_server_host:port>
 *            local UDP peer (client wg-obfuscator) <-> one TCP connection, reconnects.
 *
 * Plain C, no deps: builds for Linux servers, Android (NDK) and iOS.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAXPKT 65535

static int parse_addr(const char *s, struct sockaddr_storage *ss, socklen_t *len, int socktype) {
    char host[256];
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || (size_t)(colon - s) >= sizeof host) return -1;
    memcpy(host, s, colon - s);
    host[colon - s] = 0;
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (getaddrinfo(host, colon + 1, &hints, &res) != 0) return -1;
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int read_full(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_frame(int fd, const unsigned char *p, size_t n) {
    unsigned char hdr[2] = {(unsigned char)(n >> 8), (unsigned char)(n & 0xff)};
    if (write(fd, hdr, 2) != 2) return -1;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static void tune_tcp(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
}

/* ── server ─────────────────────────────────────────────────────────────── */
static struct sockaddr_storage g_target;
static socklen_t g_target_len;

static void *serve_conn(void *arg) {
    int tcp = (int)(long)arg;
    unsigned char buf[MAXPKT + 2];
    int udp = socket(g_target.ss_family, SOCK_DGRAM, 0);
    if (udp < 0 || connect(udp, (struct sockaddr *)&g_target, g_target_len) < 0) goto out;
    tune_tcp(tcp);
    struct pollfd p[2] = {{tcp, POLLIN, 0}, {udp, POLLIN, 0}};
    for (;;) {
        if (poll(p, 2, 300000) <= 0) break;            /* 5 min idle -> drop */
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            unsigned char h[2];
            if (read_full(tcp, h, 2) < 0) break;
            size_t n = ((size_t)h[0] << 8) | h[1];
            if (n == 0 || read_full(tcp, buf, n) < 0) break;
            send(udp, buf, n, 0);
        }
        if (p[1].revents & POLLIN) {
            ssize_t n = recv(udp, buf, MAXPKT, 0);
            if (n > 0 && write_frame(tcp, buf, (size_t)n) < 0) break;
        }
    }
out:
    if (udp >= 0) close(udp);
    close(tcp);
    return NULL;
}

static int run_server(const char *listen_s, const char *target_s) {
    struct sockaddr_storage la; socklen_t ll;
    if (parse_addr(listen_s, &la, &ll, SOCK_STREAM) || parse_addr(target_s, &g_target, &g_target_len, SOCK_DGRAM)) {
        fprintf(stderr, "bad address\n"); return 2;
    }
    int ls = socket(la.ss_family, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(ls, (struct sockaddr *)&la, ll) < 0 || listen(ls, 128) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "udptcp server %s -> udp %s\n", listen_s, target_s);
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; perror("accept"); sleep(1); continue; }
        pthread_t t;
        if (pthread_create(&t, NULL, serve_conn, (void *)(long)c) == 0) pthread_detach(t);
        else close(c);
    }
}

/* ── client ─────────────────────────────────────────────────────────────── */
static int connect_tcp(const char *server_s) {
    struct sockaddr_storage sa; socklen_t sl;
    if (parse_addr(server_s, &sa, &sl, SOCK_STREAM)) return -1;   /* re-resolve each time */
    int s = socket(sa.ss_family, SOCK_STREAM, 0);
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&sa, sl) < 0) { close(s); return -1; }
    tune_tcp(s);
    return s;
}

static int run_client(const char *local_s, const char *server_s) {
    struct sockaddr_storage la, peer; socklen_t ll, pl = 0;
    if (parse_addr(local_s, &la, &ll, SOCK_DGRAM)) { fprintf(stderr, "bad address\n"); return 2; }
    int us = socket(la.ss_family, SOCK_DGRAM, 0);
    if (bind(us, (struct sockaddr *)&la, ll) < 0) { perror("bind"); return 1; }
    fprintf(stderr, "udptcp client udp %s -> tcp %s\n", local_s, server_s);
    unsigned char buf[MAXPKT + 2];
    int tcp = -1;
    time_t last_try = 0;
    for (;;) {
        struct pollfd p[2] = {{us, POLLIN, 0}, {tcp, POLLIN, 0}};
        poll(p, tcp >= 0 ? 2 : 1, 1000);
        if (p[0].revents & POLLIN) {
            pl = sizeof peer;
            ssize_t n = recvfrom(us, buf, MAXPKT, 0, (struct sockaddr *)&peer, &pl);
            if (n > 0) {
                if (tcp < 0 && time(NULL) != last_try) {
                    last_try = time(NULL);
                    tcp = connect_tcp(server_s);
                    fprintf(stderr, tcp >= 0 ? "connected\n" : "connect failed\n");
                }
                if (tcp >= 0 && write_frame(tcp, buf, (size_t)n) < 0) { close(tcp); tcp = -1; }
            }
        }
        if (tcp >= 0 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            unsigned char h[2];
            if (read_full(tcp, h, 2) < 0) { close(tcp); tcp = -1; continue; }
            size_t n = ((size_t)h[0] << 8) | h[1];
            if (n == 0 || read_full(tcp, buf, n) < 0) { close(tcp); tcp = -1; continue; }
            if (pl) sendto(us, buf, n, 0, (struct sockaddr *)&peer, pl);
        }
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 4 && !strcmp(argv[1], "-s")) return run_server(argv[2], argv[3]);
    if (argc == 4 && !strcmp(argv[1], "-c")) return run_client(argv[2], argv[3]);
    fprintf(stderr, "usage: udptcp -s <listen ip:port> <udp target ip:port>\n"
                    "       udptcp -c <local udp ip:port> <tcp server host:port>\n");
    return 2;
}
