/*
 * pcarelay — in-process transport switch for the iOS packet tunnel.
 * wg-obfuscator (one instance, iOS forbids fork) sends to 127.0.0.1:<local>;
 * we forward either over UDP to the server's obfuscator port or over TCP to
 * the server's udptcp (frames: 2-byte length + packet). Switch with pcarelay_use_tcp().
 * Mode 2 ("Облако"): packets go to a Swift callback (WebSocket to the user's Keenetic), answers come back via pcarelay_ws_in().
 */
#include "pcarelay.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_int use_tcp = 0;   /* 0 udp, 1 tcp, 2 ws */
static pcarelay_ws_out_fn ws_out;
static int g_local = -1;
static pthread_mutex_t peer_mu = PTHREAD_MUTEX_INITIALIZER;
static struct sockaddr_storage g_peer;
static socklen_t g_pl;
static atomic_ullong rx_bytes = 0;
static char g_host[256], g_udp_port[8], g_tcp_port[8];
static int g_local_port;

static int dial(int socktype, const char *port) {
    struct addrinfo hints = {0}, *res, *r;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (getaddrinfo(g_host, port, &hints, &res) != 0) return -1;
    int s = -1;
    for (r = res; r; r = r->ai_next) {
        s = socket(r->ai_family, r->ai_socktype, 0);
        if (s < 0) continue;
        if (connect(s, r->ai_addr, r->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    if (s >= 0 && socktype == SOCK_STREAM) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    }
    return s;
}

static int read_full(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd, b + got, n - got); if (r <= 0) return -1; got += (size_t)r; }
    return 0;
}

static void *loop(void *arg) {
    (void)arg;
    struct sockaddr_in la = {0};
    la.sin_family = AF_INET;
    la.sin_port = htons((uint16_t)g_local_port);
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int local = socket(AF_INET, SOCK_DGRAM, 0);
    if (local < 0 || bind(local, (struct sockaddr *)&la, sizeof la) < 0) return NULL;
    g_local = local;
    int udp = -1, tcp = -1;
    struct sockaddr_storage peer; socklen_t pl = 0;
    unsigned char buf[65537];
    time_t last_dial = 0;
    for (;;) {
        int mode = atomic_load(&use_tcp), want_tcp = mode == 1;
        if (mode == 2) { if (udp >= 0) { close(udp); udp = -1; } if (tcp >= 0) { close(tcp); tcp = -1; } }
        if (!want_tcp && tcp >= 0) { close(tcp); tcp = -1; }
        if (want_tcp && udp >= 0) { close(udp); udp = -1; }
        if (mode == 0 && udp < 0 && time(NULL) != last_dial) { last_dial = time(NULL); udp = dial(SOCK_DGRAM, g_udp_port); }
        int up = want_tcp ? tcp : udp;
        struct pollfd p[2] = {{local, POLLIN, 0}, {up, POLLIN, 0}};
        poll(p, up >= 0 ? 2 : 1, 1000);
        if (p[0].revents & POLLIN) {
            pl = sizeof peer;
            ssize_t n = recvfrom(local, buf, 65535, 0, (struct sockaddr *)&peer, &pl);
            if (n <= 0) continue;
            pthread_mutex_lock(&peer_mu); g_peer = peer; g_pl = pl; pthread_mutex_unlock(&peer_mu);
            if (mode == 2) {
                if (ws_out) ws_out(buf, (int)n);
            } else if (want_tcp) {
                if (tcp < 0 && time(NULL) != last_dial) { last_dial = time(NULL); tcp = dial(SOCK_STREAM, g_tcp_port); }
                if (tcp >= 0) {
                    unsigned char h[2] = {(unsigned char)(n >> 8), (unsigned char)n};
                    if (send(tcp, h, 2, 0) != 2 || send(tcp, buf, (size_t)n, 0) != n) { close(tcp); tcp = -1; }
                }
            } else if (udp >= 0) {
                send(udp, buf, (size_t)n, 0);
            }
        }
        if (up >= 0 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n;
            if (want_tcp) {
                unsigned char h[2];
                if (read_full(tcp, h, 2) < 0) { close(tcp); tcp = -1; continue; }
                n = (h[0] << 8) | h[1];
                if (n == 0 || read_full(tcp, buf, (size_t)n) < 0) { close(tcp); tcp = -1; continue; }
            } else {
                n = recv(udp, buf, 65535, 0);
                if (n <= 0) { close(udp); udp = -1; continue; }
            }
            atomic_fetch_add(&rx_bytes, (unsigned long long)n);
            if (pl) sendto(local, buf, (size_t)n, 0, (struct sockaddr *)&peer, pl);
        }
    }
}

int pcarelay_start(int local_port, const char *host, int udp_port, int tcp_port) {
    g_local_port = local_port;
    snprintf(g_host, sizeof g_host, "%s", host);
    snprintf(g_udp_port, sizeof g_udp_port, "%d", udp_port);
    snprintf(g_tcp_port, sizeof g_tcp_port, "%d", tcp_port);
    pthread_t t;
    if (pthread_create(&t, NULL, loop, NULL) != 0) return -1;
    pthread_detach(t);
    return 0;
}

void pcarelay_use_tcp(int on) { atomic_store(&use_tcp, on ? 1 : 0); }
int pcarelay_is_tcp(void) { return atomic_load(&use_tcp) == 1; }

void pcarelay_use_ws(pcarelay_ws_out_fn out) { ws_out = out; atomic_store(&use_tcp, 2); }
int pcarelay_is_ws(void) { return atomic_load(&use_tcp) == 2; }

void pcarelay_ws_in(const unsigned char *p, int n) {
    if (g_local < 0 || n <= 0) return;
    atomic_fetch_add(&rx_bytes, (unsigned long long)n);
    pthread_mutex_lock(&peer_mu);
    struct sockaddr_storage peer = g_peer; socklen_t pl = g_pl;
    pthread_mutex_unlock(&peer_mu);
    if (pl) sendto(g_local, p, (size_t)n, 0, (struct sockaddr *)&peer, pl);
}
unsigned long long pcarelay_rx_bytes(void) { return atomic_load(&rx_bytes); }
