/* Mode «Облако» of pcarelay without a phone: cc -I Tunnel -o /tmp/rc Tests/RelayCheck/main.c Tunnel/pcarelay.c && /tmp/rc */
#include "pcarelay.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int wgobf_main(int c, char **v) { return 0; }
static void out(const unsigned char *p, int n) { unsigned char r[64]; memcpy(r, p, n); r[0] = 'R'; pcarelay_ws_in(r, n); }
int main(void) {
    pcarelay_start(13299, "127.0.0.1", 9, 0);
    pcarelay_use_ws(out);
    usleep(200000);
    assert(pcarelay_is_ws() && !pcarelay_is_tcp());
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(13299), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct timeval tv = {2, 0}; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    sendto(s, "ping", 4, 0, (struct sockaddr *)&a, sizeof a);
    char b[16] = {0}; int n = recv(s, b, sizeof b, 0);
    assert(n == 4 && !memcmp(b, "Ring", 4) && pcarelay_rx_bytes() == 4);
    puts("pcarelay ws: ok");
}
