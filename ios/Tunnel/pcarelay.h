#ifndef PCARELAY_H
#define PCARELAY_H

/* Start the transport switch thread: obfuscator -> 127.0.0.1:local_port -> host via UDP or TCP. */
int pcarelay_start(int local_port, const char *host, int udp_port, int tcp_port);
void pcarelay_use_tcp(int on);
int pcarelay_is_tcp(void);
/* Bytes received back from the server on any path (auto-detects a dead UDP). */
unsigned long long pcarelay_rx_bytes(void);

/* Mode "Облако": each packet from the obfuscator goes to out() (Swift sends it over WebSocket);
   packets from the WebSocket are handed back with pcarelay_ws_in(). */
typedef void (*pcarelay_ws_out_fn)(const unsigned char *p, int n);
void pcarelay_use_ws(pcarelay_ws_out_fn out);
int pcarelay_is_ws(void);
void pcarelay_ws_in(const unsigned char *p, int n);

/* wg-obfuscator compiled in with -Dmain=wgobf_main (one instance per process). */
int wgobf_main(int argc, char **argv);

#endif
