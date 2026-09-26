// ping — ICMPv4 latency probe in C, using the shared Debuglet host API header.
//
// Sends `-iter` ICMP echo requests to `-addr` (one per second) and prints the
// round-trip time of each reply.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/c/ping
//
// Run (args after `--` are passed verbatim to the guest):
//   go run ./cmd/user -wasm examples/debuglets/c/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/debuglet_api.h"

// arg_int returns the integer following `name` in argv, or `fallback` if absent.
static int arg_int(int argc, char **argv, const char *name, int fallback) {
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return atoi(argv[i + 1]);
        }
    }
    return fallback;
}

// checksum computes the standard 16-bit one's-complement ICMP checksum.
static unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "1.1.1.1");
    int iter = arg_int(argc, argv, "-iter", 5);
    int addr_len = (int)strlen(addr);

    for (int seq = 0; seq < iter; seq++) {
        int sock = connect_icmp4(addr, addr_len);
        if (sock < 0) {
            printf("icmp_seq=%d  error: connect_icmp4 failed\n", seq);
            sleep_ns(1000000000LL);
            continue;
        }

        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));
        buf[0] = 8;                                  // type: echo request
        buf[4] = 0; buf[5] = 1;                      // identifier = 1
        buf[6] = (seq >> 8) & 0xFF; buf[7] = seq & 0xFF; // sequence
        unsigned short csum = checksum((unsigned short *)buf, 64);
        buf[2] = csum & 0xFF; buf[3] = (csum >> 8) & 0xFF;

        long long t0 = get_timestamp();
        send_icmp4_data(sock, buf, 64);
        int n = receive_icmp4_data(sock, buf, sizeof(buf));
        double rtt_ms = (double)(get_timestamp() - t0) / 1e6;
        close_icmp4(sock);

        if (n < 20) {
            printf("icmp_seq=%d  error: short reply (%d bytes)\n", seq, n);
        } else {
            printf("icmp_seq=%d  time=%.3fms\n", seq, rtt_ms);
        }
        sleep_ns(1000000000LL); // ~1 s between pings
    }
    return 0;
}
