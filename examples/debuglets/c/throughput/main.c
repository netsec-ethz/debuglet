// throughput — TCP throughput sender in C, using the shared Debuglet host API.
//
// Connects to `-addr` and sends fixed-size chunks for `-secs` seconds, then
// reports the achieved throughput in Mbps. Pair it with any TCP sink.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/c/throughput
//
// Run:
//   go run ./cmd/user -wasm examples/debuglets/c/throughput/debuglet.wasm -- -addr 127.0.0.1:5201 -secs 5

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/debuglet_api.h"

static int arg_int(int argc, char **argv, const char *name, int fallback) {
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return atoi(argv[i + 1]);
        }
    }
    return fallback;
}

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "127.0.0.1:5201");
    int secs = arg_int(argc, argv, "-secs", 5);
    int chunk = arg_int(argc, argv, "-chunk", 4096);
    int addr_len = (int)strlen(addr);

    printf("[*] throughput: sending to %s for %ds (chunk=%dB)\n", addr, secs, chunk);

    int sock = connect_tcp(addr, addr_len);
    if (sock < 0) {
        printf("[-] connect failed: %s\n", addr);
        return 1;
    }

    unsigned char *buf = malloc(chunk);
    memset(buf, 'A', chunk);

    long long duration_ns = (long long)secs * 1000000000LL;
    long long end = get_timestamp() + duration_ns;
    long long sent = 0;
    while (get_timestamp() < end) {
        send_tcp_data(sock, buf, chunk);
        sent += chunk;
    }
    close_tcp(sock);
    free(buf);

    double mbps = (double)sent * 8.0 / ((double)secs * 1e6);
    printf("[+] sent %lld bytes in %ds (%.2f Mbps)\n", sent, secs, mbps);
    return 0;
}
