// iperf_tcp_client — simple TCP throughput sender.
//
// Connects to the target ("-addr <host:port>", default 127.0.0.1:5201) and blasts
// 4 KiB chunks for 5 seconds, then reports the achieved throughput. Pairs with
// iperf_tcp_server.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/c/iperf_tcp_client

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "127.0.0.1:5201");
    int addr_len = (int)strlen(addr);

    printf("[*] iperf_tcp_client started (target %s).\n", addr);

    int sock = connect_tcp(addr, addr_len);
    if (sock < 0) {
        printf("[-] Error: Failed to connect to TCP server.\n");
        return 1;
    }
    printf("[+] Connected to server (socket %d).\n", sock);

    unsigned char buf[4096];
    memset(buf, 'A', sizeof(buf));

    long long duration_ns = 5000000000LL; // 5 seconds
    long long start = get_timestamp();
    long long end = start + duration_ns;

    long long bytes_sent = 0;

    printf("[*] Sending data for 5 seconds...\n");
    while (get_timestamp() < end) {
        send_tcp_data(sock, buf, sizeof(buf));
        bytes_sent += sizeof(buf);
    }

    close_tcp(sock);

    double duration_s = (double)duration_ns / 1000000000.0;
    double mbps = (bytes_sent * 8.0) / (duration_s * 1000000.0);

    printf("[+] Sent %lld bytes in %.2f s (%.2f Mbps)\n", bytes_sent, duration_s, mbps);
    return 0;
}
