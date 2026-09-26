// iperf_tcp_server — simple TCP throughput sink paired with iperf_tcp_client.
//
// Accepts one TCP connection (via the host's accept_tcp listener), drains data
// until EOF or a 6-second timeout, then reports the receive throughput.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/c/iperf_tcp_server

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

int main(void) {
    printf("[*] iperf_tcp_server started. Waiting for connection...\n");

    int sock = accept_tcp();
    if (sock < 0) {
        printf("[-] Error: Failed to accept TCP connection.\n");
        return 1;
    }
    printf("[+] Accepted connection (socket %d).\n", sock);

    unsigned char buf[4096];
    long long bytes_received = 0;

    long long start = get_timestamp();
    long long end = start + 6000000000LL; // max 6 seconds listen

    printf("[*] Receiving data...\n");
    while (get_timestamp() < end) {
        int n = receive_tcp_data(sock, buf, sizeof(buf));
        if (n <= 0) {
            break; // EOF or error
        }
        bytes_received += n;
    }

    long long duration_ns = get_timestamp() - start;
    close_tcp(sock);

    double duration_s = (double)duration_ns / 1000000000.0;
    double mbps = (bytes_received * 8.0) / (duration_s * 1000000.0);

    printf("[+] Received %lld bytes in %.2f s (%.2f Mbps)\n", bytes_received, duration_s, mbps);
    return 0;
}
