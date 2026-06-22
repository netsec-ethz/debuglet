// latency_tcp — measure average TCP echo round-trip time.
//
// Connects to the target ("-addr <host:port>", default 127.0.0.1:5201), sends 10
// 64-byte pings and prints the average RTT. Pairs with latency_tcp_server.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/c/latency_tcp

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "127.0.0.1:5201");
    int addr_len = (int)strlen(addr);

    printf("[*] latency_tcp started (target %s).\n", addr);

    int sock = connect_tcp(addr, addr_len);
    if (sock < 0) {
        printf("[-] Error: Failed to connect to TCP server.\n");
        return 1;
    }

    unsigned char buf[64];
    memset(buf, 'P', sizeof(buf)); // Ping packet

    int num_pings = 10;
    long long total_rtt = 0;

    printf("[*] Sending %d TCP pings...\n", num_pings);
    for (int i = 0; i < num_pings; i++) {
        long long start = get_timestamp();
        send_tcp_data(sock, buf, sizeof(buf));

        int n = receive_tcp_data(sock, buf, sizeof(buf));
        long long rtt = get_timestamp() - start;

        if (n <= 0) {
            printf("[-] Failed to receive pong.\n");
            break;
        }

        double rtt_ms = (double)rtt / 1000000.0;
        printf("  Reply from server: bytes=%d time=%.3f ms\n", n, rtt_ms);
        total_rtt += rtt;

        sleep_ns(500000000LL); // Wait 500ms between pings
    }

    close_tcp(sock);

    double avg_rtt_ms = (double)total_rtt / (double)num_pings / 1000000.0;
    printf("[+] Average TCP Latency: %.3f ms\n", avg_rtt_ms);
    return 0;
}
