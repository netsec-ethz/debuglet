// latency_tcp_server — echo server paired with latency_tcp.
//
// Accepts one TCP connection (via the host's accept_tcp listener) and echoes
// every packet back until EOF or a 6-second lifetime expires.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/c/latency_tcp_server

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

int main(void) {
    printf("[*] latency_tcp_server started. Waiting for connection...\n");

    int sock = accept_tcp();
    if (sock < 0) {
        printf("[-] Error: Failed to accept TCP connection.\n");
        return 1;
    }
    printf("[+] Accepted connection (socket %d). Echoing data...\n", sock);

    unsigned char buf[64];
    long long duration_ns = 6000000000LL; // 6 seconds lifetime max
    long long start = get_timestamp();
    long long end = start + duration_ns;

    int pings = 0;
    while (get_timestamp() < end) {
        int n = receive_tcp_data(sock, buf, sizeof(buf));
        if (n <= 0) {
            break; // EOF or Error
        }
        send_tcp_data(sock, buf, n);
        pings++;
    }

    close_tcp(sock);

    printf("[+] Echoed %d ping packets.\n", pings);
    return 0;
}
