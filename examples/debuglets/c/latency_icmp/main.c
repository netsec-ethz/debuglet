// latency_icmp — measure average ICMP echo round-trip time.
//
// Sends 10 ICMP echo requests to the target ("-addr <ip>", default 1.1.1.1) and
// prints the average RTT.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/c/latency_icmp

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

// Calculate internet checksum (RFC 1071)
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*)ptr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "1.1.1.1");
    int addr_len = (int)strlen(addr);

    printf("[*] latency_icmp started (target %s).\n", addr);

    int sock = connect_icmp4(addr, addr_len);
    if (sock < 0) {
        printf("[-] Error: Failed to connect ICMP socket.\n");
        return 1;
    }

    unsigned char buf[64];
    int num_pings = 10;
    long long total_rtt = 0;

    printf("[*] Sending %d ICMP pings...\n", num_pings);
    for (int i = 0; i < num_pings; i++) {
        // Build ICMP Echo Request (Type 8)
        memset(buf, 0, sizeof(buf));
        buf[0] = 8; // Type: Echo Request
        buf[1] = 0; // Code: 0
        buf[2] = 0; // Checksum (initially 0)
        buf[3] = 0; // Checksum (initially 0)

        // Identifier = 1234
        buf[4] = 0x04;
        buf[5] = 0xD2;

        // Sequence Number = i
        buf[6] = (i >> 8) & 0xFF;
        buf[7] = i & 0xFF;

        // Fill payload
        for (int j = 8; j < 64; j++) {
            buf[j] = 'P';
        }

        // Calculate and set checksum
        unsigned short csum = calculate_checksum((unsigned short*)buf, 64);
        buf[2] = csum & 0xFF;
        buf[3] = (csum >> 8) & 0xFF;

        long long start = get_timestamp();
        send_icmp4_data(sock, buf, 64);

        int n = receive_icmp4_data(sock, buf, sizeof(buf));
        long long rtt = get_timestamp() - start;

        if (n <= 0) {
            printf("[-] Failed to receive ICMP reply.\n");
            continue;
        }

        double rtt_ms = (double)rtt / 1000000.0;
        printf("  Reply from server: bytes=%d time=%.3f ms\n", n, rtt_ms);
        total_rtt += rtt;

        sleep_ns(500000000LL); // Wait 500ms
    }

    close_icmp4(sock);

    double avg_rtt_ms = (double)total_rtt / (double)num_pings / 1000000.0;
    printf("[+] Average ICMP Latency: %.3f ms\n", avg_rtt_ms);
    return 0;
}
