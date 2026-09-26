// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * fidelity_ping — ICMP latency probe for fidelity benchmarks.
 *
 * Sends NUM_PINGS ICMP echo requests to the target address with INTER_PING_NS
 * nanoseconds between sends.  For every successful reply it prints one line:
 *
 *     RTT_SAMPLE <rtt_ms>
 *
 * followed by a final result line parsed by fidelity_bench.py:
 *
 *     [+] Result: N samples, median=X p95=Y p99=Z std=W ms
 *
 * The target is taken from "-addr <ip>" (default 1.1.1.1).
 *
 * Build:
 *   make wasm SAMPLE_DIR=examples/debuglets/c/fidelity_ping
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "../common/debuglet_api.h"

#define NUM_PINGS       1
#define INTER_PING_NS   1000000LL  /* 1 ms between sends */

/* ---- ICMP checksum ---------------------------------------------------- */
static unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

/* ---- simple sort for percentile calculations -------------------------- */
static void sort(double *a, int n) {
    for (int i = 1; i < n; i++) {
        double key = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j+1] = a[j]; j--; }
        a[j+1] = key;
    }
}

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "1.1.1.1");
    int addr_len = (int)strlen(addr);

    printf("[*] fidelity_ping: %d ICMP pings to %s\n", NUM_PINGS, addr);

    int sock = connect_icmp4(addr, addr_len);
    if (sock < 0) {
        printf("[-] connect_icmp4 failed\n");
        return 1;
    }

    unsigned char buf[64];
    double rtts[NUM_PINGS];
    int ok = 0;

    for (int i = 0; i < NUM_PINGS; i++) {
        /* Build ICMP Echo Request (type 8, code 0). */
        memset(buf, 0, sizeof(buf));
        buf[0] = 8;               /* type: Echo Request */
        buf[4] = 0x04; buf[5] = 0xD2;          /* identifier = 1234 */
        buf[6] = (i >> 8) & 0xFF; buf[7] = i & 0xFF; /* sequence */
        for (int j = 8; j < 64; j++) buf[j] = 'F';
        unsigned short csum = checksum((unsigned short *)buf, 64);
        buf[2] = csum & 0xFF; buf[3] = (csum >> 8) & 0xFF;

        long long t0 = get_timestamp();
        send_icmp4_data(sock, buf, 64);
        int n = receive_icmp4_data(sock, buf, sizeof(buf));
        long long rtt_ns = get_timestamp() - t0;

        if (n <= 0) {
            printf("[-] ping %d: no reply\n", i);
            sleep_ns(INTER_PING_NS);
            continue;
        }

        double rtt_ms = (double)rtt_ns / 1e6;
        printf("RTT_SAMPLE %.6f\n", rtt_ms);
        rtts[ok++] = rtt_ms;

        sleep_ns(INTER_PING_NS);
    }

    close_icmp4(sock);

    if (ok == 0) {
        printf("[-] Error: no replies received\n");
        return 1;
    }

    /* Compute statistics. */
    double sum = 0.0;
    for (int i = 0; i < ok; i++) sum += rtts[i];
    double avg = sum / ok;

    double var = 0.0;
    for (int i = 0; i < ok; i++) { double d = rtts[i] - avg; var += d*d; }
    double std = (ok > 1) ? sqrt(var / (ok - 1)) : 0.0;

    sort(rtts, ok);
    double median = rtts[ok / 2];
    double p95    = rtts[(int)(ok * 0.95)];
    double p99    = rtts[(int)(ok * 0.99)];

    char res[256];
    snprintf(res, sizeof(res),
             "%d samples, median=%.3f p95=%.3f p99=%.3f std=%.3f ms",
             ok, median, p95, p99, std);
    printf("[+] Result: %s\n", res);
    return 0;
}
