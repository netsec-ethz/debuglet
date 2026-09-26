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
 * fidelity_iperf_client — 30-second TCP throughput sender for fidelity benchmarks.
 *
 * Connects to the target ("-addr <host:port>", default 127.0.0.1:5201) and sends
 * 4 KiB chunks for DURATION_NS nanoseconds.  Prints one result line parsed by
 * fidelity_bench.py:
 *
 *     [+] Result: Sent <bytes> bytes in <s> s (<Mbps> Mbps)
 *
 * Build:
 *   make wasm SAMPLE_DIR=examples/debuglets/c/fidelity_iperf_client
 */

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

#define DURATION_NS  30000000000LL   /* 30 seconds */
#define CHUNK_SIZE   4096

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "127.0.0.1:5201");
    int addr_len = (int)strlen(addr);

    printf("[*] fidelity_iperf_client: connecting to %s...\n", addr);

    int sock = connect_tcp(addr, addr_len);
    if (sock < 0) {
        printf("[-] Error: connect_tcp failed\n");
        return 1;
    }
    printf("[+] Connected (socket %d). Sending for 30 s...\n", sock);

    unsigned char buf[CHUNK_SIZE];
    memset(buf, 'A', sizeof(buf));

    long long start = get_timestamp();
    long long end   = start + DURATION_NS;
    long long bytes_sent = 0;

    while (get_timestamp() < end) {
        send_tcp_data(sock, buf, sizeof(buf));
        bytes_sent += sizeof(buf);
    }

    long long elapsed_ns = get_timestamp() - start;
    close_tcp(sock);

    double duration_s = (double)elapsed_ns / 1e9;
    double mbps = (bytes_sent * 8.0) / (duration_s * 1e6);

    printf("[+] Result: Sent %lld bytes in %.2f s (%.2f Mbps)\n",
           bytes_sent, duration_s, mbps);
    return 0;
}
