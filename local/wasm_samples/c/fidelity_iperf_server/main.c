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
 * fidelity_iperf_server — TCP sink paired with fidelity_iperf_client.
 *
 * Accepts one connection (via the host's accept_tcp listener), drains data until
 * EOF or a 35 s timeout, then reports bytes received.  The timeout is
 * intentionally longer than the client's 30 s so that the server never stops
 * before the client finishes.
 *
 * Build:
 *   make wasm SAMPLE_DIR=local/wasm_samples/c/fidelity_iperf_server
 */

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

#define TIMEOUT_NS  35000000000LL   /* 35 seconds */
#define CHUNK_SIZE  4096

int main(void) {
    printf("[*] fidelity_iperf_server: waiting for connection...\n");

    int sock = accept_tcp();
    if (sock < 0) {
        printf("[-] Error: accept_tcp failed\n");
        return 1;
    }
    printf("[+] Connection accepted (socket %d).\n", sock);

    unsigned char buf[CHUNK_SIZE];
    long long bytes_received = 0;
    long long start = get_timestamp();
    long long deadline = start + TIMEOUT_NS;

    while (get_timestamp() < deadline) {
        int n = receive_tcp_data(sock, buf, sizeof(buf));
        if (n <= 0) break;  /* EOF — client closed the connection */
        bytes_received += n;
    }

    long long elapsed_ns = get_timestamp() - start;
    close_tcp(sock);

    double duration_s = (double)elapsed_ns / 1e9;
    double mbps = (bytes_received * 8.0) / (duration_s * 1e6);

    printf("[+] Result: Received %lld bytes in %.2f s (%.2f Mbps)\n",
           bytes_received, duration_s, mbps);
    return 0;
}
