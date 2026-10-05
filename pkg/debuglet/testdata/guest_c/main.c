// Copyright 2026 ETH Zurich
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

// C guest for the foreign-guest compatibility test, built on the C header in
// examples/debuglets/c/common.
//
//   -addr host:port  connect over TCP, read until end of stream with a bounded
//                    buffer and print the byte count.
//   -listen          accept one connection on the job's TCP listener, read until
//                    the peer half-closes (at most 32 KiB), echo it all and exit.
//
// The retained module guest_c.wasm is built from this file with wasi-sdk 25:
//   clang --target=wasm32-wasip1 -Oz -s -Wall -Werror -o guest_c.wasm main.c
// and recorded in guest_c.wasm.json.

#include <stdio.h>
#include <string.h>
#include "../../../../examples/debuglets/c/common/debuglet_api.h"

#define ECHO_LIMIT (32 * 1024)

static int has_flag(int argc, char **argv, const char *name) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int read_until_eof(const char *addr) {
    printf("connecting tcp %s\n", addr);
    int sock = connect_tcp(addr, (int)strlen(addr));
    if (sock < 0) {
        printf("connect tcp rc=%d\n", sock);
        return 1;
    }
    printf("connected\n");
    unsigned char buf[4096];
    long long total = 0;
    for (;;) {
        int n = receive_tcp_data(sock, buf, (int)sizeof(buf));
        if (n <= 0) {
            break;
        }
        total += n;
    }
    close_tcp(sock);
    printf("eof\n");
    printf("total=%lld\n", total);
    return 0;
}

static int echo_once(void) {
    printf("accepting\n");
    int sock = accept_tcp();
    if (sock < 0) {
        printf("accept tcp rc=%d\n", sock);
        return 1;
    }
    // Read until the peer half-closes, into a bounded buffer, then send it all
    // back with the header's helper, which splits it at the transfer bound.
    static unsigned char buf[ECHO_LIMIT];
    int n = 0;
    while (n < (int)sizeof(buf)) {
        int got = receive_tcp_data(sock, buf + n, (int)sizeof(buf) - n);
        if (got <= 0) {
            break;
        }
        n += got;
    }
    debuglet_send_tcp_all(sock, buf, n);
    printf("echoed n=%d\n", n);
    close_tcp(sock);
    printf("closed\n");
    return 0;
}

int main(int argc, char **argv) {
    if (has_flag(argc, argv, "-listen")) {
        return echo_once();
    }
    const char *addr = arg_addr(argc, argv, NULL);
    if (addr == NULL) {
        printf("usage: -addr host:port | -listen\n");
        return 2;
    }
    return read_until_eof(addr);
}
