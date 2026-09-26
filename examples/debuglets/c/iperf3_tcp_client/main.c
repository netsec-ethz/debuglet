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
 * iperf3_tcp_client — iperf3-compatible TCP sender for fidelity benchmarks.
 *
 * Implements the iperf3 wire protocol (sender role, single stream, TCP) to
 * measure TCP throughput against any standard iperf3 server (public or local).
 *
 * Handshake order (confirmed by tcpdump against iperf3 3.16):
 *
 *   Client → Server  cookie[37]          (client generates & sends first)
 *   Server → Client  PARAM_EXCHANGE (9)
 *   Client → Server  JSON params (4-byte BE len + JSON)
 *   Server → Client  CREATE_STREAMS (10)
 *   Client → Server  cookie[37]          (on a NEW TCP connection = data socket)
 *   Server → Client  TEST_START (1)
 *   [Client sends data blocks for TEST_DURATION_S seconds]
 *   Client → Server  TEST_END (4)
 *   Server → Client  EXCHANGE_RESULTS (13)
 *   Client → Server  results JSON (4-byte BE len + JSON)
 *   Server → Client  results JSON (discarded)
 *   Server → Client  IPERF_DONE (16)
 *
 * The iperf3 server address is taken from "-addr <host:port>"
 * (default 127.0.0.1:5201).
 *
 * Build:
 *   make wasm SAMPLE_DIR=examples/debuglets/c/iperf3_tcp_client
 */

#include <stdio.h>
#include <string.h>
#include "../common/debuglet_api.h"

/* ---- iperf3 state constants -------------------------------------------- */
#define IPERF_START       1
#define TEST_RUNNING      2
#define TEST_END          4
#define PARAM_EXCHANGE    9
#define CREATE_STREAMS   10
#define EXCHANGE_RESULTS 13
#define IPERF_DONE       16
#define ACCESS_DENIED   (-1)
#define SERVER_ERROR    (-2)

#define COOKIE_SIZE      37       /* 36 random alphanum chars + NUL */
#define TEST_DURATION_S  10   /* 10 s for loopback (rebuild to 5 s for public tests) */
#define BLOCK_SIZE       131072   /* 128 KiB — iperf3 default for TCP */

/* ---- big-endian helpers ------------------------------------------------- */
static void be32_put(unsigned char *b, unsigned int v) {
    b[0] = (v >> 24) & 0xFF;
    b[1] = (v >> 16) & 0xFF;
    b[2] = (v >>  8) & 0xFF;
    b[3] =  v        & 0xFF;
}

static unsigned int be32_get(const unsigned char *b) {
    return ((unsigned int)b[0] << 24) |
           ((unsigned int)b[1] << 16) |
           ((unsigned int)b[2] <<  8) |
            (unsigned int)b[3];
}

/* ---- exact-count TCP recv ----------------------------------------------- */
static int recv_n(int sock, void *buf, int n) {
    unsigned char *p = (unsigned char *)buf;
    int total = 0;
    while (total < n) {
        int r = receive_tcp_data(sock, p + total, n - total);
        if (r <= 0) return (total > 0) ? total : r;
        total += r;
    }
    return total;
}

/* ---- iperf3 control-channel helpers ------------------------------------- */
static int recv_state(int sock) {
    signed char st = 0;
    if (recv_n(sock, &st, 1) != 1) return -99;
    return (int)st;
}

static void send_state(int sock, signed char st) {
    send_tcp_data(sock, (void *)&st, 1);
}

static void send_json(int sock, const char *json) {
    unsigned int len = (unsigned int)strlen(json);
    unsigned char hdr[4];
    be32_put(hdr, len);
    send_tcp_data(sock, hdr, 4);
    send_tcp_data(sock, (void *)json, (int)len);
}

static int recv_json(int sock, char *buf, int bufsz) {
    unsigned char hdr[4];
    if (recv_n(sock, hdr, 4) != 4) return -1;
    unsigned int len = be32_get(hdr);
    if ((int)len >= bufsz) {
        /* drain the unread bytes so the stream stays in sync */
        char tmp[64];
        unsigned int left = len;
        while (left > 0) {
            int chunk = left < sizeof(tmp) ? (int)left : (int)sizeof(tmp);
            int r = recv_n(sock, tmp, chunk);
            if (r <= 0) break;
            left -= (unsigned int)r;
        }
        return -2;
    }
    int r = recv_n(sock, buf, (int)len);
    if (r != (int)len) return -3;
    buf[len] = '\0';
    return (int)len;
}

/* ---- cookie generation -------------------------------------------------- */
/* Generate a 36-char lowercase-alphanumeric cookie + NUL, using the current
   nanosecond timestamp as a seed.  The exact value does not matter as long as
   the same cookie is reused on the data connection.                          */
static void make_cookie(unsigned char *cookie) {
    static const char alpha[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    unsigned long long h = (unsigned long long)get_timestamp();
    for (int i = 0; i < COOKIE_SIZE - 1; i++) {
        /* LCG step — gives a different character for every position */
        h = h * 6364136223846793005ULL + 1442695040888963407ULL;
        cookie[i] = alpha[(h >> 33) % 36];
    }
    cookie[COOKIE_SIZE - 1] = '\0';
}

/* ---- static buffers ----------------------------------------------------- */
static unsigned char blk[BLOCK_SIZE];
static char          json_buf[4096];
static unsigned char cookie[COOKIE_SIZE];

int main(int argc, char **argv) {
    const char *addr = arg_addr(argc, argv, "127.0.0.1:5201");
    int addr_len = (int)strlen(addr);

    printf("[*] iperf3_tcp_client: connecting to %s...\n", addr);

    /* ---- 1. Control connection ----------------------------------------- */
    int ctrl = connect_tcp(addr, addr_len);
    if (ctrl < 0) {
        printf("[-] Error: connect_tcp(control) failed\n");
        return 1;
    }
    printf("[+] Control socket %d connected.\n", ctrl);

    /* ---- 2. Client sends cookie (client generates it, not the server) --- */
    make_cookie(cookie);
    send_tcp_data(ctrl, cookie, COOKIE_SIZE);
    printf("[+] Cookie sent: %.8s...\n", (char *)cookie);

    /* ---- 3. Server replies with PARAM_EXCHANGE -------------------------- */
    int st = recv_state(ctrl);
    if (st == ACCESS_DENIED) {
        printf("[-] Error: server denied access (ACCESS_DENIED)\n");
        close_tcp(ctrl);
        return 1;
    }
    if (st != PARAM_EXCHANGE) {
        printf("[-] Expected PARAM_EXCHANGE(9), got %d\n", st);
        close_tcp(ctrl);
        return 1;
    }
    printf("[+] PARAM_EXCHANGE received — sending params...\n");

    /* ---- 4. Client sends JSON parameters --------------------------------
     * Use the minimal set of fields that iperf3 3.16 actually sends on the
     * wire (confirmed by strace).  The server silently ignores unknown fields
     * but requires client_version, num, and blockcount to be present.        */
    snprintf(json_buf, sizeof(json_buf),
        "{\"tcp\":true,\"omit\":0,\"time\":%d,"
        "\"num\":0,\"blockcount\":0,"
        "\"parallel\":1,\"len\":%d,"
        "\"pacing_timer\":1000,"
        "\"client_version\":\"3.16\"}",
        TEST_DURATION_S, BLOCK_SIZE);
    send_json(ctrl, json_buf);
    printf("[+] Params sent.\n");

    /* ---- 5. Server replies with CREATE_STREAMS -------------------------- */
    st = recv_state(ctrl);
    if (st != CREATE_STREAMS) {
        printf("[-] Expected CREATE_STREAMS(10), got %d\n", st);
        close_tcp(ctrl);
        return 1;
    }
    printf("[+] CREATE_STREAMS — opening data socket...\n");

    /* ---- 6. Data connection: new TCP socket, same server address -------- */
    int data = connect_tcp(addr, addr_len);
    if (data < 0) {
        printf("[-] Error: connect_tcp(data) failed\n");
        close_tcp(ctrl);
        return 1;
    }
    /* The data socket is identified by sending the same cookie */
    send_tcp_data(data, cookie, COOKIE_SIZE);
    printf("[+] Data socket %d registered.\n", data);

    /* ---- 7. Server sends TEST_START (1) then TEST_RUNNING (2) ----------- *
     * iperf3 always sends both back-to-back; consume TEST_START then wait   *
     * for TEST_RUNNING before sending any data.                              */
    st = recv_state(ctrl);
    if (st == IPERF_START) {
        st = recv_state(ctrl);   /* consume TEST_START, now expect TEST_RUNNING */
    }
    if (st != TEST_RUNNING) {
        printf("[-] Expected TEST_RUNNING(2), got %d\n", st);
        close_tcp(data);
        close_tcp(ctrl);
        return 1;
    }
    printf("[+] Test starting — sending data for %d s...\n", TEST_DURATION_S);

    /* ---- 8. Data transfer ----------------------------------------------- */
    memset(blk, 0x41, sizeof(blk));   /* fill with 'A' */

    long long start_ns   = get_timestamp();
    long long deadline   = start_ns + (long long)TEST_DURATION_S * 1000000000LL;
    long long bytes_sent = 0;

    while (get_timestamp() < deadline) {
        send_tcp_data(data, blk, sizeof(blk));
        bytes_sent += sizeof(blk);
    }

    long long elapsed_ns = get_timestamp() - start_ns;
    close_tcp(data);
    printf("[+] Sent %lld bytes.\n", bytes_sent);

    /* ---- 9. Client signals end of test ---------------------------------- */
    send_state(ctrl, TEST_END);

    /* ---- 10. Result exchange ------------------------------------------- *
     * Sequence (confirmed by strace):                                        *
     *   server → EXCHANGE_RESULTS (13)                                       *
     *   client → results JSON                                                *
     *   server → results JSON                                                *
     *   server → DISPLAY_RESULTS (14)                                        *
     *   client → IPERF_DONE (16)         ← client sends this                */
    st = recv_state(ctrl);
    if (st == EXCHANGE_RESULTS) {
        double dur = (double)elapsed_ns / 1e9;
        snprintf(json_buf, sizeof(json_buf),
            "{\"cpu_util_total\":0,\"cpu_util_user\":0,"
            "\"cpu_util_system\":0,\"sender_has_retransmits\":1,"
            "\"congestion_used\":\"cubic\","
            "\"streams\":[{\"id\":1,\"bytes\":%lld,"
            "\"retransmits\":0,\"jitter\":0,\"errors\":0,"
            "\"packets\":0,\"start_time\":0,\"end_time\":%.3f}]}",
            bytes_sent, dur);
        send_json(ctrl, json_buf);
        recv_json(ctrl, json_buf, sizeof(json_buf));   /* server results, discard */
        recv_state(ctrl);      /* DISPLAY_RESULTS (14) */
        send_state(ctrl, 16);  /* client sends IPERF_DONE */
    }

    close_tcp(ctrl);

    /* ---- Report --------------------------------------------------------- */
    double duration_s = (double)elapsed_ns / 1e9;
    double mbps = (bytes_sent * 8.0) / (duration_s * 1e6);

    printf("[+] Result: Sent %lld bytes in %.2f s (%.2f Mbps)\n",
           bytes_sent, duration_s, mbps);
    return 0;
}
