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

#ifndef DEBUGLET_API_H
#define DEBUGLET_API_H

#include <string.h>
#include <time.h>

// -----------------------------------------------------------------------------
// Debuglet host API for C guests (wazero "env" module).
//
// The declarations below are part of guest ABI debuglet-go-wasi-imports-v1,
// with exactly the signatures that ABI freezes. The engine
// (internal/executor/debuglet/wasm/host_functions.go) runs guests as standard
// WASI command modules and passes every address and buffer by
// (pointer, length):
//
//   * Entrypoint: define `int main(int argc, char **argv)` and build the module
//     for the wasm32-wasip1 target. The engine streams stdout/stderr back to the
//     user, so plain printf() is the way to report progress and results.
//
//   * Addresses & buffers: the guest writes bytes into its own linear memory and
//     hands the host a 32-bit offset plus a length.
//
//   * Timing: the host does not export get_timestamp()/sleep(); WASI clocks are
//     used instead. The helpers below wrap the standard library, which the host
//     backs with WithSysNanotime / WithSysNanosleep.
//
// Error semantics. Failures do not come back as return values: a refused or
// unreachable destination, a destination outside the job's policy, a read or
// write error, an invalid handle and a buffer outside the module's memory all
// abort the guest inside the host call (a WebAssembly trap), and the job ends
// with whatever the guest printed before the call. No import returns a
// negative value; the `< 0` checks in the examples are defensive.
//
// Transfer bound. One call transfers at most DEBUGLET_MAX_IO_BYTES (8192)
// bytes of the buffer it is given, whatever len says: receive_* fills at most
// that much and send_* sends at most that much. Use debuglet_send_tcp_all()
// for a longer stream payload.
//
// Not provided here. The Go SDK (pkg/debuglet) is the complete reference. This
// header does not declare UDP sockets, the listener and remote address getters
// (get_tcp_addr, get_udp_addr, get_remote_addr), drain_connection, or the
// recoverable sockets of the optional debuglet_io_v1 module.
// -----------------------------------------------------------------------------

#define DEBUGLET_MAX_IO_BYTES 8192

#define IMPORT(name) __attribute__((import_module("env"), import_name(#name)))

// ---- TCP / TLS socket API ----------------------------------------------------
// connect_tcp and connect_tls dial the "host:port" in addr[0 .. addr_len) and
// return a non-negative socket handle. A dial the host cannot complete -
// refused, unreachable, a failed TLS handshake, or outside the job's allowed
// destinations - aborts the guest inside the call instead of returning.
//
// accept_tcp blocks until the job's TCP listener accepts one connection the
// job's policy admits, and returns its handle. The job must have been started
// with the TCP listener capability; without a listener the call aborts the
// guest. The executor reports the listener's address to the submitter.
//
// receive_tcp_data performs one read and returns the number of bytes read, and
// 0 only at a clean end of stream (the peer closed its side). A read error
// aborts the guest.
IMPORT(connect_tcp)        int  connect_tcp(const void *addr, int addr_len);
IMPORT(connect_tls)        int  connect_tls(const void *addr, int addr_len);
IMPORT(accept_tcp)         int  accept_tcp(void);
IMPORT(receive_tcp_data)   int  receive_tcp_data(int sock, void *buf, int len);
IMPORT(send_tcp_data)      void send_tcp_data(int sock, const void *buf, int len);
IMPORT(close_tcp)          void close_tcp(int sock);

// ---- ICMPv4 socket API -------------------------------------------------------
// connect_icmp4 takes an IPv4 address without a port and needs the executor's
// ICMP capability. receive_icmp4_data returns the datagram's length (0 for an
// empty datagram). A datagram longer than DEBUGLET_MAX_IO_BYTES cannot be sent
// in one call.
IMPORT(connect_icmp4)      int  connect_icmp4(const void *addr, int addr_len);
IMPORT(receive_icmp4_data) int  receive_icmp4_data(int sock, void *buf, int len);
IMPORT(send_icmp4_data)    void send_icmp4_data(int sock, const void *buf, int len);
IMPORT(close_icmp4)        void close_icmp4(int sock);

#undef IMPORT

// debuglet_send_tcp_all sends all len bytes of buf on a TCP or TLS connection,
// one host call per DEBUGLET_MAX_IO_BYTES. A write error aborts the guest.
static inline void debuglet_send_tcp_all(int sock, const void *buf, int len) {
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        int chunk = len < DEBUGLET_MAX_IO_BYTES ? len : DEBUGLET_MAX_IO_BYTES;
        send_tcp_data(sock, p, chunk);
        p += chunk;
        len -= chunk;
    }
}

// -----------------------------------------------------------------------------
// Timing helpers (backed by WASI clocks).
// -----------------------------------------------------------------------------

// get_timestamp returns a monotonic timestamp in nanoseconds.
static inline long long get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

// sleep_ns suspends the debuglet for the given number of nanoseconds.
static inline void sleep_ns(long long ns) {
    if (ns <= 0) {
        return;
    }
    struct timespec req;
    req.tv_sec  = (time_t)(ns / 1000000000LL);
    req.tv_nsec = (long)(ns % 1000000000LL);
    nanosleep(&req, NULL);
}

// -----------------------------------------------------------------------------
// Argument helpers.
//
// The target address is supplied on the command line by the user and reaches the
// guest as WASI argv. Following the convention of the Go samples (-addr
// <host:port>), the program name is NOT present at argv[0]; the first real
// argument is argv[0].
// -----------------------------------------------------------------------------

// arg_addr returns the value following "-addr" in argv, or `fallback` if absent.
static inline const char *arg_addr(int argc, char **argv, const char *fallback) {
    for (int i = 0; i + 1 < argc; i++) {
        if (strcmp(argv[i], "-addr") == 0) {
            return argv[i + 1];
        }
    }
    return fallback;
}

#endif // DEBUGLET_API_H
