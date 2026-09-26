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
// The refactored engine (internal/executor/debuglet/wasm/host_functions.go) runs
// guests as standard WASI command modules and passes every address and buffer by
// (pointer, length):
//
//   * Entrypoint: define `int main(int argc, char **argv)` and build the module
//     for the wasm32-wasi target. The engine streams stdout/stderr back to the
//     user, so plain printf() is the way to report progress and results.
//
//   * Addresses & buffers: the guest writes bytes into its own linear memory and
//     hands the host a 32-bit offset plus a length. This replaces the old
//     index-based scheme (e.g. connect_tcp(0)).
//
//   * Timing: the host no longer exports get_timestamp()/sleep(); WASI clocks are
//     used instead. The helpers below wrap the standard library, which the host
//     backs with WithSysNanotime / WithSysNanosleep.
// -----------------------------------------------------------------------------

#define IMPORT(name) __attribute__((import_module("env"), import_name(#name)))

// ---- Generic / TCP / TLS socket API -----------------------------------------
// connect_* dials the address in addr[0 .. addr_len) and returns a non-negative
// socket handle. A dial the host cannot complete - refused, or outside the
// job's allowed destinations - ends the job inside the call instead of
// returning, so the -1 result is defensive rather than the usual failure path.
//
// One call transfers at most 8192 bytes of the buffer it is given, whatever
// len says, so send_* and receive_* belong in a loop.
IMPORT(connect_tcp)        int  connect_tcp(const void *addr, int addr_len);
IMPORT(connect_tls)        int  connect_tls(const void *addr, int addr_len);
IMPORT(accept_tcp)         int  accept_tcp(void);
IMPORT(receive_tcp_data)   int  receive_tcp_data(int sock, void *buf, int len);
IMPORT(send_tcp_data)      void send_tcp_data(int sock, const void *buf, int len);
IMPORT(close_tcp)          void close_tcp(int sock);

// ---- ICMPv4 socket API -------------------------------------------------------
IMPORT(connect_icmp4)      int  connect_icmp4(const void *addr, int addr_len);
IMPORT(receive_icmp4_data) int  receive_icmp4_data(int sock, void *buf, int len);
IMPORT(send_icmp4_data)    void send_icmp4_data(int sock, const void *buf, int len);
IMPORT(close_icmp4)        void close_icmp4(int sock);

#undef IMPORT

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
