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

//! Rust client library for writing debuglets — WASM measurement programs that
//! run on the Debuglet executor.
//!
//! A debuglet is a standard WASI command module: write a normal `fn main()`,
//! build it for `wasm32-wasip1`, and the executor streams whatever you print to
//! stdout/stderr back to the user. Command-line arguments typed by the user
//! arrive verbatim as WASI argv (`std::env::args()`), with no program name at
//! index 0.
//!
//! This crate wraps the raw host imports exported by the executor engine so you
//! never have to write `extern "C"` blocks or juggle linear-memory offsets:
//!
//! ```no_run
//! let conn = debuglet::connect_tcp("example.com:80").unwrap();
//! conn.send(b"GET / HTTP/1.0\r\n\r\n");
//! let mut buf = [0u8; 4096];
//! let n = conn.receive(&mut buf);
//! print!("{}", String::from_utf8_lossy(&buf[..n]));
//! ```

use std::fmt;

// =============================================================================
// Raw host imports (wazero "env" module). Every address and buffer is passed by
// (pointer, length): a 32-bit offset into this module's linear memory plus a
// length. These are only resolvable inside the executor; calling them elsewhere
// traps.
// =============================================================================
#[link(wasm_import_module = "env")]
extern "C" {
    #[link_name = "connect_tcp"]
    fn host_connect_tcp(addr_ptr: u32, addr_len: u32) -> i32;
    #[link_name = "connect_tls"]
    fn host_connect_tls(addr_ptr: u32, addr_len: u32) -> i32;
    #[link_name = "accept_tcp"]
    fn host_accept_tcp() -> i32;
    #[link_name = "receive_tcp_data"]
    fn host_receive_tcp_data(sock: u32, buf_ptr: u32, buf_len: u32) -> i32;
    #[link_name = "send_tcp_data"]
    fn host_send_tcp_data(sock: u32, buf_ptr: u32, buf_len: u32);
    #[link_name = "close_tcp"]
    fn host_close_tcp(sock: u32);

    #[link_name = "connect_icmp4"]
    fn host_connect_icmp4(addr_ptr: u32, addr_len: u32) -> i32;
    #[link_name = "receive_icmp4_data"]
    fn host_receive_icmp4_data(sock: u32, buf_ptr: u32, buf_len: u32) -> i32;
    #[link_name = "send_icmp4_data"]
    fn host_send_icmp4_data(sock: u32, buf_ptr: u32, buf_len: u32);
    #[link_name = "close_icmp4"]
    fn host_close_icmp4(sock: u32);
}

/// Error returned when a connection cannot be established.
#[derive(Debug)]
pub struct ConnectError(String);

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "debuglet: connect failed: {}", self.0)
    }
}

impl std::error::Error for ConnectError {}

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Icmp4,
}

/// A connection handle returned by the `connect_*` helpers. Wraps the integer
/// socket handle owned by the host and routes `send`/`receive`/`close` to the
/// correct host functions for its transport.
pub struct Conn {
    handle: i32,
    transport: Transport,
}

impl Conn {
    /// The raw host socket handle (for diagnostics / advanced use).
    pub fn handle(&self) -> i32 {
        self.handle
    }

    /// Writes the whole of `buf` to the connection.
    pub fn send(&self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        let (ptr, len) = (buf.as_ptr() as u32, buf.len() as u32);
        unsafe {
            match self.transport {
                Transport::Icmp4 => host_send_icmp4_data(self.handle as u32, ptr, len),
                Transport::Tcp => host_send_tcp_data(self.handle as u32, ptr, len),
            }
        }
    }

    /// Reads up to `buf.len()` bytes into `buf` and returns the count read.
    /// Returns 0 on a non-positive host result (error or empty read).
    pub fn receive(&self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let (ptr, len) = (buf.as_mut_ptr() as u32, buf.len() as u32);
        let n = unsafe {
            match self.transport {
                Transport::Icmp4 => host_receive_icmp4_data(self.handle as u32, ptr, len),
                Transport::Tcp => host_receive_tcp_data(self.handle as u32, ptr, len),
            }
        };
        if n < 0 {
            0
        } else {
            n as usize
        }
    }

    fn close_inner(&self) {
        unsafe {
            match self.transport {
                Transport::Icmp4 => host_close_icmp4(self.handle as u32),
                Transport::Tcp => host_close_tcp(self.handle as u32),
            }
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close_inner();
    }
}

fn dial(addr: &str, transport: Transport, tls: bool) -> Result<Conn, ConnectError> {
    if addr.is_empty() {
        return Err(ConnectError("empty address".into()));
    }
    let (ptr, len) = (addr.as_ptr() as u32, addr.len() as u32);
    let handle = unsafe {
        match transport {
            Transport::Icmp4 => host_connect_icmp4(ptr, len),
            Transport::Tcp if tls => host_connect_tls(ptr, len),
            Transport::Tcp => host_connect_tcp(ptr, len),
        }
    };
    if handle < 0 {
        return Err(ConnectError(addr.to_string()));
    }
    Ok(Conn { handle, transport })
}

/// Dials a plaintext TCP connection to `addr` ("host:port").
pub fn connect_tcp(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Tcp, false)
}

/// Dials a TLS-over-TCP connection to `addr` ("host:port").
pub fn connect_tls(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Tcp, true)
}

/// Opens a raw ICMPv4 socket to `addr` (an IPv4 address, no port).
pub fn connect_icmp4(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Icmp4, false)
}

/// Blocks until the host's TCP listener accepts one inbound connection.
/// Requires the executor's TCP listener to be enabled.
pub fn accept_tcp() -> Result<Conn, ConnectError> {
    let handle = unsafe { host_accept_tcp() };
    if handle < 0 {
        return Err(ConnectError("accept_tcp".into()));
    }
    Ok(Conn {
        handle,
        transport: Transport::Tcp,
    })
}
