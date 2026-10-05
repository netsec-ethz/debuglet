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
//!
//! # Host semantics
//!
//! The bindings target guest ABI `debuglet-go-wasi-imports-v1`. Each import
//! has exactly the signature that ABI freezes; the crate imports only the part
//! listed below, which any host implementing that ABI provides.
//!
//! - One host call transfers at most [`MAX_IO_BYTES`] bytes, whatever the
//!   buffer's length is. [`Conn::receive`] therefore fills at most that much,
//!   and [`Conn::send`] splits a longer stream payload into several calls.
//! - A stream read returns the number of bytes read, and 0 only at a clean end
//!   of stream (the peer closed its side). It never returns a negative value.
//! - Failures do not come back as values. A refused or unreachable destination,
//!   a destination outside the job's policy, a read or write error, an invalid
//!   handle and a buffer outside the module's memory all abort the guest inside
//!   the host call (a WebAssembly trap): the job ends with whatever the guest
//!   printed before the call. [`ConnectError`] reports only input this crate
//!   rejects itself.
//! - [`accept_tcp`] needs the job's TCP listener capability.
//!
//! # Not provided
//!
//! The Go SDK (`pkg/debuglet` in the Debuglet repository) is the complete
//! reference. This crate does not provide UDP sockets, the listener and remote
//! address getters (`get_tcp_addr`, `get_udp_addr`, `get_remote_addr`),
//! `drain_connection`, or the recoverable sockets of the optional
//! `debuglet_io_v1` module.

use std::fmt;

/// The number of bytes one host call transfers. It belongs to the guest ABI:
/// the host reads or writes at most this many bytes of the buffer it is given.
pub const MAX_IO_BYTES: usize = 8192;

// =============================================================================
// Raw host imports (wazero "env" module). Every address and buffer is passed by
// (pointer, length): a 32-bit offset into this module's linear memory plus a
// length. These are only resolvable inside the executor; a module that imports
// them does not link on another WASI runtime.
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

/// Error returned for a connection request this crate rejects before calling
/// the host: an empty address, or a negative handle, which the host does not
/// produce. A destination the host cannot reach aborts the guest instead.
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
    ///
    /// One host call carries at most [`MAX_IO_BYTES`] bytes, so a longer TCP
    /// payload becomes consecutive calls; the peer receives the same bytes. An
    /// ICMP datagram cannot be split without changing what the peer receives,
    /// so a longer one panics instead of being sent truncated.
    ///
    /// A write error aborts the guest inside the host call.
    pub fn send(&self, buf: &[u8]) {
        if let Transport::Icmp4 = self.transport {
            assert!(
                buf.len() <= MAX_IO_BYTES,
                "debuglet: {}-byte datagram exceeds the {}-byte host transfer bound",
                buf.len(),
                MAX_IO_BYTES
            );
        }
        for chunk in buf.chunks(MAX_IO_BYTES) {
            let (ptr, len) = (chunk.as_ptr() as u32, chunk.len() as u32);
            unsafe {
                match self.transport {
                    Transport::Icmp4 => host_send_icmp4_data(self.handle as u32, ptr, len),
                    Transport::Tcp => host_send_tcp_data(self.handle as u32, ptr, len),
                }
            }
        }
    }

    /// Performs one host read into `buf` and returns the count read. One call
    /// fills at most [`MAX_IO_BYTES`] bytes, so a larger buffer is filled only
    /// that far; a short read is normal.
    ///
    /// On a TCP or TLS connection 0 means the peer closed its side (end of
    /// stream). On an ICMP socket 0 is an empty datagram. A read error, an
    /// invalid handle or a refused peer aborts the guest inside the host call;
    /// the host never returns a negative count, and this method maps one to 0
    /// only defensively.
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

/// Dials a plaintext TCP connection to `addr` ("host:port"). The destination
/// must be allowed by the job's policy; a refused, unreachable or disallowed
/// destination aborts the guest inside the call.
pub fn connect_tcp(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Tcp, false)
}

/// Dials a TLS-over-TCP connection to `addr` ("host:port"). A failed dial or
/// handshake aborts the guest inside the call.
pub fn connect_tls(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Tcp, true)
}

/// Opens a raw ICMPv4 socket to `addr` (an IPv4 address, no port). This needs
/// the executor's ICMP capability; without it the call aborts the guest.
pub fn connect_icmp4(addr: &str) -> Result<Conn, ConnectError> {
    dial(addr, Transport::Icmp4, false)
}

/// Blocks until the job's TCP listener accepts one inbound connection that the
/// job's policy admits. The job must have been started with the TCP listener
/// capability; without a listener the call aborts the guest. The listener's
/// address is reported to the submitter by the executor; this crate does not
/// provide `get_tcp_addr` to read it from inside the guest.
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
