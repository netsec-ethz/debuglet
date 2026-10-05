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

// Rust guest for the foreign-guest compatibility test, built on the Rust
// bindings in examples/debuglets/rust/debuglet.
//
//   -addr host:port  connect over TCP, read until end of stream with a bounded
//                    buffer and print the byte count.
//   -listen          accept one connection on the job's TCP listener, read until
//                    the peer half-closes (at most 32 KiB), echo it all and exit.

use std::process::exit;

const ECHO_LIMIT: usize = 32 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-listen") {
        echo_once();
        return;
    }
    let addr = match args.iter().position(|a| a == "-addr").and_then(|i| args.get(i + 1)) {
        Some(addr) => addr.clone(),
        None => {
            println!("usage: -addr host:port | -listen");
            exit(2);
        }
    };
    read_until_eof(&addr);
}

fn read_until_eof(addr: &str) {
    println!("connecting tcp {addr}");
    let conn = match debuglet::connect_tcp(addr) {
        Ok(conn) => conn,
        Err(err) => {
            println!("{err}");
            exit(1);
        }
    };
    println!("connected");
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = conn.receive(&mut buf);
        if n == 0 {
            break;
        }
        total += n;
    }
    println!("eof");
    println!("total={total}");
}

fn echo_once() {
    println!("accepting");
    let conn = match debuglet::accept_tcp() {
        Ok(conn) => conn,
        Err(err) => {
            println!("{err}");
            exit(1);
        }
    };
    // Read until the peer half-closes, into a bounded buffer, then send it all
    // back in one call to the binding, which splits it at the transfer bound.
    let mut buf = vec![0u8; ECHO_LIMIT];
    let mut n = 0usize;
    while n < buf.len() {
        let got = conn.receive(&mut buf[n..]);
        if got == 0 {
            break;
        }
        n += got;
    }
    conn.send(&buf[..n]);
    println!("echoed n={n}");
    drop(conn);
    println!("closed");
}
