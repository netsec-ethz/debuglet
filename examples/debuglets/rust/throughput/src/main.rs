// throughput — TCP throughput sender, written with the Debuglet Rust SDK.
//
// Connects to `-addr` and sends fixed-size chunks for `-secs` seconds, then
// reports the achieved throughput in Mbps. Pair it with any TCP sink.
//
// Build:
//   make wasm SAMPLE_DIR=examples/debuglets/rust/throughput
//
// Run:
//   go run ./cmd/user -wasm examples/debuglets/rust/throughput/debuglet.wasm -- -addr 127.0.0.1:5201 -secs 5

use std::time::{Duration, Instant};

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let addr = flag_str(&argv, "-addr", "127.0.0.1:5201");
    let secs = flag_str(&argv, "-secs", "5").parse::<u64>().unwrap_or(5);
    let chunk = flag_str(&argv, "-chunk", "4096").parse::<usize>().unwrap_or(4096);

    println!("[*] throughput: sending to {addr} for {secs}s (chunk={chunk}B)");

    let conn = match debuglet::connect_tcp(&addr) {
        Ok(c) => c,
        Err(e) => {
            println!("[-] {e}");
            std::process::exit(1);
        }
    };

    let buf = vec![b'A'; chunk];
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut sent: u64 = 0;
    while Instant::now() < deadline {
        conn.send(&buf);
        sent += buf.len() as u64;
    }

    let mbps = (sent as f64) * 8.0 / (secs as f64 * 1e6);
    println!("[+] sent {sent} bytes in {secs}s ({mbps:.2} Mbps)");
}

fn flag_str(argv: &[String], name: &str, fallback: &str) -> String {
    argv.iter()
        .position(|a| a == name)
        .and_then(|i| argv.get(i + 1))
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}
