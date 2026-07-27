// ping — ICMPv4 latency probe, written with the Debuglet Rust SDK.
//
// Sends `-iter` ICMP echo requests to `-addr` (one per second) and prints the
// round-trip time of each reply.
//
// Build:
//   make wasm SAMPLE_DIR=local/wasm_samples/rust/ping
//
// Run (args after `--` are passed verbatim to the guest):
//   go run ./cmd/user -wasm local/wasm_samples/rust/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5

use std::time::Instant;

fn main() {
    // WASI argv has no program name, so args() yields the user's flags directly.
    let argv: Vec<String> = std::env::args().collect();
    let addr = flag_str(&argv, "-addr", "1.1.1.1");
    let iter = flag_str(&argv, "-iter", "5").parse::<u16>().unwrap_or(5);

    for seq in 0..iter {
        match ping(&addr, 1, seq) {
            Ok(ms) => println!("icmp_seq={seq}  time={ms:.3}ms"),
            Err(e) => println!("icmp_seq={seq}  error: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Returns the value following `name` in argv, or `fallback` if absent.
fn flag_str(argv: &[String], name: &str, fallback: &str) -> String {
    argv.iter()
        .position(|a| a == name)
        .and_then(|i| argv.get(i + 1))
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}

fn ping(addr: &str, id: u16, seq: u16) -> Result<f64, String> {
    let conn = debuglet::connect_icmp4(addr).map_err(|e| e.to_string())?;
    let packet = echo_packet(id, seq, 64);

    let start = Instant::now();
    conn.send(&packet);
    let mut buf = [0u8; 100];
    let n = conn.receive(&mut buf);
    let rtt = start.elapsed().as_secs_f64() * 1000.0;

    if n < 20 {
        return Err(format!("short reply: {n} bytes (missing IP header)"));
    }
    Ok(rtt)
}

/// Builds a minimal ICMP echo request (type 8) with the checksum set.
fn echo_packet(id: u16, seq: u16, size: usize) -> Vec<u8> {
    let mut p = vec![0u8; size];
    p[0] = 8; // type: echo request
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    let csum = checksum(&p);
    p[2..4].copy_from_slice(&csum.to_be_bytes());
    p
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < b.len() {
        sum += (u32::from(b[i]) << 8) | u32::from(b[i + 1]);
        i += 2;
    }
    if b.len() % 2 == 1 {
        sum += u32::from(b[b.len() - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
