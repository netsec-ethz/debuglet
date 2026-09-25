#!/usr/bin/env python3
# Copyright 2025 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""debug_tesla.py — step-by-step TESLA key schedule diagnostic tool.

Checks every layer of the verification pipeline independently so you can see
exactly where a mismatch occurs.

Usage:
    python3 scripts/debug_tesla.py --server https://localhost:9000 \\
        --ip 127.0.0.1 --pcap test.pcap [--no-verify-tls]
"""

import argparse
import base64
import hashlib
import hmac
import struct
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Crypto helpers (identical to verify_pcap.py)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_chain_forward(key: bytes, steps: int) -> bytes:
    cur = key
    for _ in range(steps):
        cur = _sha256(cur)
    return cur


def hkdf_sha256(secret: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF-SHA256 with salt = 32 zero bytes (matches Go nil salt)
    salt = bytes(32)
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


def siphash24(k0: int, k1: int, data: bytes) -> int:
    def rotl(v, n):
        return ((v << n) | (v >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

    def sipround(v0, v1, v2, v3):
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = rotl(v1, 13) ^ v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = rotl(v1, 17) ^ v2
        v2 = rotl(v2, 32)
        return v0, v1, v2, v3

    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    cap = min(len(data), 64)
    blocks = cap // 8
    if blocks > 8:
        blocks = 8

    for i in range(blocks):
        m = struct.unpack_from("<Q", data, i * 8)[0]
        v3 ^= m
        for _ in range(2):
            v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m

    b = (cap << 56) & 0xFFFFFFFFFFFFFFFF
    v3 ^= b
    for _ in range(2):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFF


def compute_bpf_tag(ak: bytes, payload: bytes) -> int:
    k0 = struct.unpack_from("<Q", ak, 0)[0]
    k1 = struct.unpack_from("<Q", ak, 8)[0]
    cap = min(len(payload), 64)
    return siphash24(k0, k1, payload[:cap])


def canonicalize_ipv4(raw: bytes) -> bytes:
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return raw
    pkt = bytearray(raw)
    pkt[4] = pkt[5] = 0    # IPID
    pkt[10] = pkt[11] = 0  # checksum
    return bytes(pkt)


def sep(title=""):
    width = 70
    if title:
        print(f"\n{'─' * 3} {title} {'─' * (width - 5 - len(title))}")
    else:
        print("─" * width)


def hex_abbrev(b: bytes, n: int = 8) -> str:
    if not b:
        return "(empty)"
    h = b.hex()
    return h[:n*2] + ("…" if len(b) > n else "")


# ---------------------------------------------------------------------------
# Diagnostic steps
# ---------------------------------------------------------------------------

def check_api(server: str, ip: str, verify_tls: bool, n: int):
    sep("STEP 1 — API: executor by IP")
    url = f"{server}/executors/by-ip"
    params = {"ip": ip}
    if n > 0:
        params["n"] = n
    print(f"  GET {url}  params={params}")
    try:
        resp = requests.get(url, params=params, verify=verify_tls)
        resp.raise_for_status()
        by_ip = resp.json()
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return None, None

    print(f"  executor_id     : {by_ip.get('executor_id')}")
    mids = by_ip.get("measurement_ids", [])
    print(f"  measurement_ids : {mids}  ({len(mids)} entries)")
    if not mids:
        print("  ⚠ WARNING: no measurement IDs — either no measurements were dispatched")
        print("             or they haven't been recorded yet.")

    sep("STEP 2 — API: TESLA params")
    exec_id = by_ip.get("executor_id")
    if not exec_id:
        print("  ✗ Cannot proceed: no executor_id")
        return None, None

    url2 = f"{server}/executors/{exec_id}/tesla"
    print(f"  GET {url2}")
    try:
        resp2 = requests.get(url2, verify=verify_tls)
        resp2.raise_for_status()
        tesla = resp2.json()
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return None, None

    print(f"  executor_id         : {tesla.get('executor_id')}")
    print(f"  anchor_timestamp_ns : {tesla.get('anchor_timestamp_ns')}")
    print(f"  delay_sec           : {tesla.get('delay_sec')}")
    print(f"  disclosed_epoch     : {tesla.get('disclosed_epoch')}")

    anchor_b64 = tesla.get("anchor_key", "")
    disclosed_b64 = tesla.get("disclosed_key", "")
    print(f"  anchor_key          : {anchor_b64[:20]}…  ({len(base64.b64decode(anchor_b64)) if anchor_b64 else 0} bytes)")
    print(f"  disclosed_key       : {disclosed_b64[:20] if disclosed_b64 else '(EMPTY — no key disclosed yet)'}…  "
          f"({len(base64.b64decode(disclosed_b64)) if disclosed_b64 else 0} bytes)")

    if not disclosed_b64:
        print()
        print("  ✗ FATAL: disclosed_key is empty.")
        print("    The executor has not yet disclosed any key to the dispatcher.")
        print("    Possible reasons:")
        print("      • The executor just started and the first epoch hasn't ended.")
        print("        (With delay=10s, the first key is disclosed after ~10-15s.)")
        print("      • The heartbeat interval is delay/2; check that heartbeats are")
        print("        being received by the dispatcher.")
        print("      • TeslaDelay may be 0 in the executor config (check TOML key")
        print("        matches the struct tag: toml:\"delay\" → use [tesla] delay).")
        return None, None

    return by_ip, tesla


def check_chain(tesla: dict):
    sep("STEP 3 — Chain consistency: H^τ(k_τ) == k_0")
    anchor_b64 = tesla.get("anchor_key", "")
    disclosed_b64 = tesla.get("disclosed_key", "")
    if not anchor_b64 or not disclosed_b64:
        print("  ⚠ SKIPPED: missing anchor or disclosed key")
        return

    anchor = base64.b64decode(anchor_b64)
    disclosed = base64.b64decode(disclosed_b64)
    tau = tesla["disclosed_epoch"]

    print(f"  anchor (k_0) bytes : {hex_abbrev(anchor)}")
    print(f"  k_τ (epoch={tau}) bytes : {hex_abbrev(disclosed)}")
    print(f"  Computing H^{tau}(k_τ) …", end=" ", flush=True)
    derived_anchor = hash_chain_forward(disclosed, tau)
    match = hmac.compare_digest(derived_anchor, anchor)
    print("OK ✓" if match else f"MISMATCH ✗")
    if not match:
        print(f"  Expected (anchor) : {anchor.hex()}")
        print(f"  Got               : {derived_anchor.hex()}")
        print("  ✗ Chain is broken — the disclosed key is not consistent with the")
        print("    anchor key stored by the dispatcher. Possible causes:")
        print("      • The anchor key was stored from a DIFFERENT key schedule run")
        print("        (executor restarted with a new random seed).")
        print("      • The disclosed key was corrupted in transit.")
    else:
        print(f"  Chain is valid — k_{tau} correctly hashes to k_0.")


def check_packets(pcap_path: str, tesla: dict, by_ip: dict, src_ip: str):
    sep("STEP 4 — Packet-level verification")
    try:
        from scapy.layers.inet import IP
        from scapy.utils import rdpcap
    except ImportError:
        print("  ⚠ scapy not installed — skipping packet check")
        print("    Run: pip install scapy")
        return

    anchor_b64 = tesla.get("anchor_key", "")
    disclosed_b64 = tesla.get("disclosed_key", "")
    if not disclosed_b64:
        print("  ⚠ SKIPPED: no disclosed key")
        return

    anchor = base64.b64decode(anchor_b64) if anchor_b64 else None
    disclosed = base64.b64decode(disclosed_b64)
    tau = tesla["disclosed_epoch"]
    anchor_ts_ns = tesla["anchor_timestamp_ns"]
    delay_ns = int(tesla["delay_sec"]) * 1_000_000_000
    measurement_ids = by_ip.get("measurement_ids", [])

    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"  ✗ Cannot read pcap: {e}")
        return

    ip_pkts = [(p, p.time) for p in pkts if IP in p and p[IP].src == src_ip]
    if not ip_pkts:
        print(f"  ⚠ No IPv4 packets from {src_ip} found in {pcap_path}")
        return

    print(f"  Found {len(ip_pkts)} IPv4 packet(s) from {src_ip}\n")

    for idx, (pkt, pkt_time) in enumerate(ip_pkts[:5]):  # cap at first 5
        ip_layer = pkt[IP]
        pkt_ts_ns = int(float(pkt_time) * 1e9)
        raw_ip = bytes(ip_layer)
        canonical = canonicalize_ipv4(raw_ip)
        ip_id = ip_layer.id

        elapsed_ns = pkt_ts_ns - anchor_ts_ns
        pkt_epoch = max(0, elapsed_ns // delay_ns) if elapsed_ns >= 0 else 0

        print(f"  Packet #{idx+1}")
        print(f"    capture time (ns) : {pkt_ts_ns}")
        print(f"    anchor time  (ns) : {anchor_ts_ns}")
        print(f"    elapsed      (ns) : {elapsed_ns}")
        print(f"    delay        (ns) : {delay_ns}")
        print(f"    computed epoch    : {pkt_epoch}")
        print(f"    disclosed epoch τ : {tau}")
        print(f"    ip.id (observed)  : 0x{ip_id:04x} ({ip_id})")
        print(f"    raw IP (first 20B): {raw_ip[:20].hex()}")
        print(f"    canonical (4-5,10-11 zeroed): {canonical[:20].hex()}")

        if pkt_epoch < 1:
            print("    ✗ No signing key in epoch 0: packets sent during the executor's first epoch carry no attribution tag.")
            print()
            continue

        if pkt_epoch > tau:
            print(f"    ✗ Packet epoch {pkt_epoch} > disclosed epoch {tau} — key not yet disclosed.")
            print()
            continue

        steps = tau - pkt_epoch
        chain_key = hash_chain_forward(disclosed, steps)
        print(f"    steps (τ - t)     : {steps}")
        print(f"    k_{pkt_epoch} (derived) : {hex_abbrev(chain_key)}")

        if anchor:
            chain_ok = hmac.compare_digest(hash_chain_forward(chain_key, pkt_epoch), anchor)
            print(f"    chain check H^{pkt_epoch}(k_{pkt_epoch})==k_0 : {'✓ PASS' if chain_ok else '✗ FAIL'}")
            if not chain_ok:
                print("      → skipping measurement check (chain broken)")
                print()
                continue

        if not measurement_ids:
            print("    ⚠ No measurement IDs to try.")
        else:
            print(f"    Trying {len(measurement_ids)} measurement ID(s):")
            for mid in measurement_ids:
                ak = hkdf_sha256(chain_key, mid.encode())
                tag = compute_bpf_tag(ak, canonical)
                match_sym = "✓ MATCH" if tag == ip_id else f"✗ no match (computed 0x{tag:04x})"
                print(f"      measurement={mid!r:40s}  ak={hex_abbrev(ak)}  tag=0x{tag:04x}  {match_sym}")
        print()

    if len(ip_pkts) > 5:
        print(f"  … (showing first 5 of {len(ip_pkts)} packets)")


def main():
    parser = argparse.ArgumentParser(description="TESLA verification diagnostic tool")
    parser.add_argument("--server", default="https://localhost:9000")
    parser.add_argument("--ip", required=True, help="Source IP to investigate")
    parser.add_argument("--pcap", help="Optional pcap file for packet-level check")
    parser.add_argument("--n", type=int, default=0, help="Max measurement IDs to fetch")
    parser.add_argument("--no-verify-tls", action="store_true")
    args = parser.parse_args()

    verify_tls = not args.no_verify_tls

    print(f"TESLA Diagnostic — server={args.server}  ip={args.ip}")
    sep()

    by_ip, tesla = check_api(args.server, args.ip, verify_tls, args.n)
    if tesla is None:
        print("\n✗ Diagnostics aborted — fix the issue above and retry.")
        sys.exit(1)

    check_chain(tesla)

    if args.pcap:
        check_packets(args.pcap, tesla, by_ip, args.ip)
    else:
        sep("STEP 4 — Packet-level verification")
        print("  (no --pcap provided — skipping)")

    sep()
    print("Diagnostics complete.")


if __name__ == "__main__":
    main()
