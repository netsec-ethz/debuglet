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

"""verify_pcap.py — offline TESLA packet verification tool.

Workflow
--------
1. Parse the pcap locally (requires scapy).
2. For each unique source IP call GET /executors/by-ip?ip=<ip>[&n=<n>]
   to obtain the executor ID and the candidate measurement IDs.
3. Call GET /executors/<id>/tesla to obtain:
      anchor_key            – k_0 (base64), used for chain consistency checks
      anchor_timestamp_ns   – t_0, when epoch 0 started
      delay_sec             – epoch duration I
      disclosed_epoch       – τ, the latest epoch whose key is published
      disclosed_key         – k_τ (base64)
4. For each IPv4 packet:
   a. Compute the epoch t from the packet timestamp.
   b. Derive k_t = H^(τ-t)(k_τ)   [hash forward in the backward chain].
   c. Optionally verify chain consistency: H^t(k_t) == k_0.
   d. For each candidate measurement ID derive the per-measurement key:
          ak = HKDF-SHA256(secret=k_t, info=measurement_id)
      and check the SipHash-2-4 tag stored in the IP-ID field.
5. Report which measurement IDs verified for each packet.

Usage
-----
    python3 scripts/verify_pcap.py --pcap capture.pcap \\
        [--server https://localhost:9000] [--n 20] [--no-verify-tls]

Dependencies: scapy, requests, hkdf
    pip install scapy requests hkdf
"""

import argparse
import base64
import hashlib
import hmac
import struct
import sys
from typing import Optional

import requests
import urllib3

# Optional: suppress TLS warnings when --no-verify-tls is used.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Crypto helpers (pure Python, matching the Go implementation)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_chain_forward(key: bytes, steps: int) -> bytes:
    """Hash key forward `steps` times: k_{t} = H^steps(key).

    In the backward chain k_i = H(k_{i+1}), so going from a later disclosed
    key k_τ to an earlier key k_t requires hashing forward (τ-t) times.
    """
    cur = key
    for _ in range(steps):
        cur = _sha256(cur)
    return cur


def verify_chain(anchor: bytes, key: bytes, t: int) -> bool:
    """Check H^t(key) == anchor (k_0)."""
    return hmac.compare_digest(hash_chain_forward(key, t), anchor)


def hkdf_sha256(secret: bytes, info: bytes, length: int = 32) -> bytes:
    """Minimal HKDF-SHA256 with empty salt, matching Go's golang.org/x/crypto/hkdf."""
    # Extract
    salt = bytes(32)  # zero-length salt → HMAC with zero key of hash length
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    # Expand
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


def siphash24(k0: int, k1: int, data: bytes) -> int:
    """SipHash-2-4, matching the BPF tagger's 64-byte-capped implementation."""

    def rotl(v: int, n: int) -> int:
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

    # Cap at 64 bytes, matching tagger.c
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
    """Compute the 16-bit SipHash-2-4 tag, matching ComputeBPFTag in Go."""
    k0 = struct.unpack_from("<Q", ak, 0)[0]
    k1 = struct.unpack_from("<Q", ak, 8)[0]
    cap = min(len(payload), 64)
    return siphash24(k0, k1, payload[:cap])


def canonicalize_ipv4(raw: bytes) -> bytes:
    """Zero the IPID (bytes 4-5) and checksum (bytes 10-11) fields."""
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return raw
    pkt = bytearray(raw)
    pkt[4] = pkt[5] = 0   # IPID
    pkt[10] = pkt[11] = 0  # checksum
    return bytes(pkt)


# ---------------------------------------------------------------------------
# Dispatcher API helpers
# ---------------------------------------------------------------------------

class DispatcherClient:
    def __init__(self, server: str, verify_tls: bool = True):
        self.server = server.rstrip("/")
        self.verify_tls = verify_tls
        self._executor_cache: dict = {}
        self._tesla_cache: dict = {}

    def _get(self, path: str, **params) -> dict:
        url = f"{self.server}{path}"
        resp = requests.get(url, params=params or None, verify=self.verify_tls)
        resp.raise_for_status()
        return resp.json()

    def executor_by_ip(self, ip: str, n: int = 0) -> Optional[dict]:
        """Call GET /executors/by-ip?ip=<ip>[&n=<n>].

        Returns {"executor_id": ..., "measurement_ids": [...]} or None.
        """
        cache_key = (ip, n)
        if cache_key in self._executor_cache:
            return self._executor_cache[cache_key]
        params = {"ip": ip}
        if n > 0:
            params["n"] = n
        try:
            result = self._get("/executors/by-ip", **params)
            self._executor_cache[cache_key] = result
            return result
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def executor_tesla(self, executor_id: str) -> Optional[dict]:
        """Call GET /executors/<id>/tesla.

        Returns the TESLA key schedule parameters or None.
        """
        if executor_id in self._tesla_cache:
            return self._tesla_cache[executor_id]
        try:
            result = self._get(f"/executors/{executor_id}/tesla")
            self._tesla_cache[executor_id] = result
            return result
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

def verify_packet(raw_ip: bytes, ip_id: int, pkt_ts_ns: int,
                  tesla: dict) -> list[str]:
    """Return the list of measurement IDs that successfully verify for this packet.

    Parameters
    ----------
    raw_ip      Full IPv4 packet bytes (header + payload).
    ip_id       The IPID field value from the captured packet (the tag).
    pkt_ts_ns   Packet capture timestamp in nanoseconds.
    tesla       Dict as returned by GET /executors/:id/tesla.
    """
    anchor_key_b64 = tesla.get("anchor_key", "")
    disclosed_key_b64 = tesla.get("disclosed_key", "")
    if not disclosed_key_b64:
        return []

    anchor_ts_ns: int = tesla["anchor_timestamp_ns"]
    delay_ns: int = int(tesla["delay_sec"]) * 1_000_000_000
    disclosed_epoch: int = tesla["disclosed_epoch"]
    measurement_ids: list = tesla.get("measurement_ids", [])

    disclosed_key = base64.b64decode(disclosed_key_b64)
    anchor_key = base64.b64decode(anchor_key_b64) if anchor_key_b64 else None

    # Compute the packet epoch.
    elapsed_ns = pkt_ts_ns - anchor_ts_ns
    if elapsed_ns < 0:
        pkt_epoch = 0
    else:
        pkt_epoch = elapsed_ns // delay_ns

    # Reconstruct k_{pkt_epoch} by hashing k_{disclosed_epoch} forward.
    # In the backward chain: k_t = H^(disclosed_epoch - t)(k_{disclosed_epoch}).
    matched = []
    for epoch_candidate in [pkt_epoch, max(0, pkt_epoch - 1)]:
        if epoch_candidate > disclosed_epoch:
            continue  # key not yet disclosed
        steps = disclosed_epoch - epoch_candidate
        chain_key = hash_chain_forward(disclosed_key, steps)

        # Optional chain consistency check.
        if anchor_key and not verify_chain(anchor_key, chain_key, epoch_candidate):
            continue  # chain tampered or wrong epoch

        # Try each measurement ID.
        canonical = canonicalize_ipv4(raw_ip)
        for mid in measurement_ids:
            ak = hkdf_sha256(chain_key, mid.encode())
            tag = compute_bpf_tag(ak, canonical)
            if tag == ip_id:
                if mid not in matched:
                    matched.append(mid)

    return matched


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Verify IPv4 packet authentication tags in a pcap using the dispatcher TESLA APIs"
    )
    parser.add_argument("--server", default="https://localhost:9000",
                        help="Dispatcher API base URL (default: https://localhost:9000)")
    parser.add_argument("--pcap", required=True, help="Path to the pcap file")
    parser.add_argument("--n", type=int, default=0,
                        help="Max recent measurement IDs to fetch per executor (default: server default = 10)")
    parser.add_argument("--no-verify-tls", action="store_true",
                        help="Disable TLS certificate verification (for local testing)")
    args = parser.parse_args()

    try:
        from scapy.layers.inet import IP
        from scapy.utils import rdpcap
    except ImportError:
        print("Error: scapy is not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)

    client = DispatcherClient(args.server, verify_tls=not args.no_verify_tls)

    print(f"Reading {args.pcap} …")
    try:
        packets = rdpcap(args.pcap)
    except Exception as e:
        print(f"Error reading pcap: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  {len(packets)} packets read.\n")

    # Group unique source IPs so we fetch executor info once per IP.
    ip_packets = [(pkt, pkt.time) for pkt in packets if IP in pkt]
    if not ip_packets:
        print("No IPv4 packets found.")
        sys.exit(0)

    # Collect executor + TESLA info per source IP.
    tesla_by_ip: dict = {}
    for pkt, _ in ip_packets:
        src_ip = pkt[IP].src
        if src_ip in tesla_by_ip:
            continue
        exec_info = client.executor_by_ip(src_ip, args.n)
        if exec_info is None:
            tesla_by_ip[src_ip] = None
            print(f"  [{src_ip}] no registered executor — skipping")
            continue
        exec_id = exec_info["executor_id"]
        tesla_info = client.executor_tesla(exec_id)
        if tesla_info is None:
            tesla_by_ip[src_ip] = None
            print(f"  [{src_ip}] executor {exec_id} has no TESLA params — skipping")
            continue
        # Attach measurement IDs from the by-ip response into the tesla dict
        # so verify_packet can iterate over them.
        tesla_info["measurement_ids"] = exec_info.get("measurement_ids", [])
        tesla_by_ip[src_ip] = tesla_info
        print(f"  [{src_ip}] executor={exec_id}  "
              f"delay={tesla_info['delay_sec']}s  "
              f"disclosed_epoch={tesla_info.get('disclosed_epoch', '—')}  "
              f"measurements={exec_info['measurement_ids']}")
    print()

    # Verify packets.
    col_w = 20
    header = (f"{'Timestamp':<28}  {'Src IP':<16}  {'Dst IP':<16}  "
              f"{'IPID':>6}  Matched measurement IDs")
    print(header)
    print("-" * len(header))

    total = verified = 0
    for pkt, pkt_time in ip_packets:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        tesla = tesla_by_ip.get(src_ip)
        if tesla is None:
            continue

        total += 1
        # Scapy timestamp is a float in seconds; convert to ns.
        pkt_ts_ns = int(float(pkt_time) * 1e9)
        raw_ip = bytes(ip_layer)
        ip_id = ip_layer.id

        matched = verify_packet(raw_ip, ip_id, pkt_ts_ns, tesla)
        if matched:
            verified += 1

        ts_str = f"{float(pkt_time):.6f}"
        matched_str = ", ".join(matched) if matched else "(none)"
        print(f"{ts_str:<28}  {src_ip:<16}  {ip_layer.dst:<16}  "
              f"0x{ip_id:04x}  {matched_str}")

    print("-" * len(header))
    print(f"\nResult: {verified}/{total} packets matched at least one measurement ID.")


if __name__ == "__main__":
    main()
