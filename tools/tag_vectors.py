#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich

"""tag_vectors.py — independent reference for the debuglet-tag-v1 packet tag.

This file is written from docs/tag-spec.md alone. It shares no code with the
Go tagger (internal/executor/tagger), the eBPF tagger (tagger.c) or the
capture verifier (tools/verify_pcap.py), and it uses only the Python standard
library. Its SipHash-2-4 is checked against the reference vectors published
with the SipHash paper (Aumasson and Bernstein, 2012) before any tag vector is
produced.

    python3 tools/tag_vectors.py            write testdata/tag-vectors-v1.json
    python3 tools/tag_vectors.py --check    fail if the committed file differs

The vector file is the shared known-answer fixture: Go tests, the kernel test
of tagger.c and tools/verify_pcap.py all read it.
"""

import argparse
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

SPEC = "debuglet-tag-v1"
OUT = Path(__file__).resolve().parents[1] / "testdata" / "tag-vectors-v1.json"

MASK = (1 << 64) - 1

# SipHash-2-4 reference outputs for key 00 01 .. 0f and message 00 01 .. (n-1),
# n = 0 .. 63, as the 8 output bytes (little-endian encoding of the 64-bit
# result). From the vectors of the SipHash reference implementation; entry 15
# is also the worked example in Appendix A of the paper (a129ca6149be45e5).
SIPHASH_REFERENCE = """
310e0edd47db6f72 fd67dc93c539f874 5a4fa9d909806c0d 2d7efbd796666785
b7877127e09427cf 8da699cd64557618 cee3fe586e46c9cb 37d1018bf50002ab
6224939a79f5f593 b0e4a90bdf82009e f3b9dd94c5bb5d7a a7ad6b22462fb3f4
fbe50e86bc8f1e75 903d84c02756ea14 eef27a8e90ca23f7 e545be4961ca29a1
db9bc2577fcc2a3f 9447be2cf5e99a69 9cd38d96f0b3c14b bd6179a71dc96dbb
98eea21af25cd6be c7673b2eb0cbf2d0 883ea3e395675393 c8ce5ccd8c030ca8
94af49f6c650adb8 eab8858ade92e1bc f315bb5bb835d817 adcf6b0763612e2f
a5c91da7acaa4dde 716595876650a2a6 28ef495c53a387ad 42c341d8fa92d832
ce7cf2722f512771 e37859f94623f3a7 381205bb1ab0e012 ae97a10fd434e015
b4a31508beff4d31 81396229f0907902 4d0cf49ee5d4dcca 5c73336a76d8bf9a
d0a704536ba93e0e 925958fcd6420cad a915c29bc8067318 952b79f3bc0aa6d4
f21df2e41d4535f9 87577519048f53a9 10a56cf5dfcd9adb eb75095ccd986cd0
51a9cb9ecba312e6 96afadfc2ce666c7 72fe52975a4364ee 5a1645b276d592a1
b274cb8ebf87870a 6f9bb4203de7b381 eaecb2a30b22a87f 9924a43cc1315724
bd838d3aafbf8db7 0b1a2a3265d51aea 135079a3231ce660 932b2846e4d70666
e1915f5cb1eca46c f325965ca16d629f 575ff28e60381be5 724506eb4c328a95
""".split()


def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK


def _sipround(v):
    v0, v1, v2, v3 = v
    v0 = (v0 + v1) & MASK
    v1 = _rotl(v1, 13) ^ v0
    v0 = _rotl(v0, 32)
    v2 = (v2 + v3) & MASK
    v3 = _rotl(v3, 16) ^ v2
    v0 = (v0 + v3) & MASK
    v3 = _rotl(v3, 21) ^ v0
    v2 = (v2 + v1) & MASK
    v1 = _rotl(v1, 17) ^ v2
    v2 = _rotl(v2, 32)
    return [v0, v1, v2, v3]


def siphash24(key: bytes, msg: bytes) -> bytes:
    """Standard SipHash-2-4; returns the 8-byte little-endian output."""
    assert len(key) == 16
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D,
         k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]
    # Pad per the paper: the final word carries the trailing bytes and
    # (len mod 256) in its most significant byte.
    tail = len(msg) % 8
    padded = msg + bytes(7 - tail) + bytes([len(msg) & 0xFF])
    for i in range(0, len(padded), 8):
        m = struct.unpack_from("<Q", padded, i)[0]
        v[3] ^= m
        v = _sipround(_sipround(v))
        v[0] ^= m
    v[2] ^= 0xFF
    for _ in range(4):
        v = _sipround(v)
    return struct.pack("<Q", v[0] ^ v[1] ^ v[2] ^ v[3])


def check_siphash_reference():
    key = bytes(range(16))
    if len(SIPHASH_REFERENCE) != 64:
        raise SystemExit("SipHash reference table must have 64 entries")
    for n, want in enumerate(SIPHASH_REFERENCE):
        got = siphash24(key, bytes(range(n))).hex()
        if got != want:
            raise SystemExit(f"SipHash-2-4 reference vector {n}: got {got}, want {want}")


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 with the salt absent (HashLen zero bytes)."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block = b"", b""
    for i in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


def ipv4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# Checksum offset inside the transport header, per IP protocol number.
L4_CHECKSUM = {1: 2, 6: 16, 17: 6}


def hash_input(packet: bytes):
    """Return (input bytes, None) or (None, unsupported reason) per spec §3."""
    if len(packet) < 1:
        return None, "too_short"
    version = packet[0] >> 4
    if version == 6:
        return None, "ipv6"
    if version != 4:
        return None, "not_ipv4"
    if len(packet) < 20:
        return None, "too_short"
    ihl = (packet[0] & 0x0F) * 4
    total = (packet[2] << 8) | packet[3]
    if ihl < 20 or total < ihl:
        return None, "malformed"
    if ((packet[6] << 8) | packet[7]) & 0x3FFF:
        return None, "fragment"
    n = min(64, total)
    if len(packet) < n:
        return None, "too_short"
    buf = bytearray(packet[:n])
    for i in (1, 4, 5, 6, 7, 8, 10, 11):
        buf[i] = 0
    for i in range(20, min(ihl, n)):
        buf[i] = 0
    if buf[9] in L4_CHECKSUM:
        c = ihl + L4_CHECKSUM[buf[9]]
        for i in (c, c + 1):
            if i < n:
                buf[i] = 0
    return bytes(buf), None


def tag_of(ak: bytes, data: bytes) -> int:
    out = siphash24(ak[:16], data)
    return out[0] | (out[1] << 8)  # low 16 bits of the 64-bit result


def tagged_packet(packet: bytes, tag: int) -> bytes:
    pkt = bytearray(packet)
    pkt[4], pkt[5] = tag >> 8, tag & 0xFF
    pkt[6] |= 0x40  # DF
    ihl = (pkt[0] & 0x0F) * 4
    pkt[10] = pkt[11] = 0
    c = ipv4_checksum(bytes(pkt[:ihl]))
    pkt[10], pkt[11] = c >> 8, c & 0xFF
    return bytes(pkt)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

SRC = bytes([192, 0, 2, 10])
DST = bytes([198, 51, 100, 20])


def ipv4(proto, l4, *, tos=0, ident=0x1234, flags=0, ttl=64, options=b"", src=SRC, dst=DST,
         total=None, checksum=None):
    ihl = 20 + len(options)
    assert ihl % 4 == 0
    tot = ihl + len(l4) if total is None else total
    hdr = bytearray(struct.pack(">BBHHHBBH4s4s", 0x40 | (ihl // 4), tos, tot, ident, flags,
                                ttl, proto, 0, src, dst)) + options
    c = ipv4_checksum(bytes(hdr)) if checksum is None else checksum
    hdr[10], hdr[11] = c >> 8, c & 0xFF
    return bytes(hdr) + l4


def payload(n, seed=0):
    return bytes((i * 29 + seed * 7 + 3) & 0xFF for i in range(n))


def udp(n, sport=40000, dport=33434, csum=0xBEEF, seed=0):
    return struct.pack(">HHHH", sport, dport, 8 + n, csum) + payload(n, seed)


def tcp(n, csum=0x5A5A, seed=0):
    return struct.pack(">HHIIBBHHH", 40001, 443, 0x01020304, 0x0A0B0C0D, 0x50, 0x18, 0xFFFF,
                       csum, 0) + payload(n, seed)


def icmp(n, csum=0x7777, seed=0):
    return struct.pack(">BBHHH", 8, 0, csum, 0x4242, 1) + payload(n, seed)


# ---------------------------------------------------------------------------
# Vector set
# ---------------------------------------------------------------------------

# The TESLA chain of the vectors: k_L = SEED, k_i = SHA-256(k_{i+1}), L = 4.
SEED = hashlib.sha256(b"debuglet-tag-v1 vector seed").digest()
CHAIN_LENGTH = 4
MEASUREMENT = "5f0c7a3e-2b1d-4c8e-9a6f-0d3b2e1c4a57"


def chain():
    keys = [None] * (CHAIN_LENGTH + 1)
    keys[CHAIN_LENGTH] = SEED
    for i in range(CHAIN_LENGTH - 1, -1, -1):
        keys[i] = hashlib.sha256(keys[i + 1]).digest()
    return keys


def cases():
    """(name, description, packet) in a fixed order."""
    out = []

    def add(name, description, packet):
        out.append((name, description, packet))

    # Lengths around the 8-byte block and the 64-byte input boundary. Total
    # length 20 is a bare header; 28 is a bare UDP header.
    for total in (20, 21, 27, 28, 29, 35, 36, 55, 56, 57, 63, 64, 65, 72, 100, 576, 1400):
        if total == 20:
            add("udp_total_20", "bare IPv4 header, protocol UDP, no transport bytes",
                ipv4(17, b""))
        elif total < 28:
            add(f"udp_total_{total}", f"total length {total}: truncated UDP header",
                ipv4(17, udp(0)[: total - 20]))
        else:
            add(f"udp_total_{total}", f"IPv4/UDP, total length {total}",
                ipv4(17, udp(total - 28)))
    for total in (40, 41, 64, 65, 1500):
        add(f"tcp_total_{total}", f"IPv4/TCP, total length {total}", ipv4(6, tcp(total - 40)))
    for total in (28, 60, 84):
        add(f"icmp_total_{total}", f"IPv4/ICMP echo, total length {total}",
            ipv4(1, icmp(total - 28)))
    add("gre_total_60", "IPv4/GRE (47): no transport checksum is zeroed", ipv4(47, payload(40)))

    base = ipv4(17, udp(60))
    add("udp_base", "reference UDP packet for the invariance and alteration cases", base)
    add("udp_mutable_rewritten",
        "udp_base after routing: TTL, TOS (DSCP+ECN), IP-ID and header checksum changed; same tag",
        ipv4(17, udp(60), ttl=3, tos=0xB9, ident=0xFFFF))
    add("udp_df_set", "udp_base with DF already set by the sender; same tag",
        ipv4(17, udp(60), flags=0x4000))
    add("udp_l4_checksum_rewritten",
        "udp_base with a different UDP checksum (offload or NAT fix-up); same tag",
        ipv4(17, udp(60, csum=0x0000)))
    add("udp_payload_changed_inside",
        "udp_base with one payload byte inside the first 64 bytes changed; different tag",
        ipv4(17, udp(60)[:40] + bytes([udp(60)[40] ^ 1]) + udp(60)[41:]))
    add("udp_payload_changed_outside",
        "udp_base with a byte after the first 64 bytes changed; same tag (not authenticated)",
        ipv4(17, udp(60)[:60] + bytes([udp(60)[60] ^ 1]) + udp(60)[61:]))
    add("udp_port_changed", "udp_base with another destination port (as after NAPT); different tag",
        ipv4(17, udp(60, dport=33435)))
    add("udp_source_changed", "udp_base with another source address (as after NAT); different tag",
        ipv4(17, udp(60), src=bytes([203, 0, 113, 7])))

    rr = bytes([7, 11, 4]) + bytes([10, 0, 0, 1]) + bytes(4) + b"\x00"  # record route + EOL
    add("udp_options_record_route",
        "IHL 8 with a record-route option; option bytes are zeroed, L4 checksum at IHL+6",
        ipv4(17, udp(40), options=rr))
    add("udp_options_rewritten",
        "udp_options_record_route after a router filled the next slot; same tag",
        ipv4(17, udp(40), options=bytes([7, 11, 8]) + bytes([10, 0, 0, 1, 10, 0, 0, 2]) + b"\x00"))
    add("tcp_options_max_ihl",
        "IHL 15 (40 option bytes): the TCP checksum lies beyond the 64-byte input",
        ipv4(6, tcp(20), options=bytes([1] * 39) + b"\x00"))

    add("unsupported_more_fragments", "first fragment (MF set): untagged, unsupported",
        ipv4(17, udp(60), flags=0x2000))
    add("unsupported_fragment_offset", "non-first fragment (offset 185): untagged, unsupported",
        ipv4(17, payload(80), flags=0x00B9))
    add("unsupported_ipv6", "IPv6 packet: not specified in v1",
        bytes([0x60, 0, 0, 0, 0, 8, 17, 64]) + bytes(32) + udp(0))
    add("unsupported_short_capture",
        "IPv4 total length 100 but only 40 bytes captured: fewer than the 64 input bytes",
        ipv4(17, udp(72))[:40])
    add("unsupported_header_only_capture", "19 bytes: shorter than an IPv4 header",
        ipv4(17, udp(72))[:19])
    add("unsupported_bad_ihl", "IHL 4: malformed", bytes([0x44]) + ipv4(17, udp(8))[1:])
    return out


# Expected relations between vectors: a transformation the spec absorbs keeps
# the tag, and one it authenticates changes it. build() asserts each.
RELATIONS = {
    "udp_mutable_rewritten": ("same_tag_as", "udp_base"),
    "udp_df_set": ("same_tag_as", "udp_base"),
    "udp_l4_checksum_rewritten": ("same_tag_as", "udp_base"),
    "udp_payload_changed_inside": ("tag_differs_from", "udp_base"),
    "udp_payload_changed_outside": ("same_tag_as", "udp_base"),
    "udp_port_changed": ("tag_differs_from", "udp_base"),
    "udp_source_changed": ("tag_differs_from", "udp_base"),
    "udp_options_rewritten": ("same_tag_as", "udp_options_record_route"),
}


def build():
    check_siphash_reference()
    keys = chain()
    epoch = 1
    ak = hkdf_sha256(keys[epoch], MEASUREMENT.encode())
    anchor_ak = hkdf_sha256(keys[0], MEASUREMENT.encode())
    vectors = []
    for name, description, packet in cases():
        data, reason = hash_input(packet)
        v = {"name": name, "description": description, "packet_hex": packet.hex()}
        if reason is not None:
            v["supported"] = False
            v["unsupported_reason"] = reason
        else:
            tag = tag_of(ak, data)
            v["supported"] = True
            v["input_hex"] = data.hex()
            v["siphash_hex"] = siphash24(ak[:16], data).hex()
            v["tag"] = tag
            v["tag_hex"] = f"{tag:04x}"
            v["tagged_packet_hex"] = tagged_packet(packet, tag).hex()
            v["anchor_tag"] = tag_of(anchor_ak, data)
        if name in RELATIONS:
            kind, ref = RELATIONS[name]
            v[kind] = ref
            other = next(o for o in vectors if o["name"] == ref)
            if (other["tag"] == v["tag"]) != (kind == "same_tag_as"):
                raise SystemExit(f"vector {name}: relation {kind} {ref} does not hold")
        vectors.append(v)
    return {
        "spec": SPEC,
        "generator": "tools/tag_vectors.py",
        "note": "Generated; do not edit. Regenerate with python3 tools/tag_vectors.py.",
        "siphash_reference": {
            "key_hex": bytes(range(16)).hex(),
            "message": "bytes 00 01 .. (n-1) for n = 0 .. 63",
            "outputs_hex": SIPHASH_REFERENCE,
        },
        "chain": {
            "hash": "SHA-256",
            "chain_length": CHAIN_LENGTH,
            "tail_hex": SEED.hex(),
            "keys_hex": [k.hex() for k in keys],
            "anchor_hex": keys[0].hex(),
            "signing_epoch": epoch,
        },
        "measurement_id": MEASUREMENT,
        "k_t_hex": keys[epoch].hex(),
        "ak_hex": ak.hex(),
        "anchor_ak_hex": anchor_ak.hex(),
        "vectors": vectors,
    }


def render(doc) -> str:
    return json.dumps(doc, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed vector file differs from a fresh generation")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    text = render(build())
    if args.check:
        if not args.out.exists() or args.out.read_text() != text:
            print(f"{args.out} is stale: run python3 tools/tag_vectors.py", file=sys.stderr)
            return 1
        print(f"{args.out} matches a fresh generation ({SPEC}).")
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
