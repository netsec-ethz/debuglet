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

"""verify_pcap.py — offline TESLA packet verification tool (IPv4).

This is the reference implementation of Debuglet packet attribution. The
browser-side verifier in debuglet-website (src/lib/verify.ts) mirrors it
step for step; keep the two in sync.

Workflow
--------
1. Parse the capture locally (pcap and pcapng, stdlib only — no scapy).
2. For each source IP and capture second call the public, dated lookup
   GET /attribution/candidates?ip=<ip>&at=<RFC 3339 time>. It lists the runs
   active from that address within one epoch of the time, each with its
   executor, run ID and chain schedule {chain, k0, t0, interval,
   delay_epochs, chain_length, tag_spec} and disclosed_through (tau, the
   latest disclosed epoch), plus retained_from, before which the dispatcher
   holds no history. Then read k_tau with
   GET /attribution/keys?executor=<id>&chain=<chain>&from_epoch=tau&to_epoch=tau.
   Neither route needs an account. A dispatcher without them (404) is asked
   the deprecated routes instead: GET /executors/by-ip?ip=<ip>[&n=<n>] for
   the executor and the caller's own recent debuglet IDs, and
   GET /executors/<id>/tesla for the current chain only:
      anchor_key              – k_0 (base64), used for chain consistency checks
      anchor_timestamp_ns     – t_0, when epoch 0 started
      epoch_seconds           – epoch length I (delay_sec on older dispatchers)
      disclosure_delay_epochs – d, the key of epoch e is disclosed from t_0 + (e+d)*I
      disclosed_epoch         – tau, the latest epoch whose key is published
      disclosed_key           – k_tau (base64)
   Both are turned into that same schedule. A schedule with d < 2 (or none
   reported) is refused: see Disclosure timing.
4. For each IPv4 packet:
   a. Compute the epoch t from the packet timestamp. The candidates are t and
      t-1 only. Epoch 0 has no signing key: k_0 is the public anchor, so the
      executor never tags with it and epoch 0 is never a candidate; a packet
      from epoch 0 that matches no later epoch is reported as carrying no
      attribution tag.
   b. For each candidate e, derive k_e = H^(tau-e)(k_tau) [hash forward in
      the backward chain], but only if k_e was still secret when the packet
      was captured (see Disclosure timing).
   c. Verify chain consistency: H^t(k_t) == k_0.
   d. For each candidate debuglet ID derive the per-measurement key:
          ak = HKDF-SHA256(secret=k_t, info=debuglet_id)
      and check the tag stored in the IP-ID field: SipHash-2-4, which the
      eBPF tagger and the pure-Go fallback compute alike.
5. Report which debuglet IDs verified for each packet.

Disclosure timing
-----------------
TESLA's safety condition: a key may attribute a packet only if the key was
still secret when the packet was captured; anyone who has seen k_e can forge
tags for epoch e. The executor discloses k_e no earlier than the start of
epoch e+d, and the dispatcher rejects any disclosure before that (allowing
DISPATCHER_CLOCK_SKEW_S of executor clock lead). So k_e was secret until
    D_e = t_0 + (e+d)*I - DISPATCHER_CLOCK_SKEW_S
and a candidate epoch e is used only when capture_time + tolerance < D_e,
where tolerance (--clock-tolerance) bounds how far the capture host's clock
may lag true time. Candidate t-1 absorbs an executor clock that lags the
capture clock by up to one epoch; with d = 1 its key would already be public
during epoch t, so d must be at least 2, and d*I must exceed the tolerance
plus clock skew by a wide margin. The executor clock must not lead the capture
clock: epoch t+1 is not a candidate.

A key is also published no earlier than the first executor heartbeat after
every kernel tagger has moved off it, so disclosure lags t_0 + (e+d)*I by up
to one heartbeat interval, and longer while a refresh fails. "Not disclosed
yet" therefore means retry later, not that the packet failed to verify.

Usage
-----
    python3 tools/verify_pcap.py --pcap capture.pcap \\
        [--server http://localhost:9000] [--n 20] [--no-verify-tls] \\
        [--clock-tolerance 1.0]

Dependencies: none beyond the Python 3.9+ standard library.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

# ---------------------------------------------------------------------------
# Crypto helpers (pure Python, matching the Go implementation)
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_chain_forward(key: bytes, steps: int) -> bytes:
    """Hash key forward `steps` times: k_{t} = H^steps(key).

    In the backward chain k_i = H(k_{i+1}), so going from a later disclosed
    key k_tau to an earlier key k_t requires hashing forward (tau-t) times.
    """
    cur = key
    for _ in range(steps):
        cur = _sha256(cur)
    return cur


def verify_chain(anchor: bytes, key: bytes, t: int) -> bool:
    """Check H^t(key) == anchor (k_0)."""
    return hmac.compare_digest(hash_chain_forward(key, t), anchor)


def hkdf_sha256(secret: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 with an empty salt, matching golang.org/x/crypto/hkdf.

    Go's hkdf.New(sha256.New, secret, nil, info) substitutes a zero-filled
    salt of one hash length for a nil salt, so extract uses a 32-byte zero
    HMAC key.
    """
    # Extract
    prk = hmac.new(bytes(32), secret, hashlib.sha256).digest()
    # Expand
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


_M64 = 0xFFFFFFFFFFFFFFFF


def siphash24(k0: int, k1: int, data: bytes) -> int:
    """SipHash-2-4, matching the BPF tagger's 64-byte-capped implementation.

    tagger.c hashes only whole 8-byte blocks (at most 8 of them) and folds
    the *capped* length into the finalisation word, so trailing bytes beyond
    the last full block never enter the state. tesla.ComputeTag in Go does the
    same; this function reproduces both.
    """

    def rotl(v: int, n: int) -> int:
        return ((v << n) | (v >> (64 - n))) & _M64

    def sipround(v0, v1, v2, v3):
        v0 = (v0 + v1) & _M64
        v1 = rotl(v1, 13) ^ v0
        v0 = rotl(v0, 32)
        v2 = (v2 + v3) & _M64
        v3 = rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & _M64
        v3 = rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & _M64
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

    for i in range(blocks):
        m = struct.unpack_from("<Q", data, i * 8)[0]
        v3 ^= m
        for _ in range(2):
            v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m

    b = (cap << 56) & _M64
    v3 ^= b
    for _ in range(2):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFF


def compute_bpf_tag(ak: bytes, payload: bytes) -> int:
    """16-bit SipHash-2-4 tag — the eBPF tagger. Matches tesla.ComputeTag in Go."""
    k0 = struct.unpack_from("<Q", ak, 0)[0]
    k1 = struct.unpack_from("<Q", ak, 8)[0]
    return siphash24(k0, k1, payload[:64])


def canonicalize_ipv4(raw: bytes) -> bytes:
    """Zero the IPID (bytes 4-5) and header checksum (bytes 10-11) fields.

    Both taggers hash the packet in this canonical form so a verifier can
    reproduce the hash input without knowing the pre-tag IPID or checksum.
    """
    if len(raw) < 20 or (raw[0] >> 4) != 4:
        return raw
    pkt = bytearray(raw)
    pkt[4] = pkt[5] = 0  # IPID
    pkt[10] = pkt[11] = 0  # header checksum
    return bytes(pkt)


# ---------------------------------------------------------------------------
# Capture parsing (pcap + pcapng, standard library only)
# ---------------------------------------------------------------------------

# Link types we know how to strip down to an IPv4 header.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_IPV4 = 228


class Packet:
    __slots__ = ("ts_ns", "ip")

    def __init__(self, ts_ns: int, ip: bytes):
        self.ts_ns = ts_ns
        self.ip = ip

    @property
    def src(self) -> str:
        return ".".join(str(b) for b in self.ip[12:16])

    @property
    def dst(self) -> str:
        return ".".join(str(b) for b in self.ip[16:20])

    @property
    def ip_id(self) -> int:
        return struct.unpack_from(">H", self.ip, 4)[0]


def extract_ipv4(linktype: int, frame: bytes) -> Optional[bytes]:
    """Strip the link-layer header and return the IPv4 packet, or None.

    The returned slice is trimmed to the IPv4 total-length field, which is
    what the tagger hashed (tagger.c uses skb->len minus the L2 offset, and
    egress frames carry no L2 padding at the capture point).
    """
    off = 0
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        # Walk 802.1Q / 802.1ad VLAN tags.
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
            ethertype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        if ethertype != 0x0800:
            return None
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        off = 0
    elif linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        # 4-byte host-endian (NULL) / big-endian (LOOP) address family.
        if len(frame) < 4:
            return None
        off = 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        if struct.unpack_from(">H", frame, 14)[0] != 0x0800:
            return None
        off = 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        if struct.unpack_from(">H", frame, 0)[0] != 0x0800:
            return None
        off = 20
    else:
        return None

    pkt = frame[off:]
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    total = struct.unpack_from(">H", pkt, 2)[0]
    if 20 <= total <= len(pkt):
        pkt = pkt[:total]
    return pkt


def read_pcap(data: bytes) -> list:
    """Parse a classic libpcap file."""
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_mult = "<", 1_000  # microseconds
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_mult = ">", 1_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_mult = "<", 1  # nanoseconds
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_mult = ">", 1
    else:
        raise ValueError("not a pcap file")

    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    out = []
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_frac, caplen, _origlen = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if pos + caplen > len(data):
            break
        frame = data[pos : pos + caplen]
        pos += caplen
        ip = extract_ipv4(linktype, frame)
        if ip is not None:
            out.append(Packet(ts_sec * 1_000_000_000 + ts_frac * ts_mult, ip))
    return out


def read_pcapng(data: bytes) -> list:
    """Parse a pcapng file (Section Header / Interface Description / EPB)."""
    out = []
    pos = 0
    endian = "<"
    # interface id -> (linktype, timestamp resolution divisor)
    ifaces: list = []
    while pos + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, pos)[0]
        if block_type == 0x0A0D0D0A:  # Section Header Block
            bom = struct.unpack_from(">I", data, pos + 8)[0]
            endian = "<" if bom == 0x4D3C2B1A else ">"
            ifaces = []
            block_type = 0x0A0D0D0A
        block_len = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if block_len < 12 or pos + block_len > len(data):
            break
        body = data[pos + 8 : pos + block_len - 4]

        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            # if_tsresol option (code 9); default 10^-6 s.
            tsresol = 6
            opos = 8
            while opos + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, opos)
                if code == 0:
                    break
                val = body[opos + 4 : opos + 4 + olen]
                if code == 9 and olen >= 1:
                    tsresol = val[0]
                opos += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, tsresol))
        elif block_type == 0x00000006:  # Enhanced Packet Block
            iface_id, ts_hi, ts_lo, caplen, _origlen = struct.unpack_from(
                endian + "IIIII", body, 0
            )
            frame = body[20 : 20 + caplen]
            linktype, tsresol = ifaces[iface_id] if iface_id < len(ifaces) else (1, 6)
            raw_ts = (ts_hi << 32) | ts_lo
            if tsresol & 0x80:  # power of two
                ts_ns = raw_ts * 1_000_000_000 // (1 << (tsresol & 0x7F))
            else:
                ts_ns = raw_ts * (10 ** (9 - tsresol)) if tsresol <= 9 else raw_ts // (
                    10 ** (tsresol - 9)
                )
            ip = extract_ipv4(linktype, frame)
            if ip is not None:
                out.append(Packet(ts_ns, ip))

        pos += block_len
    return out


def read_capture(path: str) -> list:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(data)
    return read_pcap(data)


# ---------------------------------------------------------------------------
# Dispatcher API helpers
# ---------------------------------------------------------------------------


class DispatcherClient:
    def __init__(self, server: str, verify_tls: bool = True):
        self.server = server.rstrip("/")
        self.ctx = None
        if not verify_tls:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self._executor_cache: dict = {}
        self._tesla_cache: dict = {}
        self._candidate_cache: dict = {}
        self._key_cache: dict = {}
        # None until the first dated lookup shows whether the dispatcher
        # serves the attribution routes.
        self.attribution_routes: Optional[bool] = None

    def _get(self, path: str, **params) -> dict:
        url = f"{self.server}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        for attempt in range(ATTRIBUTION_RETRIES + 1):
            try:
                with urllib.request.urlopen(req, context=self.ctx, timeout=20) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as e:
                # The public attribution routes are rate-limited per address.
                if e.code != 429 or attempt == ATTRIBUTION_RETRIES:
                    raise
                try:
                    wait = float(e.headers.get("Retry-After") or 1)
                except ValueError:
                    wait = 1.0
                time.sleep(min(max(wait, 0.1), 30.0))
        raise AssertionError("unreachable")

    def executor_by_ip(self, ip: str, n: int = 0) -> Optional[dict]:
        """Deprecated GET /executors/by-ip?ip=<ip>[&n=<n>] → {executor_id, debuglet_ids}."""
        cache_key = (ip, n)
        if cache_key in self._executor_cache:
            return self._executor_cache[cache_key]
        params = {"ip": ip}
        if n > 0:
            params["n"] = n
        try:
            result = self._get("/executors/by-ip", **params)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        self._executor_cache[cache_key] = result
        return result

    def executor_tesla(self, executor_id: str) -> Optional[dict]:
        """Deprecated GET /executors/<id>/tesla → the TESLA key schedule parameters."""
        if executor_id in self._tesla_cache:
            return self._tesla_cache[executor_id]
        try:
            result = self._get(f"/executors/{urllib.parse.quote(executor_id)}/tesla")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        self._tesla_cache[executor_id] = result
        return result

    def attribution_candidates(self, ip: str, at_ns: int) -> Optional[dict]:
        """GET /attribution/candidates for ip at the capture second of at_ns.

        Every epoch is at least a second long, so one lookup per second
        covers every run active within one epoch of any packet in it. None
        means the dispatcher does not serve the route.
        """
        second = at_ns // 1_000_000_000
        cache_key = (ip, second)
        if cache_key in self._candidate_cache:
            return self._candidate_cache[cache_key]
        at = datetime.datetime.fromtimestamp(second, datetime.timezone.utc)
        try:
            result = self._get("/attribution/candidates", ip=ip,
                               at=at.strftime("%Y-%m-%dT%H:%M:%SZ"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.attribution_routes = False
                return None
            raise
        self.attribution_routes = True
        self._candidate_cache[cache_key] = result
        return result

    def attribution_key(self, executor_id: str, chain: str, epoch: int) -> Optional[bytes]:
        """The disclosed key of one epoch from GET /attribution/keys, or None."""
        cache_key = (executor_id, chain, epoch)
        if cache_key in self._key_cache:
            return self._key_cache[cache_key]
        try:
            page = self._get("/attribution/keys", executor=executor_id, chain=chain,
                             from_epoch=epoch, to_epoch=epoch)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        key = None
        for item in page.get("keys") or []:
            if int(item["epoch"]) == epoch:
                key = base64.b64decode(item["key"])
        self._key_cache[cache_key] = key
        return key

    def lookup(self, ip: str, ts_ns: int, n: int = 0):
        """The schedules and debuglet IDs to check a packet from ip at ts_ns.

        Returns (groups, reason): groups is [(tesla, ids)] with tesla in the
        shape of the deprecated /executors/<id>/tesla answer, one per
        (executor, chain) with the run IDs of that chain; reason explains an
        empty list. The dated attribution routes are preferred, the
        deprecated ones are the fallback of a dispatcher without them.
        """
        if self.attribution_routes is not False:
            doc = self.attribution_candidates(ip, ts_ns)
            if doc is not None:
                return self._dated_groups(doc, ts_ns)
        exec_info = self.executor_by_ip(ip, n)
        if exec_info is None:
            return [], "no registered executor"
        exec_id = exec_info["executor_id"]
        tesla_info = self.executor_tesla(exec_id)
        if tesla_info is None:
            return [], f"executor {exec_id} has no TESLA params"
        tesla_info = dict(tesla_info, executor_id=exec_id)
        return [(tesla_info, exec_info.get("debuglet_ids") or [])], ""

    def _dated_groups(self, doc: dict, ts_ns: int):
        candidates = doc.get("candidates") or []
        if not candidates:
            retained = _parse_time_ns(doc.get("retained_from"))
            if retained is not None and ts_ns < retained:
                return [], ("missing: the dispatcher retains no attribution "
                            "history for that time")
            return [], "no run was active from that address at that time"
        groups: dict = {}
        for c in candidates:
            s = c["schedule"]
            group = (c["executor_id"], s["chain"])
            if group not in groups:
                tau = int(c.get("disclosed_through") or 0)
                key = self.attribution_key(c["executor_id"], s["chain"], tau) if tau > 0 else None
                groups[group] = ({
                    "executor_id": c["executor_id"],
                    "anchor_key": s["k0"],
                    "anchor_timestamp_ns": int(s["t0"]),
                    "epoch_seconds": int(s["interval"]),
                    "disclosure_delay_epochs": int(s["delay_epochs"]),
                    "disclosed_epoch": tau if key is not None else 0,
                    "disclosed_key": base64.b64encode(key).decode() if key is not None else "",
                }, [])
            if c["run_id"] not in groups[group][1]:
                groups[group][1].append(c["run_id"])
        if doc.get("truncated"):
            print(f"  warning: more than {len(candidates)} runs were active; "
                  "only the listed ones are checked", file=sys.stderr)
        return list(groups.values()), ""


# ATTRIBUTION_RETRIES bounds the retries of a rate-limited request.
ATTRIBUTION_RETRIES = 5


def _parse_time_ns(value) -> Optional[int]:
    """Unix nanoseconds of an RFC 3339 time, at microsecond precision."""
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    # datetime reads at most six fractional digits.
    if "." in text:
        head, rest = text.split(".", 1)
        digits = ""
        while rest and rest[0].isdigit():
            digits, rest = digits + rest[0], rest[1:]
        text = f"{head}.{digits[:6].ljust(6, '0')}{rest}"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1000


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

# The shortest disclosure delay d, in epochs, this tool accepts. Candidate
# epoch t-1 is tried for a packet of epoch t; with d = 1 its key is already
# public during epoch t. Matches tesla.MinDisclosureDelay.
MIN_DISCLOSURE_DELAY = 2

# The executor clock lead over the dispatcher's that the dispatcher tolerates
# when it bounds a disclosure (clockSkew in internal/dispatcher/tag). A key
# may therefore have been accepted this much before its scheduled time.
DISPATCHER_CLOCK_SKEW_S = 5

# Default bound on how far the capture host's clock may lag true time.
DEFAULT_CLOCK_TOLERANCE_S = 1.0


def epoch_seconds(tesla: dict) -> int:
    """The epoch length I; older dispatchers name it only delay_sec."""
    return int(tesla.get("epoch_seconds", tesla.get("delay_sec", 0)))


def secret_until_ns(epoch: int, anchor_ns: int, delay_ns: int, d: int) -> int:
    """The earliest instant the key of epoch could have become public."""
    return anchor_ns + (epoch + d) * delay_ns - DISPATCHER_CLOCK_SKEW_S * 1_000_000_000


def epoch_of(ts_ns: int, anchor_ns: int, delay_ns: int) -> int:
    """Epoch index containing ts_ns, matching KeySchedule.epochOf."""
    elapsed = ts_ns - anchor_ns
    if elapsed < 0:
        return 0
    return elapsed // delay_ns


def verify_packet(pkt: Packet, tesla: dict, debuglet_ids: list,
                  tolerance_ns: int = int(DEFAULT_CLOCK_TOLERANCE_S * 1_000_000_000)):
    """Verify one packet.

    Returns (matches, reason): matches is [(debuglet_id, epoch, tagger)] for
    every ID whose tag reproduces, and reason explains an empty result.
    tolerance_ns bounds how far the capture clock may lag true time.
    """
    anchor_ns = int(tesla["anchor_timestamp_ns"])
    delay_ns = epoch_seconds(tesla) * 1_000_000_000
    if delay_ns <= 0:
        return [], "the executor reports a zero-length epoch"
    d = int(tesla.get("disclosure_delay_epochs") or 0)
    if d < MIN_DISCLOSURE_DELAY:
        return [], (f"the executor's disclosure delay is {d or 'not reported'}"
                    f"{' epochs' if d else ''}; at least {MIN_DISCLOSURE_DELAY} are "
                    f"needed, since otherwise a disclosed key could forge its tags")

    disclosed_epoch = int(tesla["disclosed_epoch"])
    disclosed_key_b64 = tesla.get("disclosed_key") or ""
    if not disclosed_key_b64:
        return [], "the executor has not disclosed any key yet"

    disclosed_key = base64.b64decode(disclosed_key_b64)
    anchor_b64 = tesla.get("anchor_key") or ""
    anchor_key = base64.b64decode(anchor_b64) if anchor_b64 else None

    # Confirm the disclosed key really belongs to the published chain:
    # H^tau(k_tau) must equal k_0.
    if anchor_key is None:
        return [], "the executor has published no anchor key to check the chain against"
    if not verify_chain(anchor_key, disclosed_key, disclosed_epoch):
        return [], "the disclosed key does not hash back to the published anchor"

    pkt_epoch = epoch_of(pkt.ts_ns, anchor_ns, delay_ns)
    if pkt_epoch > disclosed_epoch:
        gap = pkt_epoch - disclosed_epoch
        if gap <= d + 1:
            due_ns = anchor_ns + (pkt_epoch + d) * delay_ns
            due = datetime.datetime.fromtimestamp(due_ns / 1e9, datetime.timezone.utc)
            return [], (f"the key for epoch {pkt_epoch} is not disclosed yet — it is "
                        f"due at {due.isoformat(timespec='seconds')} ({due_ns} ns), "
                        f"{d} epochs after its own")
        return [], (f"no key is disclosed for epoch {pkt_epoch} (latest is "
                    f"{disclosed_epoch}); the executor restarted after the capture, "
                    f"or its key schedule ran out")
    if not debuglet_ids:
        return [], "no recent debuglets are recorded for this executor"

    canonical = canonicalize_ipv4(pkt.ip)
    tag = pkt.ip_id

    matched = []
    seen = set()
    too_late = False
    # Tolerate an executor clock up to one epoch behind the capture clock.
    # Epoch 0 is never a candidate: a tag derived from the public anchor k_0
    # proves nothing. A key that may have been public when the packet was
    # captured proves nothing either.
    for epoch in (pkt_epoch, pkt_epoch - 1):
        if epoch < 1 or epoch > disclosed_epoch:
            continue
        if pkt.ts_ns + tolerance_ns >= secret_until_ns(epoch, anchor_ns, delay_ns, d):
            too_late = True
            continue
        chain_key = hash_chain_forward(disclosed_key, disclosed_epoch - epoch)
        for mid in debuglet_ids:
            if mid in seen:
                continue
            ak = hkdf_sha256(chain_key, mid.encode())
            if compute_bpf_tag(ak, canonical) == tag:
                matched.append((mid, epoch, "siphash"))
                seen.add(mid)
    if not matched:
        if pkt_epoch < 1:
            return [], ("no signing key in epoch 0: packets sent during the "
                        "executor's first epoch carry no attribution tag")
        if too_late:
            return [], ("no candidate key was still secret when the packet was "
                        "captured, so its tag cannot be attributed")
        return [], "no recent debuglet on this executor produces this tag"
    return matched, ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Verify IPv4 packet authentication tags in a capture "
        "using the dispatcher TESLA APIs"
    )
    parser.add_argument(
        "--server",
        default="http://localhost:9000",
        help="Dispatcher API base URL (default: http://localhost:9000)",
    )
    parser.add_argument("--pcap", required=True, help="Path to the pcap/pcapng file")
    parser.add_argument(
        "--n",
        type=int,
        default=0,
        help="Max recent debuglet IDs to fetch per executor (default: server default = 10)",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS certificate verification (for local testing)",
    )
    parser.add_argument(
        "--clock-tolerance",
        type=float,
        default=DEFAULT_CLOCK_TOLERANCE_S,
        help="Seconds the capture host's clock may lag true time; a key is used "
        "only if it was still secret at capture time plus this "
        f"(default: {DEFAULT_CLOCK_TOLERANCE_S})",
    )
    args = parser.parse_args()
    if args.clock_tolerance < 0:
        parser.error("--clock-tolerance must not be negative")
    tolerance_ns = int(args.clock_tolerance * 1_000_000_000)

    client = DispatcherClient(args.server, verify_tls=not args.no_verify_tls)

    print(f"Reading {args.pcap} …")
    try:
        packets = read_capture(args.pcap)
    except Exception as e:
        print(f"Error reading capture: {e}", file=sys.stderr)
        sys.exit(1)

    if not packets:
        print("No IPv4 packets found.")
        sys.exit(0)
    print(f"  {len(packets)} IPv4 packets read.\n")

    header = (
        f"{'Timestamp (ns)':<22}  {'Src IP':<16}  {'Dst IP':<16}  "
        f"{'IPID':>6}  {'Epoch':>6}  Matched debuglet IDs"
    )
    print(header)
    print("-" * len(header))

    total = verified = 0
    announced: set = set()
    for pkt in packets:
        groups, reason = client.lookup(pkt.src, pkt.ts_ns, args.n)
        for tesla, ids in groups:
            key = (pkt.src, tesla["executor_id"], tesla["anchor_key"])
            if key not in announced:
                announced.add(key)
                print(
                    f"  [{pkt.src}] executor={tesla['executor_id']}  "
                    f"epoch={epoch_seconds(tesla)}s  "
                    f"disclosure_delay={tesla.get('disclosure_delay_epochs', 0)} epochs  "
                    f"disclosed_epoch={tesla.get('disclosed_epoch', '—')}  "
                    f"debuglets={ids}"
                )
        if not groups and client.attribution_routes is not True and reason == "no registered executor":
            continue  # the deprecated lookup knows no executor for this address
        total += 1
        matched, epoch = [], None
        for tesla, ids in groups:
            found, why = verify_packet(pkt, tesla, ids, tolerance_ns)
            matched.extend(found)
            if found or not reason:
                reason = why
            if epoch is None or found:
                epoch = epoch_of(
                    pkt.ts_ns,
                    int(tesla["anchor_timestamp_ns"]),
                    epoch_seconds(tesla) * 1_000_000_000,
                )
        if matched:
            verified += 1
            reason = ""

        matched_str = (
            ", ".join(f"{m} (epoch {e}, {t})" for m, e, t in matched)
            if matched
            else f"— {reason}"
        )
        epoch_str = "—" if epoch is None else str(epoch)
        print(
            f"{pkt.ts_ns:<22}  {pkt.src:<16}  {pkt.dst:<16}  "
            f"0x{pkt.ip_id:04x}  {epoch_str:>6}  {matched_str}"
        )

    print("-" * len(header))
    print(f"\nResult: {verified}/{total} packets matched at least one debuglet ID.")
    sys.exit(0 if verified else 2)


if __name__ == "__main__":
    main()
