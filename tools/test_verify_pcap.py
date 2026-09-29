"""The verification window of tools/verify_pcap.py: candidate epochs t and t-1
only, a disclosure delay of at least two epochs, and no key that may already
have been public when the packet was captured."""
import base64
import hashlib
from pathlib import Path
import struct
import sys
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_pcap as vp  # noqa: E402

SECOND = 1_000_000_000
ANCHOR_NS = 1_700_000_000 * SECOND
EPOCH_S = 10
LENGTH = 16
DEBUGLET = "00000000-0000-4000-8000-000000000001"


def chain(length=LENGTH):
    """keys[i] is k_i of a backward chain whose tail is a fixed seed."""
    keys = [b""] * (length + 1)
    keys[length] = bytes(range(32))
    for i in range(length - 1, -1, -1):
        keys[i] = hashlib.sha256(keys[i + 1]).digest()
    return keys


KEYS = chain()


def packet(ts_ns, epoch):
    """An IPv4 packet whose IP-ID carries the tag of epoch's key."""
    ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
                               bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])))
    ip += b"payload!"
    ak = vp.hkdf_sha256(KEYS[epoch], DEBUGLET.encode())
    tag = vp.compute_bpf_tag(ak, vp.canonicalize_ipv4(bytes(ip)))
    struct.pack_into(">H", ip, 4, tag)
    return vp.Packet(ts_ns, bytes(ip))


def schedule(disclosed, d=2, **extra):
    info = {
        "anchor_timestamp_ns": ANCHOR_NS,
        "epoch_seconds": EPOCH_S,
        "delay_sec": EPOCH_S,
        "anchor_key": base64.b64encode(KEYS[0]).decode(),
        "disclosed_epoch": disclosed,
        "disclosed_key": base64.b64encode(KEYS[disclosed]).decode(),
    }
    if d is not None:
        info["disclosure_delay_epochs"] = d
    info.update(extra)
    return info


def at(epoch, offset_s=0.0):
    return ANCHOR_NS + epoch * EPOCH_S * SECOND + int(offset_s * SECOND)


class VerificationWindowTest(unittest.TestCase):
    def verify(self, pkt, info):
        return vp.verify_packet(pkt, info, [DEBUGLET], 0)

    def test_current_and_previous_epoch_verify(self):
        for signed in (5, 4):
            matched, reason = self.verify(packet(at(5, 1), signed), schedule(9))
            self.assertEqual(matched, [(DEBUGLET, signed, "siphash")], reason)

    def test_next_epoch_is_not_a_candidate(self):
        matched, reason = self.verify(packet(at(5, 1), 6), schedule(9))
        self.assertEqual(matched, [])
        self.assertIn("produces this tag", reason)

    def test_key_public_at_capture_time_is_refused(self):
        # With d = 2, k_4 may be disclosed from the start of epoch 6, less the
        # dispatcher's skew allowance: a packet late in epoch 5 cannot prove
        # it was tagged before anyone else could compute k_4.
        late = at(6, -vp.DISPATCHER_CLOCK_SKEW_S + 1)
        matched, reason = self.verify(packet(late, 4), schedule(9))
        self.assertEqual(matched, [])
        self.assertIn("still secret", reason)
        # The current epoch's key is still secret at that time.
        matched, _ = self.verify(packet(late, 5), schedule(9))
        self.assertEqual(matched, [(DEBUGLET, 5, "siphash")])
        # The capture clock tolerance widens the refused interval.
        early = at(6, -vp.DISPATCHER_CLOCK_SKEW_S - 2)
        self.assertTrue(vp.verify_packet(packet(early, 4), schedule(9), [DEBUGLET], 0)[0])
        self.assertFalse(vp.verify_packet(packet(early, 4), schedule(9), [DEBUGLET], 3 * SECOND)[0])

    def test_short_or_missing_disclosure_delay_is_refused(self):
        for d in (None, 0, 1):
            matched, reason = self.verify(packet(at(5, 1), 5), schedule(9, d=d))
            self.assertEqual(matched, [], d)
            self.assertIn("at least 2", reason)

    def test_undisclosed_key_names_its_due_time(self):
        matched, reason = self.verify(packet(at(5, 1), 5), schedule(3))
        self.assertEqual(matched, [])
        self.assertIn(str(at(7)), reason)

    def test_older_dispatcher_names_only_delay_sec(self):
        info = schedule(9)
        del info["epoch_seconds"]
        matched, reason = self.verify(packet(at(5, 1), 5), info)
        self.assertEqual(matched, [(DEBUGLET, 5, "siphash")], reason)


class StubClient(vp.DispatcherClient):
    """A DispatcherClient answering from a routing table instead of HTTP."""

    def __init__(self, routes):
        super().__init__("http://dispatcher.test")
        self.routes = routes
        self.calls = []

    def _get(self, path, **params):
        self.calls.append((path, params))
        answer = self.routes.get(path)
        if answer is None:
            raise urllib.error.HTTPError(path, 404, "not found", {}, None)
        return answer(params) if callable(answer) else answer


def candidates(ts_ns, retained_from="2020-01-01T00:00:00Z", runs=(DEBUGLET,)):
    return {
        "ip": "192.0.2.1", "at": "", "retained_from": retained_from, "truncated": False,
        "candidates": [{
            "executor_id": "exec-1", "run_id": run, "active_from": "", "active_to": "",
            "ip_source": "observed", "disclosed_through": 9,
            "schedule": {"chain": "c1", "k0": base64.b64encode(KEYS[0]).decode(),
                         "t0": ANCHOR_NS, "interval": EPOCH_S, "delay_epochs": 2,
                         "chain_length": LENGTH, "tag_spec": 1},
        } for run in runs],
    }


class LookupTest(unittest.TestCase):
    def test_dated_routes_are_preferred(self):
        pkt = packet(at(5, 1), 5)
        stub = StubClient({
            "/attribution/candidates": lambda params: candidates(pkt.ts_ns),
            "/attribution/keys": {"executor_id": "exec-1", "chain": "c1", "next_epoch": None,
                                  "keys": [{"epoch": 9, "key": base64.b64encode(KEYS[9]).decode()}]},
        })
        groups, reason = stub.lookup("192.0.2.1", pkt.ts_ns)
        self.assertEqual(len(groups), 1, reason)
        tesla, ids = groups[0]
        self.assertEqual(ids, [DEBUGLET])
        matched, why = vp.verify_packet(pkt, tesla, ids, 0)
        self.assertEqual(matched, [(DEBUGLET, 5, "siphash")], why)
        self.assertNotIn("/executors/by-ip", [path for path, _ in stub.calls])
        keys = [params for path, params in stub.calls if path == "/attribution/keys"]
        self.assertEqual(keys, [{"executor": "exec-1", "chain": "c1", "from_epoch": 9, "to_epoch": 9}])
        # A second packet of the same second is answered from the cache.
        stub.lookup("192.0.2.1", pkt.ts_ns + 1)
        self.assertEqual(len(stub.calls), 2)

    def test_history_before_retained_from_is_missing(self):
        pkt = packet(at(5, 1), 5)
        doc = candidates(pkt.ts_ns, retained_from="2100-01-01T00:00:00.123456789Z", runs=())
        stub = StubClient({"/attribution/candidates": doc})
        groups, reason = stub.lookup("192.0.2.1", pkt.ts_ns)
        self.assertEqual(groups, [])
        self.assertIn("missing", reason)
        doc["retained_from"] = "2020-01-01T00:00:00Z"
        stub = StubClient({"/attribution/candidates": doc})
        self.assertIn("no run", stub.lookup("192.0.2.1", pkt.ts_ns)[1])

    def test_older_dispatcher_falls_back_to_the_deprecated_routes(self):
        pkt = packet(at(5, 1), 5)
        stub = StubClient({
            "/executors/by-ip": {"executor_id": "exec-1", "debuglet_ids": [DEBUGLET]},
            "/executors/exec-1/tesla": schedule(9),
        })
        groups, reason = stub.lookup("192.0.2.1", pkt.ts_ns)
        self.assertEqual(len(groups), 1, reason)
        matched, why = vp.verify_packet(pkt, groups[0][0], groups[0][1], 0)
        self.assertEqual(matched, [(DEBUGLET, 5, "siphash")], why)
        # The missing route is not asked again.
        stub.lookup("192.0.2.1", pkt.ts_ns + 5 * SECOND)
        self.assertEqual([path for path, _ in stub.calls].count("/attribution/candidates"), 1)


if __name__ == "__main__":
    unittest.main()
