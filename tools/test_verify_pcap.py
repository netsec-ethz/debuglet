"""The verification window of tools/verify_pcap.py: candidate epochs t and t-1
only, a disclosure delay of at least two epochs, and no key that may already
have been public when the packet was captured."""
import base64
import hashlib
from pathlib import Path
import struct
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
