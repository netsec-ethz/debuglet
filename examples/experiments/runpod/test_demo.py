# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich

import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import demo


class FakeAPI:
    def __init__(self, pods=()):
        self.current = {p["id"]: copy.deepcopy(p) for p in pods}
        self.calls = []
        self.ambiguous = False
        self.delete_pending = False

    def pods(self):
        self.calls.append(("GET", "/pods"))
        return copy.deepcopy(list(self.current.values()))

    def call(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "POST":
            pod = {"id": "created", "name": body["name"], "cost": 0.06, "mounts": {}}
            self.current[pod["id"]] = pod
            if self.ambiguous:
                raise demo.Failure("transport ended after create")
            return pod
        pod_id = path.rsplit("/", 1)[1]
        if pod_id not in self.current:
            raise demo.APIError(404)
        if method == "GET":
            return copy.deepcopy(self.current[pod_id])
        if method == "DELETE":
            if not self.delete_pending:
                del self.current[pod_id]
            return None
        raise AssertionError((method, path))


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.inventory = {
            "schema_version": 1, "run_id": "1" * 16, "expires_at": time.time() + 3600,
            "baseline_ids": ["existing"], "terminate": False, "image": "ubuntu:24.04",
            "planned": [{"role": role, "name": "debuglet-demo-" + "1" * 16 + "-" + role, "region": "EU-RO-1"} for role in demo.ROLES],
            "attempts": [], "pods": [],
            "quote": {"cpu_flavor": "cpu3c", "hours": 4, "budget_usd": 10, "estimated_usd": 2,
                "reserved_hourly": {role: 0.1 for role in demo.ROLES}},
            "package": {"directory": "/package", "version": "v1", "console_archive": "/console.tar.gz"},
        }
        self.persist()
        (self.state / "ssh_key.pub").write_text("ssh-ed25519 PUBLIC\n")
        self.heartbeat()

    def persist(self):
        demo.save(self.state / "inventory.json", self.inventory)

    def heartbeat(self, **changes):
        demo.save(self.state / "guard.json", {"run_id": self.inventory["run_id"], "expires_at": self.inventory["expires_at"],
            "checked_at": time.time(), "healthy": True, **changes})

    def attempted(self, role="dispatcher", pod_id=None, outcome="created"):
        planned = next(p for p in self.inventory["planned"] if p["role"] == role)
        self.inventory["attempts"].append({**planned, "outcome": outcome, "hostkey_nonce": "nonce"})
        if pod_id:
            self.inventory["pods"].append({**planned, "id": pod_id, "hostkey_nonce": "nonce"})
        self.persist()
        return {"id": pod_id, "name": planned["name"], "cost": 0.06, "mounts": {}}

    def test_ambiguous_create_is_recorded_and_never_blindly_repeated(self):
        api = FakeAPI()
        api.ambiguous = True
        with mock.patch.object(demo, "package_metadata", return_value=self.inventory["package"]), mock.patch.object(demo, "quote", return_value=self.inventory["quote"]):
            with self.assertRaisesRegex(demo.Failure, "transport ended"):
                demo.up(self.state, api)
            persisted = demo.read(self.state)
            self.assertEqual(persisted["attempts"][0]["outcome"], "unknown")
            with self.assertRaisesRegex(demo.Failure, "Uncertain create"):
                demo.up(self.state, api)
        self.assertEqual(api.calls.count(("POST", "/pods")), 1)
        # The independent guard recovers the paid ID by its full unique name.
        self.assertFalse(demo.guard_once(self.state, api))
        persisted = demo.read(self.state)
        self.assertEqual(persisted["pods"][0]["id"], "created")
        self.assertEqual(persisted["attempts"][0]["outcome"], "found")

    def test_no_create_without_current_independent_guard(self):
        for status in ({"healthy": False}, {"checked_at": time.time() - 120}, {"run_id": "different"}, {"expires_at": 0}):
            with self.subTest(status=status):
                self.heartbeat(**status)
                api = FakeAPI()
                with mock.patch.object(demo, "package_metadata", return_value=self.inventory["package"]), mock.patch.object(demo, "quote", return_value=self.inventory["quote"]):
                    with self.assertRaises(demo.Failure):
                        demo.up(self.state, api)
                self.assertFalse(any(method == "POST" for method, _ in api.calls))

    def test_cleanup_uses_exact_id_name_and_never_baseline_or_prefix(self):
        target = self.attempted(pod_id="owned")
        api = FakeAPI([target, {"id": "existing", "name": target["name"]},
            {"id": "unrelated", "name": target["name"] + "-other"}])
        self.assertTrue(demo.cleanup_once(self.state, api))
        self.assertEqual([path for method, path in api.calls if method == "DELETE"], ["/pods/owned"])
        self.assertEqual(set(api.current), {"existing", "unrelated"})

    def test_renamed_pod_is_refused_but_other_owned_pod_is_cleaned(self):
        renamed = self.attempted(pod_id="renamed")
        renamed["name"] = "another-name"
        other = self.attempted("executor-1", "other")
        api = FakeAPI([renamed, other])
        self.assertFalse(demo.cleanup_once(self.state, api))
        self.assertIn("renamed", api.current)
        self.assertNotIn("other", api.current)

    def test_delete_requires_confirmed_absence(self):
        api = FakeAPI([self.attempted(pod_id="owned")])
        api.delete_pending = True
        self.assertFalse(demo.cleanup_once(self.state, api))
        api.delete_pending = False
        self.assertTrue(demo.cleanup_once(self.state, api))

    def test_expiry_cleans_found_resources_and_keeps_watch_for_uncertain_create(self):
        pod = self.attempted(pod_id="owned")
        self.attempted("executor-1", outcome="unknown")
        self.inventory["expires_at"] = time.time() - 1
        self.persist()
        api = FakeAPI([pod])
        self.assertFalse(demo.guard_once(self.state, api))
        self.assertTrue(demo.read(self.state)["terminate"])
        self.assertNotIn("owned", api.current)
        cleanup = json.loads((self.state / "cleanup.json").read_text())
        self.assertTrue(cleanup["uncertain_create"])
        self.assertFalse(cleanup["complete"])

    def test_price_overrun_triggers_independent_cleanup(self):
        pod = self.attempted(pod_id="owned")
        pod["cost"] = 1.5
        api = FakeAPI([pod])
        self.assertTrue(demo.guard_once(self.state, api))
        self.assertTrue(demo.read(self.state)["terminate"])
        self.assertEqual(api.current, {})

    def test_guard_retains_armed_deadline_if_inventory_expiry_is_changed(self):
        pod = self.attempted(pod_id="owned")
        frozen = {"run_id": self.inventory["run_id"], "expires_at": time.time() - 1}
        api = FakeAPI([pod])
        self.assertTrue(demo.guard_once(self.state, api, frozen))
        self.assertEqual(api.current, {})
        heartbeat = json.loads((self.state / "guard.json").read_text())
        self.assertEqual(heartbeat["expires_at"], frozen["expires_at"])
        with self.assertRaises(demo.Failure):
            demo.guard_ready(self.state, demo.read(self.state))

    def test_six_cpu_only_requests_and_symmetric_peer_ports(self):
        for planned in self.inventory["planned"]:
            body = demo.create_body(self.inventory, planned, "ssh-ed25519 PUBLIC", "nonce")
            self.assertEqual(body["cpu"], {"id": "cpu3c", "vcpuCount": 2})
            self.assertNotIn("gpu", body)
            self.assertFalse(body["globalNetworking"])
            self.assertEqual(body["dataCenterIds"], [planned["region"]])
            self.assertIn("70000/tcp" if planned["role"] != "dispatcher" else "8080/http", body["ports"])
        self.assertEqual(len(self.inventory["planned"]), 6)

    def test_fault_only_writes_next_trial_arguments(self):
        with mock.patch("builtins.print"):
            demo.fault(self.state, 0, 2)
        setting = json.loads((self.state / "fault.json").read_text())
        self.assertEqual(setting["guest_args"], ["-blocked-from=0", "-blocked-to=2"])
        self.assertEqual(setting["label"], "Simulated connection failure")
        with self.assertRaises(demo.Failure):
            demo.fault(self.state, 2, 2)


class CatalogTests(unittest.TestCase):
    def test_quote_includes_all_six_disks_and_refuses_limits_or_unavailable_regions(self):
        api = mock.Mock()
        api.call.return_value = {"cpus": [{"id": "cpu3c", "vcpu": {"min": 2, "max": 16},
            "ramGbPerVcpu": 2, "price": {"securePerVcpu": 0.03}, "dataCenters": [{"id": "EU-RO-1", "availability": "HIGH"}]}]}
        value = demo.quote(api, "cpu3c", ["EU-RO-1"] * 6, 4, 10)
        self.assertAlmostEqual(value["estimated_usd"], (0.36 + 35 * 0.1 / 720) * 4 * 1.25)
        for hours, budget in [(5, 10), (4, 11), (float("nan"), 10), (4, 0.1)]:
            with self.assertRaises(demo.Failure):
                demo.quote(api, "cpu3c", ["EU-RO-1"] * 6, hours, budget)
        with self.assertRaises(demo.Failure):
            demo.quote(api, "cpu3c", ["missing"], 4, 10)

    def test_inventory_walks_every_page(self):
        api = demo.API("test-only-key")
        api.call = mock.Mock(side_effect=[
            {"pods": [{"id": "a"}], "pagination": {"hasNextPage": True, "nextCursor": "opaque/+"}},
            {"pods": [{"id": "b"}], "pagination": {"hasNextPage": False, "nextCursor": None}}])
        self.assertEqual(api.pods(), [{"id": "a"}, {"id": "b"}])
        self.assertIn("cursor=opaque%2F%2B", api.call.call_args.args[1])
        api.call = mock.Mock(return_value={"pods": []})
        with self.assertRaises(demo.Failure):
            api.pods()


if __name__ == "__main__":
    unittest.main()
