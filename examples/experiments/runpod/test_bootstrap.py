#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Offline bootstrap tests: all host and HTTP operations are replaced by fixtures."""
import copy
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("delivery_bootstrap", Path(__file__).with_name("bootstrap.py"))
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)


def inventory(directory):
    package = directory / "package"
    package.mkdir()
    names = {"debuglet-v1.2.3-linux-amd64.tar.gz": b"archive", "install.sh": b"installer",
             "SHA256SUMS": b"checksums", "console.tar.gz": b"console"}
    for name, data in names.items():
        (package / name).write_bytes(data)
    pods = []
    for index, role in enumerate(BOOT.ROLES):
        pod = {"role": role, "id": f"podid{index}", "name": f"owned-{role}",
               "public_ip": f"93.184.216.{index + 10}", "ssh_port": 22000 + index}
        if index:
            pod["peer_port"] = 30000 + index
        else:
            pod.update(api_port=29000, control_port=29001,
                       console_url="https://podid0-8080.proxy.runpod.net")
        pods.append(pod)
    return {"run_id": "0123456789abcdef", "expires_at": time.time() + 14400, "pods": pods,
            "package": {"directory": str(package), "version": "v1.2.3",
                        "archive": str(package / "debuglet-v1.2.3-linux-amd64.tar.gz"),
                        "sha256": BOOT.digest(package / "debuglet-v1.2.3-linux-amd64.tar.gz"),
                        "installer_sha256": BOOT.digest(package / "install.sh"),
                        "checksums_sha256": BOOT.digest(package / "SHA256SUMS"),
                        "console_archive": str(package / "console.tar.gz"),
                        "console_sha256": BOOT.digest(package / "console.tar.gz")}}


def observations(peers):
    return [{"source_role": source["role"], "source_ip": source["public_ip"], "source_port": 45000,
             "role": target["role"], "target_ip": target["public_ip"], "target_port": target["peer_port"]}
            for source in peers for target in peers if source != target]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.inventory = inventory(self.state)
        self.peers = self.inventory["pods"][1:]
        BOOT.save(self.state / "inventory.json", self.inventory)

    def test_inventory_requires_actual_ports_and_six_roles(self):
        BOOT.validate_inventory(self.inventory)
        for change in (
            lambda value: value["pods"].pop(),
            lambda value: value["pods"][1].update(peer_port=70000),
            lambda value: value["pods"][1].update(public_ip="10.1.2.3"),
            lambda value: value["pods"][0].update(console_url="https://wrong.example"),
            lambda value: value.update(expires_at=float("nan")),
            lambda value: value.update(expires_at="2026-10-13T12:00:00Z"),
        ):
            value = copy.deepcopy(self.inventory)
            change(value)
            with self.assertRaises(ValueError):
                BOOT.validate_inventory(value)

    def test_all_selected_artifacts_are_checked_before_remote_use(self):
        BOOT.package_files(self.inventory["package"])
        for filename in ("install.sh", "SHA256SUMS", "console.tar.gz", "debuglet-v1.2.3-linux-amd64.tar.gz"):
            with self.subTest(filename=filename):
                path = self.state / "package" / filename
                original = path.read_bytes()
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    BOOT.package_files(self.inventory["package"])
                path.write_bytes(original)

    def test_ssh_pins_exact_pod_alias_and_host_key_file(self):
        host = BOOT.Host(self.state, self.peers[0])
        self.assertIn("HostKeyAlias=podid1", host.options)
        self.assertIn("UserKnownHostsFile=" + str(self.state / "known_hosts"), host.options)
        self.assertIn("StrictHostKeyChecking=yes", host.options)
        self.assertIn("BatchMode=yes", host.options)

    def test_peer_policy_excludes_every_address_outside_selected_peers(self):
        blocks = [ipaddress.ip_network(value) for value in BOOT.denied_networks(
            peer["public_ip"] for peer in self.peers).split(",")]
        for peer in self.peers:
            self.assertFalse(any(ipaddress.ip_address(peer["public_ip"]) in block for block in blocks))
        for address in ("93.184.216.10", "93.184.216.16", "8.8.8.8", "127.0.0.1", "10.0.0.1", "::1"):
            self.assertTrue(any(ipaddress.ip_address(address) in block for block in blocks))

    def test_join_config_keeps_tls_identity_and_fallback(self):
        source = ('[tls]\ndisable = false\n[credentials]\nclient_key = "/private/key"\n'
                  '[network]\npacket_counter = "fallback"\n[network.policy]\n'
                  'local_targets = false\nscion = false\ninbound = false\n[logging]\nlog_level = "info"\n')
        result = tomllib.loads(BOOT.executor_config(source, self.peers[0], self.peers))
        self.assertFalse(result["tls"]["disable"])
        self.assertEqual(result["credentials"]["client_key"], "/private/key")
        self.assertEqual(result["network"]["packet_counter"], "fallback")
        self.assertEqual(result["network"]["public_ports"], "30001")
        self.assertTrue(result["network"]["policy"]["inbound"])
        self.assertFalse(result["network"]["policy"]["local_targets"])
        self.assertEqual(result["network"]["policy"]["permitted_ports"], "30001,30002,30003,30004,30005")
        self.assertTrue(result["connectivity"]["listeners"])

    def test_preflight_requires_every_directed_pair_and_global_expected_sources(self):
        values = observations(self.peers)
        BOOT.validate_preflight(self.peers, values)
        for changed in (values[:-1], values[:-1] + [values[0]],
                        [dict(values[0], source_ip="10.0.0.2")] + values[1:],
                        [dict(values[0], source_ip="8.8.8.8")] + values[1:],
                        [dict(values[0], target_port=1)] + values[1:]):
            with self.assertRaises(ValueError):
                BOOT.validate_preflight(self.peers, changed)

    def test_dispatcher_requires_enrolled_tls_and_nginx_verifies_upstream(self):
        config = tomllib.loads(BOOT.dispatcher_config(self.inventory["pods"][0]))
        self.assertFalse(config["server"]["local_development"])
        self.assertFalse(config["tls"]["disable"])
        self.assertTrue(config["tls"]["require_client_cert"])
        self.assertTrue(config["sui"]["disabled"])
        self.assertEqual(config["executor_onboarding"]["grpc_address"], "93.184.216.10:29001")
        self.assertIn("proxy_ssl_verify on;", BOOT.nginx_config())
        self.assertIn("proxy_ssl_name localhost;", BOOT.nginx_config())
        self.assertNotIn("account-key", BOOT.nginx_config())

    def test_login_page_uses_existing_cookie_login_without_embedded_credentials(self):
        self.assertIn("fetch('/api/auth/login'", BOOT.LOGIN_PAGE)
        self.assertIn("credentials: 'same-origin'", BOOT.LOGIN_PAGE)
        self.assertIn("account_key: key.value.trim()", BOOT.LOGIN_PAGE)
        self.assertIn("window.location.assign('/console/')", BOOT.LOGIN_PAGE)
        self.assertNotIn("localStorage", BOOT.LOGIN_PAGE)
        self.assertNotIn("sessionStorage", BOOT.LOGIN_PAGE)
        self.assertNotIn("Authorization:", BOOT.LOGIN_PAGE)

    def test_console_extraction_accepts_both_layouts_and_refuses_links(self):
        for name in ("console/index.html", "index.html", "../outside", "/absolute", "link"):
            with self.subTest(name=name):
                remote = self.state / ("remote-" + str(len(name)))
                remote.mkdir(exist_ok=True)
                archive = remote / "console.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    member = tarfile.TarInfo(name)
                    member.size = 5
                    if name == "link":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/outside"
                        member.size = 0
                    bundle.addfile(member, io.BytesIO(b"hello"))
                with patch.object(BOOT, "BASE", remote):
                    if name in ("console/index.html", "index.html"):
                        BOOT.extract_console(archive)
                        self.assertEqual((remote / "www/console/index.html").read_text(), "hello")
                        self.assertIn("account_key", (remote / "www/demo-login.html").read_text())
                    else:
                        with self.assertRaises(ValueError):
                            BOOT.extract_console(archive)

    def test_supervisor_starting_exit_three_is_polled(self):
        results = [subprocess.CompletedProcess([], 3, b"executor STARTING", b""),
                   subprocess.CompletedProcess([], 0, b"executor RUNNING", b"")]
        with patch.object(BOOT.subprocess, "run", side_effect=results), patch.object(BOOT.time, "sleep"):
            BOOT.wait_program("executor")

    def test_join_resumes_after_supervisor_failure_without_reenrollment(self):
        for failed_step in ("reload_programs", "wait_program"):
            with self.subTest(failed_step=failed_step):
                remote = self.state / failed_step
                (remote / "config").mkdir(parents=True)
                node = "12345678-1234-1234-1234-123456789abc"
                enrolled = remote / "state" / ("executor-" + node)
                value = {"enrollment": {"executor": {"id": node}, "token": "fixture-setup-secret"},
                         "pod": self.peers[0], "peers": self.peers, "version": "v1.2.3",
                         "api_url": "https://podid0-8080.proxy.runpod.net/api"}
                joins = []

                def fake_run(arguments, **kwargs):
                    if "join" not in arguments:
                        return b""
                    joins.append(arguments)
                    enrolled.mkdir(parents=True)
                    (enrolled / "executor.crt").write_bytes(b"same enrolled certificate")
                    (enrolled / "executor.key").write_bytes(b"same private key")
                    (enrolled / "executor.sqlite").write_bytes(b"same database")
                    config = enrolled / "service.toml"
                    config.write_text('[identity]\nexecutor_id = "' + node + '"\n'
                                      '[network]\npacket_counter = "fallback"\n'
                                      '[network.policy]\nlocal_targets = false\ninbound = false\n')
                    return json.dumps({"config": str(config)}).encode()

                with patch.object(BOOT, "BASE", remote), patch.object(BOOT, "run", side_effect=fake_run), \
                        patch.object(BOOT, "program"), patch.object(BOOT, "reload_programs") as reload, \
                        patch.object(BOOT, "wait_program") as wait:
                    (reload if failed_step == "reload_programs" else wait).side_effect = [RuntimeError("startup failed"), None]
                    with self.assertRaises(RuntimeError):
                        BOOT.remote_join(value)
                    self.assertTrue((remote / "join-checkpoint.json").exists())
                    self.assertFalse((remote / "join-result.json").exists())
                    value["enrollment"].pop("token")  # Recovery must not even read it.
                    result = BOOT.remote_join(value)
                self.assertEqual(len(joins), 1)
                self.assertEqual(result["executor_id"], node)
                self.assertEqual(result["certificate_sha256"], BOOT.digest(enrolled / "executor.crt"))
                self.assertEqual((enrolled / "executor.key").read_bytes(), b"same private key")
                self.assertEqual((enrolled / "executor.sqlite").read_bytes(), b"same database")
                config = tomllib.loads((enrolled / "service.toml").read_text())
                self.assertEqual(config["identity"]["executor_id"], node)
                self.assertEqual(config["network"]["public_ports"], "30001")
                self.assertFalse((remote / "config/setup-token").exists())

    def test_uncertain_join_with_existing_state_never_reuses_token(self):
        remote = self.state / "uncertain"
        (remote / "config").mkdir(parents=True)
        node = "12345678-1234-1234-1234-123456789abc"
        enrolled = remote / "state" / ("executor-" + node)
        value = {"enrollment": {"executor": {"id": node}, "token": "fixture-setup-secret"},
                 "pod": self.peers[0], "peers": self.peers, "version": "v1.2.3",
                 "api_url": "https://podid0-8080.proxy.runpod.net/api"}
        joins = []

        def uncertain_run(arguments, **kwargs):
            if "join" in arguments:
                joins.append(arguments)
                enrolled.mkdir(parents=True)
                (enrolled / "executor.crt").write_bytes(b"preserve this identity")
                raise RuntimeError("join response unavailable")
            return b""

        with patch.object(BOOT, "BASE", remote), patch.object(BOOT, "run", side_effect=uncertain_run):
            with self.assertRaises(RuntimeError):
                BOOT.remote_join(value)
            self.assertFalse((remote / "join-checkpoint.json").exists())
            with self.assertRaisesRegex(ValueError, "Preserve .*manual recovery"):
                BOOT.remote_join(value)
        self.assertEqual(len(joins), 1)
        self.assertEqual((enrolled / "executor.crt").read_bytes(), b"preserve this identity")

    def exercise_bootstrap(self, private_source=False):
        calls = []
        peers = self.peers
        owned = []

        class FakeHost:
            def __init__(self, state, pod):
                self.pod = pod

            def command(self, *args, **kwargs):
                return b""

            def copy(self, *args):
                pass

            def remote(self, action, value, **kwargs):
                calls.append((action, self.pod["role"]))
                if action == "probe-client":
                    result = [item for item in observations(peers) if item["source_role"] == self.pod["role"]]
                    if private_source:
                        result[0]["source_ip"] = "10.0.0.1"
                    return result
                if action == "join":
                    return {"executor_id": value["enrollment"]["executor"]["id"], "role": self.pod["role"],
                            "peer_ip": self.pod["public_ip"], "peer_port": self.pod["peer_port"]}
                return {}

        class FakeAPI:
            token = None

            def __init__(self, origin):
                pass

            def call(self, method, path, body=None):
                calls.append((method, path))
                if path == "/user":
                    return {"id": "account", "role": "user", "account_key": "fixture-account-secret",
                            "recovery_code": "fixture-recovery-secret"}
                if path == "/auth/login":
                    return {"token": "fixture-session-secret"}
                if path == "/operator/executors":
                    if method == "POST":
                        item = {"id": "node-" + body["name"], "ready": True, "status": "online"}
                        owned.append(item)
                        return {"executor": item, "token": "fixture-setup-secret"}
                    return {"executors": owned}
                return {}

        with patch.object(BOOT, "Host", FakeHost), patch.object(BOOT, "API", FakeAPI):
            if private_source:
                with self.assertRaises(ValueError):
                    BOOT.bootstrap(self.state)
            else:
                result = BOOT.bootstrap(self.state)
                self.assertEqual(result["phase"], "ready")
                self.assertEqual(len(result["executor_ids"]), 5)
                self.assertTrue(result["login_url"].endswith("/demo-login"))
        return calls

    def test_bootstrap_stops_every_probe_before_enrollment_and_keeps_keys_private(self):
        calls = self.exercise_bootstrap()
        last_stop = max(index for index, item in enumerate(calls) if item[0] == "probe-stop")
        first_join = next(index for index, item in enumerate(calls) if item[0] == "join")
        self.assertLess(last_stop, first_join)
        self.assertEqual(calls.count(("PUT", "/user")), 1)
        self.assertEqual(calls[-1], ("POST", "/auth/logout"))
        self.assertEqual(stat.S_IMODE((self.state / "account-key").stat().st_mode), 0o600)
        self.assertNotIn("fixture-", (self.state / "runtime.json").read_text())

    def test_private_preflight_source_is_recorded_and_prevents_account_or_guest_setup(self):
        calls = self.exercise_bootstrap(private_source=True)
        self.assertFalse(any(method in ("PUT", "POST", "join") for method, _ in calls))
        runtime = json.loads((self.state / "runtime.json").read_text())
        self.assertEqual(runtime["preflight"][0]["source_ip"], "10.0.0.1")
        self.assertEqual(sum(action == "probe-stop" for action, _ in calls), 5)


if __name__ == "__main__":
    unittest.main()
