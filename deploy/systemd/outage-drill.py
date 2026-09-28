#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Rehearse an installed service outage in a disposable Docker/systemd fixture.

Requires an installed full bundle, debuglet account, iptables, a private network
namespace and DEBUGLET_SERVICE_FIXTURE=1. The caller owns container teardown.
Never use host networking. Services retain their normal empty capability set.
"""
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import re
import select
import socket
import sqlite3
import subprocess
import time
import tomllib
import urllib.request
import uuid

DBL = "/usr/local/bin/dbl"
URL = "http://127.0.0.1:9000"
ROLES = (("dispatcher", "local"), ("executor", "worker"))
STATE = Path("/var/lib/debuglet/executors/worker")
DROP = ("iptables", "-w", "5", "-p", "tcp", "-o", "lo", "--dport", "9001", "-j", "DROP")


def run(*args, ok=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if ok and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr}")
    return result


def cli(*args, ok=True):
    result = run(DBL, "--output", "json", *args, ok=ok)
    return json.loads(result.stdout)


def event(phase, **values):
    print(json.dumps({"phase": phase, **values}), flush=True)


def wait_for(check, description, seconds=45):
    deadline = time.monotonic() + seconds
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise RuntimeError("timed out: " + description)
        time.sleep(0.1)


def status(role, name):
    return cli("service", "status", "--role", role, "--name", name, ok=False)


def ready(role, name):
    return wait_for(lambda: status(role, name).get("ready"), role + " readiness")


def request(path, token=None, data=None, method=None, text=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(URL + path, headers=headers, method=method,
                                 data=None if data is None else json.dumps(data).encode())
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read().decode() if text else json.load(response)


def metrics(token):
    body = request("/metrics", token, text=True)
    wanted = {"debuglet_api_ready", "debuglet_executors_ready",
              "debuglet_ready_capacity_bits_per_second", "debuglet_retained_runs_unknown"}
    values = {name: float(value) for line in body.splitlines() if line and not line.startswith("#")
              for name, value in [line.split()] if name in wanted}
    if set(values) != wanted:
        raise RuntimeError("required authoritative metrics missing")
    return values


def target():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(15)
    return listener, uuid.uuid4().hex


def acknowledge(listener, nonce):
    connection, _ = listener.accept()
    try:
        connection.settimeout(15)
        connection.sendall(("DEBUGLET/1 " + nonce + "\n").encode())
        expected = ("ACK " + nonce + "\n").encode()
        actual = b""
        while len(actual) < len(expected):
            block = connection.recv(len(expected) - len(actual))
            if not block:
                raise RuntimeError("guest closed before acknowledgement")
            actual += block
        if actual != expected:
            raise RuntimeError("guest acknowledgement mismatch")
        return connection
    except BaseException:
        connection.close()
        raise


def main():
    if not __debug__ or os.geteuid() != 0 or os.environ.get("DEBUGLET_SERVICE_FIXTURE") != "1":
        raise RuntimeError("explicit disposable fixture opt-in and enabled assertions required")
    if Path("/run/systemd/container").read_text().strip() != "docker" or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("Docker fixture with systemd PID 1 required")
    # The caller passes its host namespace identity; matching it is forbidden.
    host_netns = os.environ.get("DEBUGLET_HOST_NETNS")
    if not host_netns or os.readlink("/proc/self/ns/net") == host_netns:
        raise RuntimeError("a verified private network namespace is required")
    if list(Path("/etc/debuglet/services").glob("*.json")):
        raise RuntimeError("fixture already contains managed roles")
    if run("iptables", "-S", "OUTPUT").stdout.strip() != "-P OUTPUT ACCEPT":
        raise RuntimeError("fixture OUTPUT chain must be empty")
    payload = Path(DBL).resolve().parent.parent
    manifest = json.loads((payload / "share/debuglet/manifest.json").read_text())
    expected = os.environ.get("DEBUGLET_LOCAL_SOURCE_SHA")
    if not expected or manifest["source_sha"] != expected:
        raise RuntimeError("exact installed source revision required")
    event("identity", version=cli("version"), kernel=os.uname().release,
          systemd=run("systemctl", "--version").stdout.splitlines()[0])
    sockets, installed = [], []
    dropped = False
    try:
        for role, name in ROLES:
            args = ["service", "install", "--role", role, "--name", name]
            if role == "executor":
                args += ["--dispatcher", "127.0.0.1:9001"]
            installed.append((role, name))
            report = cli(*args)
            assert report["ready"]
            process = dict(line.split(":", 1) for line in Path(f'/proc/{report["main_pid"]}/status').read_text().splitlines() if ":" in line)
            assert int(process["CapEff"], 16) == 0 and process["NoNewPrivs"].strip() == "1"
        identity = status("executor", "worker")["executor_id"]
        assert cli("service", "stop", "--role", "executor", "--name", "worker")["joined"]
        executor_config = STATE / "service.toml"
        configured, count = re.subn(r"(?m)^(\s*local_targets\s*=\s*)false$", r"\g<1>true", executor_config.read_text())
        assert count == 1
        executor_config.write_text(configured)
        assert cli("service", "start", "--role", "executor", "--name", "worker")["ready"]
        assert status("executor", "worker")["executor_id"] == identity
        event("fixture_policy", local_targets=True, scope="owned container loopback only")
        config = Path("/var/lib/debuglet/dispatchers/local/service.toml")
        lease = tomllib.loads(config.read_text())["scheduler"]["executor_timeout"]
        account = request("/user", data={"name": "outage-drill"}, method="PUT")
        run(str(payload / "bin/debuglet-dispatcher"), "--config", str(config), "--grant-operator", account["id"])
        token = request("/auth/login", data={"account_key": account["account_key"]}, method="POST")["token"]
        key = Path("/run/outage-account-key")
        key.touch(mode=0o600)
        key.write_text(account["account_key"])
        cli("connect", URL, "--name", "outage")
        cli("--dispatcher", "outage", "login", "--account-key-file", str(key))
        wait_for(lambda: metrics(token)["debuglet_executors_ready"] == 1, "eligible executor")

        def submit(start=None):
            listener, nonce = target()
            sockets.append(listener)
            batch = [{"order_id": 0, "executor_id": identity,
                      "wasm": base64.b64encode((payload / "share/debuglet/demo.wasm").read_bytes()).decode(),
                      "args": [f"127.0.0.1:{listener.getsockname()[1]}", nonce],
                      "policy": {"floor_bw": 1, "ceil_bw": 1048576, "timeout_ms": 300000,
                                 "addresses": ["127.0.0.1"]}}]
            if start is not None:
                batch[0]["start_time"] = start
            intent = request("/payment/intent", token, {"debuglets": batch, "payment_method": "TEST", "refund_address": ""}, "PUT")
            assert intent["method"] == "TEST"
            ids = request("/debuglet", token, {"debuglets": batch, **intent["intent"]}, "PUT")
            assert len(ids) == 1 and str(uuid.UUID(ids[0])) == ids[0]
            if start is not None:
                return ids[0], listener
            connection = acknowledge(listener, nonce)
            sockets.append(connection)
            wait_for(lambda: request("/debuglet/" + ids[0] + "/state", token)["state"] == "RunStateStarted", "real guest start")
            return ids[0], connection

        def fresh():
            run_id, connection = submit()
            connection.close()  # Normal target EOF permits this guest to finish.
            wait_for(lambda: request("/debuglet/" + run_id + "/state", token)["state"] == "RunStateExited", "fresh terminal")
            assert request("/debuglet/" + run_id + "/state", token)["error"] == ""
            output = run(DBL, "--dispatcher", "outage", "logs", run_id).stdout
            assert "DEBUGLET_DEMO_OK" in output
            return run_id

        cancelled, connection = submit()
        began = time.monotonic()
        assert cli("--dispatcher", "outage", "cancel", cancelled)["acknowledged"]
        assert connection.recv(1) == b""
        eof = time.monotonic() - began
        wait_for(lambda: request("/debuglet/" + cancelled + "/state", token)["state"] == "RunStateExited", "connected cancelled terminal")
        event("connected_cancellation", target_eof_seconds=round(eof, 3), terminal_seconds=round(time.monotonic() - began, 3))

        active, connection = submit()
        queued_at = int(time.time() + lease + 20)
        queued, queued_target = submit(queued_at)
        original = request("/debuglet/" + active + "/recovery", token)["original_binding"]
        assert original and request("/debuglet/" + queued + "/recovery", token)["original_binding"] == original
        executor_pid = status("executor", "worker")["main_pid"]
        before_journal = run("journalctl", "-u", "debuglet-executor-worker", "--no-pager", "-o", "cat").stdout
        began = time.monotonic()
        run(*DROP[:3], "-I", "OUTPUT", "1", *DROP[3:])
        dropped = True
        wait_for(lambda: not status("executor", "worker").get("ready"), "lease readiness withdrawal", lease + 10)
        withdrawn = time.monotonic() - began
        assert connection.recv(1) == b""  # Still-open target; no fixture cancellation.
        eof = time.monotonic() - began
        wait_for(lambda: "control session ended: lease expired" in run("journalctl", "-u", "debuglet-executor-worker", "--no-pager", "-o", "cat").stdout[len(before_journal):], "joined lease-expired session", 5)
        assert status("executor", "worker")["main_pid"] == executor_pid
        wait_for(lambda: metrics(token)["debuglet_executors_ready"] == 0, "withdrawn capacity", 5)
        lost = metrics(token)
        assert lost["debuglet_ready_capacity_bits_per_second"] == 0
        assert request("/healthz")["status"] == "ok"
        event("partition", configured_lease_seconds=lease, readiness_withdrawn_seconds=round(withdrawn, 3),
              target_eof_seconds=round(eof, 3), metrics=lost, executor_process_unchanged=True)

        stopped = cli("service", "stop", "--role", "dispatcher", "--name", "local")
        assert stopped["joined"] and not status("dispatcher", "local").get("ready")
        run(*DROP[:3], "-D", "OUTPUT", *DROP[3:])
        dropped = False
        began = time.monotonic()
        cli("service", "start", "--role", "dispatcher", "--name", "local")
        ready("executor", "worker")
        wait_for(lambda: metrics(token)["debuglet_executors_ready"] == 1, "recovered capacity")
        ready_elapsed = time.monotonic() - began
        new_run = fresh()
        recovery_elapsed = time.monotonic() - began
        successor = request("/debuglet/" + new_run + "/recovery", token)["original_binding"]
        assert successor["dispatcher_incarnation"] != original["dispatcher_incarnation"]
        assert successor["session_id"] != original["session_id"]
        while time.time() <= queued_at:
            assert not select.select([queued_target], [], [], min(0.25, queued_at - time.time() + 0.1))[0]
        fresh()  # Serving checkpoint after the old queued start became due.
        assert not select.select([queued_target], [], [], 0)[0]
        retained = []
        # Local cleanup retains an unacknowledged exit and removes the active
        # execution row. Inspection covers execution rows, not terminal rows.
        for run_id, classification in ((active, "absent"), (queued, "retained_unstarted")):
            observation = request("/debuglet/" + run_id + "/recovery", token)
            assert observation["state"] != "RunStateExited" and observation["original_binding"] == original
            assert observation["control_status"] == "unavailable"
            assert observation["observation"]["classification"] == classification, observation
            assert observation["observation"]["current_at_check"] is True
            retained.append(observation)
        assert metrics(token)["debuglet_retained_runs_unknown"] >= 2
        event("recovery", readiness_seconds=round(ready_elapsed, 3), fresh_output_seconds=round(recovery_elapsed, 3),
              original_binding=original, successor_binding=successor, retained=retained)

        drained = cli("drain", "--role", "executor", "--name", "worker", "--wait", "30s")
        assert drained["joined"] and drained["active"] == "inactive"
        assert not status("executor", "worker").get("ready")
        def retained_exit():
            with closing(sqlite3.connect((STATE / "executor.sqlite").as_uri() + "?mode=ro", uri=True)) as database:
                row = database.execute("SELECT dispatcher_incarnation, session_id, exit_code, error_message, recorded_at, attempts, last_attempt_at, last_error, rejected FROM debuglet_exits WHERE debuglet_id = ?", (active,)).fetchone()
            assert row and row[:2] == (original["dispatcher_incarnation"], original["session_id"])
            assert row[2] == -1 and row[5] == 0 and row[7] and row[8] == 0
            return row
        terminal = retained_exit()
        doctor = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit", "debuglet-outage-doctor"]
        for setting in ("User=debuglet", "Group=debuglet", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectControlGroups=yes", "ProtectKernelModules=yes", "ReadWritePaths=" + str(STATE)):
            doctor += ["--property", setting]
        report = json.loads(run(*doctor, DBL, "--output", "json", "doctor", "--role", "executor", "--file", str(STATE / "service.toml"), "--offline").stdout)
        checks = {item["id"]: item["status"] for item in report["checks"]}
        assert checks["schema"] == checks["state_permissions"] == "pass"
        assert cli("drain", "--role", "executor", "--name", "worker", "--resume")["ready"]
        wait_for(lambda: metrics(token)["debuglet_executors_ready"] == 1, "resumed capacity")
        fresh()
        assert request("/debuglet/" + active + "/state", token)["state"] != "RunStateExited"
        assert cli("drain", "--role", "executor", "--name", "worker", "--wait", "30s")["joined"]
        assert retained_exit() == terminal
        event("drain_resume", joined=True, doctor=checks, fresh_measurement=True, retained_terminal_unchanged=True)
    finally:
        cleanup_errors = []
        if dropped:
            try:
                run(*DROP[:3], "-D", "OUTPUT", *DROP[3:])
            except Exception as error:
                cleanup_errors.append(str(error))
        for connection in sockets:
            connection.close()
        for role, name in reversed(installed):
            try:
                removed = cli("service", "uninstall", "--role", role, "--name", name)
                assert removed["joined"] and removed["state"] == "uninstalled"
                assert not status(role, name).get("main_pid")
            except Exception as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise RuntimeError("owned service cleanup failed: " + "; ".join(cleanup_errors))
    assert run("iptables", "-S", "OUTPUT").stdout.strip() == "-P OUTPUT ACCEPT"
    event("complete", joined=True, private_drop_removed=True)


if __name__ == "__main__":
    main()
