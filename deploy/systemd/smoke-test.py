#!/usr/bin/env python3
"""Check an installed full bundle in an explicitly disposable Docker/systemd fixture.

Requires root, Python 3, systemd, a debuglet account and /usr/local/bin/dbl.
The caller installs the exact archive, sets DEBUGLET_SERVICE_FIXTURE=1 and owns
container teardown. Never run against a host or a container with existing roles.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time

DBL = "/usr/local/bin/dbl"
ROLES = (("dispatcher", "local"), ("executor", "worker"))
STATE = Path("/var/lib/debuglet/executors/worker")
CFG = STATE / "service.toml"


def run(*args, ok=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if ok and result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result


def dbl(*args, ok=True):
    result = run(DBL, "--output", "json", *args, ok=ok)
    return json.loads(result.stdout), result.returncode


def event(name, value):
    print(json.dumps({"check": name, "result": value}), flush=True)


def wait_for(probe, description):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(0.2)
    raise AssertionError("timed out: " + description)


def status(role, name):
    report, _ = dbl("service", "status", "--role", role, "--name", name, ok=False)
    return report


def ready(role, name):
    def probe():
        report = status(role, name)
        return report if report.get("ready") else None
    return wait_for(probe, role + " readiness")


def sandbox(unit, command, *, wait=True, hide_btf=False):
    args = ["systemd-run", "--quiet", "--unit", unit]
    if wait:
        args += ["--wait", "--pipe", "--collect"]
    for setting in ["User=debuglet", "Group=debuglet", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectControlGroups=yes", "ProtectKernelModules=yes", "ReadWritePaths=" + str(STATE)]:
        args += ["--property", setting]
    if hide_btf:
        args += ["--property", "InaccessiblePaths=-/sys/kernel/btf"]
    return run(*args, *command, ok=False)


def doctor(config=CFG, *, hide_btf=False):
    result = sandbox("debuglet-profile-doctor", [DBL, "--output", "json", "doctor", "--role", "executor", "--file", str(config), "--offline"], hide_btf=hide_btf)
    report = json.loads(result.stdout)
    event("doctor", report)
    return {item["id"]: item["status"] for item in report["checks"]}, result.returncode


def main():
    if not __debug__ or os.geteuid() != 0 or os.environ.get("DEBUGLET_SERVICE_FIXTURE") != "1":
        raise RuntimeError("explicit disposable fixture opt-in and enabled assertions required")
    if Path("/run/systemd/container").read_text().strip() != "docker" or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("Docker fixture with systemd as PID 1 required")
    if list(Path("/etc/debuglet/services").glob("*.json")):
        raise RuntimeError("fixture already contains managed roles")
    event("identity", dbl("version")[0])
    event("environment", {"os": Path("/etc/os-release").read_text(), "kernel": os.uname().release, "architecture": os.uname().machine, "systemd": run("systemctl", "--version").stdout.splitlines()[0], "cgroup": run("stat", "-fc", "%T", "/sys/fs/cgroup").stdout.strip()})
    run("systemd-run", "--quiet", "--unit", "debuglet-profile-unrelated", "/usr/bin/sleep", "infinity")
    try:
        dispatcher, _ = dbl("service", "install", "--role", "dispatcher", "--name", "local")
        executor, _ = dbl("service", "install", "--role", "executor", "--name", "worker", "--dispatcher", "127.0.0.1:9001")
        assert dispatcher["ready"] and executor["ready"]
        event("installed", [dispatcher, executor])
        identity = executor["executor_id"]
        for role, name in ROLES:
            pid = ready(role, name)["main_pid"]
            process = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            assert int(process["CapEff"].strip(), 16) == 0 and process["NoNewPrivs"].strip() == "1"
            event("service_identity", {"role": role, "uid": process["Uid"].strip(), "capabilities": process["CapEff"].strip(), "no_new_privileges": process["NoNewPrivs"].strip()})
        run(DBL, "connect", "http://127.0.0.1:9000", "--name", "managed")
        run(DBL, "--dispatcher", "managed", "login", "--register", "profile-researcher")
        wait_for(lambda: any(node.get("ready") for node in dbl("--dispatcher", "managed", "nodes")[0]), "dispatcher discovery readiness")
        receipt, _ = dbl("--dispatcher", "managed", "run", "--sample", "hello", "--wait", "--", "managed-profile")
        assert receipt["state"] == "RunStateExited"
        run_id = receipt["id"]
        event("run", receipt)
        logs = run(DBL, "--dispatcher", "managed", "logs", run_id).stdout
        assert "managed-profile" in logs
        run("systemctl", "restart", "debuglet-executor-worker.service")
        assert ready("executor", "worker")["executor_id"] == identity
        assert run(DBL, "--dispatcher", "managed", "logs", run_id).stdout == logs
        event("restart", "identity and completed run retained")
        drained, _ = dbl("drain", "--role", "executor", "--name", "worker", "--wait", "30s")
        assert drained["joined"] and drained["active"] == "inactive"
        checks, code = doctor()
        assert code == 0 and checks["state_permissions"] == "pass" and checks["schema"] == "pass"
        assert checks["btf"] == "not_checked" and checks["capabilities"] == "not_checked"
        database = STATE / "executor.sqlite"
        database.chmod(0o400)
        try:
            checks, code = doctor()
            assert code == 1 and checks["state_permissions"] == "failure"
            run("systemctl", "start", "debuglet-executor-worker.service")
            failure = wait_for(lambda: run("systemctl", "show", "-p", "Result", "--value", "debuglet-executor-worker.service").stdout.strip() == "exit-code", "read-only database startup failure")
            event("permission_negative", {"doctor": checks["state_permissions"], "startup_failed": failure})
        finally:
            run("systemctl", "stop", "debuglet-executor-worker.service", ok=False)
            database.chmod(0o600)
        automatic = STATE / "profile-auto.toml"
        config = CFG.read_text()
        config, changed = re.subn(r"(?m)^\s*packet_counter\s*=.*$", 'packet_counter = "auto"', config)
        assert changed == 1
        config, changed = re.subn(r"(?m)^\s*interface\s*=.*$", 'interface = "lo"', config)
        assert changed == 1
        automatic.write_text(config)
        automatic.chmod(0o600)
        os.chown(automatic, database.stat().st_uid, database.stat().st_gid)
        checks, code = doctor(automatic, hide_btf=True)
        assert code == 0 and checks["btf"] == "not_checked" and checks["capabilities"] == "not_checked"
        daemon = str(Path(DBL).resolve().parent / "debuglet-executor")
        auto_ready = STATE / "profile-auto-ready.json"
        started = sandbox("debuglet-profile-auto", [daemon, "--config", str(automatic), "--ready-file", str(auto_ready)], wait=False, hide_btf=True)
        assert started.returncode == 0
        wait_for(auto_ready.exists, "automatic counter fallback readiness")
        journal = run("journalctl", "-u", "debuglet-profile-auto", "--no-pager", "-o", "cat").stdout
        assert '"packet_counter":"fallback"' in journal
        event("kernel_negative", {"btf_hidden": True, "capabilities": "none", "ready": True, "counter": "fallback"})
        run("systemctl", "stop", "debuglet-profile-auto")
        automatic.unlink()
        auto_ready.unlink(missing_ok=True)
        resumed, _ = dbl("drain", "--role", "executor", "--name", "worker", "--resume")
        assert resumed["ready"]
        override = Path("/run/systemd/system/debuglet-executor-worker.service.d/stop-refusal.conf")
        override.parent.mkdir()
        override.write_text("[Unit]\nRefuseManualStop=yes\n")
        try:
            run("systemctl", "daemon-reload")
            assert run("systemctl", "stop", "debuglet-executor-worker.service", ok=False).returncode != 0
            refused, code = dbl("service", "uninstall", "--role", "executor", "--name", "worker", ok=False)
            assert code != 0 and refused.get("state") != "uninstalled" and database.exists()
            assert run("systemctl", "is-active", "debuglet-executor-worker.service").stdout.strip() == "active"
            event("failed_stop_and_override", refused)
        finally:
            override.unlink()
            override.parent.rmdir()
            run("systemctl", "daemon-reload")
        stopped, _ = dbl("service", "stop", "--role", "executor", "--name", "worker")
        assert stopped["joined"]
        before = {name: hashlib.sha256((STATE / name).read_bytes()).hexdigest() for name in ["executor.sqlite", "role-state.json", "service.toml"]}
        removed, _ = dbl("service", "uninstall", "--role", "executor", "--name", "worker")
        assert removed["joined"] and removed["state"] == "uninstalled"
        assert all(hashlib.sha256((STATE / name).read_bytes()).hexdigest() == digest for name, digest in before.items())
        assert ready("dispatcher", "local")["main_pid"] == dispatcher["main_pid"]
        assert run("systemctl", "is-active", "debuglet-profile-unrelated").stdout.strip() == "active"
        reinstalled, _ = dbl("service", "install", "--role", "executor", "--name", "worker", "--dispatcher", "127.0.0.1:9001")
        assert reinstalled["ready"] and reinstalled["executor_id"] == identity
        assert run(DBL, "--dispatcher", "managed", "logs", run_id).stdout == logs
        event("remove_reinstall", {"executor_id": identity, "retained_files_unchanged_by_removal": list(before), "dispatcher_uninterrupted": True, "unrelated_unit_running": True})
    finally:
        for role, name in reversed(ROLES):
            result = run(DBL, "--output", "json", "service", "uninstall", "--role", role, "--name", name, ok=False)
            event("cleanup_" + role, {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        run("systemctl", "stop", "debuglet-profile-auto", "debuglet-profile-unrelated", ok=False)
    assert all(not status(role, name).get("main_pid") for role, name in ROLES)
    event("complete", "managed fallback profile passed; caller must remove the disposable container")


if __name__ == "__main__":
    main()
