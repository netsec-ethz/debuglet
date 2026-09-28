#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Exercise actual storage pressure and offline backup results in an owned container.

The pressure directory must be a dedicated small tmpfs (64 MiB), never a host
filesystem. The metrics and backup packages may be separate installed versions.
Only new fixture state and the drill's own filler file are removed on success.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse

from drill import request, wait_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("install-root", "backup-install-root", "prometheus", "node-exporter", "pressure-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    pressure = args.pressure_dir.resolve(strict=True)
    if subprocess.check_output(["stat", "-f", "-c", "%T", pressure], text=True).strip() != "tmpfs" or os.statvfs(pressure).f_blocks * os.statvfs(pressure).f_frsize > 128 * 1024 * 1024:
        raise RuntimeError("pressure directory must be a dedicated tmpfs of at most 128 MiB")
    for binary, version in ((args.prometheus, "3.15.0"), (args.node_exporter, "1.12.1")):
        if "version " + version not in subprocess.check_output([binary, "--version"], text=True, stderr=subprocess.STDOUT):
            raise RuntimeError("use pinned monitoring binaries")
    work = Path(tempfile.mkdtemp(prefix="debuglet-storage-drill-"))
    state = Path(tempfile.mkdtemp(prefix="debuglet-state-", dir=pressure))
    environment = dict(os.environ, HOME=str(work), XDG_CONFIG_HOME=str(work / "config"), XDG_STATE_HOME=str(work / "state"))
    source = Path(__file__).resolve().parent
    children, events = [], []
    passed = False
    prom_url = "http://127.0.0.1:19090"
    node_exporter = None

    def start(command, name):
        with (work / (name + ".log")).open("ab") as output:
            process = subprocess.Popen(command, env=environment, stdout=output, stderr=output)
        children.append(process)
        return process

    def role(prefix, directory, name):
        process = start([prefix / "bin/dbl", "--output", "json", "dispatcher", "up", "--port", "0", "--grpc-port", "0", "--state-dir", directory, "--name", name], name)
        def ready():
            if process.poll() is not None:
                raise RuntimeError(name + " exited during startup")
            try:
                return json.loads((directory / "ready.json").read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        return process, wait_for(name + " readiness", ready, 40)

    def query(expression):
        try:
            return request(prom_url + "/api/v1/query?" + urllib.parse.urlencode({"query": expression}))["data"]["result"]
        except OSError:
            return []

    def alert(name):
        return bool(query('ALERTS{alertname="' + name + '",alertstate="firing"}'))

    def backup(destination, success):
        command = [sys.executable, source / "backup-metrics.py", "--dbl", args.backup_install_root / "bin/dbl", "--state-dir", work / "backup-state", "--destination", destination, "--metrics-file", work / "textfile/backup.prom", "--offline"]
        result = subprocess.run(command, env=environment, capture_output=True, timeout=320)
        if (result.returncode == 0) != success:
            (work / "backup-error.log").write_bytes(result.stderr)
            raise RuntimeError("unexpected backup result; see private backup-error.log")

    try:
        _, record = role(args.install_root, state, "storage-drill")
        endpoint = record["endpoint"]
        account = request(endpoint + "/user", {"name": "storage-drill"}, "PUT")
        payload = (args.install_root / "bin/dbl").resolve().parent
        subprocess.run([payload / "debuglet-dispatcher", "--config", state / "service.toml", "--grant-operator", account["id"]], env=environment, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        token = request(endpoint + "/auth/login", {"account_key": account["account_key"]}, "POST")["token"]
        credential = work / "session"
        credential.write_text(token)
        credential.chmod(0o600)
        textfile = work / "textfile"
        textfile.mkdir(mode=0o755)
        node_exporter = start([args.node_exporter, "--collector.disable-defaults", "--collector.textfile", "--collector.textfile.directory=" + str(textfile), "--web.listen-address=127.0.0.1:19100"], "node-exporter")
        config = {"global": {"scrape_interval": "15s", "scrape_timeout": "5s", "evaluation_interval": "15s"},
                  "rule_files": [str(source / "storage-alerts.yml")],
                  "scrape_configs": [{"job_name": "debuglet-dispatcher", "metrics_path": "/metrics", "authorization": {"credentials_file": str(credential)}, "static_configs": [{"targets": [urllib.parse.urlsplit(endpoint).netloc]}]},
                                     {"job_name": "debuglet-backup", "static_configs": [{"targets": ["127.0.0.1:19100"]}]}]}
        (work / "prometheus.json").write_text(json.dumps(config))
        start([args.prometheus, "--config.file=" + str(work / "prometheus.json"), "--storage.tsdb.path=" + str(work / "prometheus"), "--web.listen-address=127.0.0.1:19090"], "prometheus")
        wait_for("initial storage observation", lambda: query('debuglet_state_available_bytes{job="debuglet-dispatcher"}'), 40)
        if alert("DebugletStateStorageLow"):
            raise RuntimeError("initial storage is not healthy")
        filler = state / "drill-filler"
        space = os.statvfs(state)
        with filler.open("wb") as output:
            remaining = int((space.f_bavail - space.f_blocks * 0.05) * space.f_frsize)
            while remaining > 0:
                size = min(remaining, 1024 * 1024)
                output.write(b"x" * size)
                remaining -= size
            output.flush()
            os.fsync(output.fileno())
        began = time.monotonic()
        wait_for("low storage alert", lambda: alert("DebugletStateStorageLow"))
        events.append({"phase": "storage_pressure", "alert_firing_seconds": round(time.monotonic() - began, 3)})
        filler.unlink()  # Only the file created above; database and sidecars remain.
        wait_for("storage recovery", lambda: not alert("DebugletStateStorageLow"), 45)
        wait_for("missing backup observation", lambda: alert("DebugletBackupFailed") and alert("DebugletBackupStale"))
        process, _ = role(args.backup_install_root, work / "backup-state", "backup-drill")
        process.send_signal(signal.SIGINT)
        if process.wait(timeout=35) != 0:
            raise RuntimeError("backup fixture did not complete a clean shutdown")
        backup(work / "backup-one", True)
        wait_for("verified backup recovery", lambda: not alert("DebugletBackupFailed") and not alert("DebugletBackupStale"), 45)
        before = (textfile / "backup.prom").read_text().split("debuglet_backup_last_verified_timestamp_seconds ")[-1].strip()
        backup(work / "backup-one", False)  # An existing destination must fail.
        after = (textfile / "backup.prom").read_text().split("debuglet_backup_last_verified_timestamp_seconds ")[-1].strip()
        if after != before:
            raise RuntimeError("failed backup advanced verified freshness")
        began = time.monotonic()
        wait_for("failed backup alert", lambda: alert("DebugletBackupFailed"))
        events.append({"phase": "backup_failure", "alert_firing_seconds": round(time.monotonic() - began, 3), "verified_timestamp_preserved": True})
        backup(work / "backup-two", True)
        wait_for("backup recovery", lambda: not alert("DebugletBackupFailed") and not alert("DebugletBackupStale"), 45)
        events.append({"phase": "backup_recovery", "verified": True})
        passed = True
    finally:
        if not passed:
            (work / "observations.json").write_text(json.dumps(query('{__name__=~"debuglet_.*|node_textfile_.*|up|ALERTS"}'), indent=2))
        cleanup_errors = []
        for process in reversed(children):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    cleanup_errors.append("child required forced termination")
                # Pinned node_exporter has no SIGINT handler; its requested
                # signal exit is normal. Role launchers must report clean join.
                expected = (0, -signal.SIGINT) if process is node_exporter else (0,)
                if process.returncode not in expected:
                    cleanup_errors.append(f"{Path(process.args[0]).name} exited {process.returncode} during cleanup")
        if cleanup_errors:
            passed = False
            (work / "cleanup-errors.json").write_text(json.dumps({"events": events, "errors": cleanup_errors}, indent=2))
        if passed:
            shutil.rmtree(work)
            shutil.rmtree(state)
        else:
            print("Private drill diagnostics retained at " + str(work) + " and " + str(state))
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
    print(json.dumps({"passed": True, "observation_budget_seconds": 90, "events": events}, indent=2))


if __name__ == "__main__":
    main()
