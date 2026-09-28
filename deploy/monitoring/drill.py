#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Exercise alerts with owned installed daemons in an isolated Linux container.

Every state path is newly created. Signals target verified children only. No
Alertmanager or external notification service is contacted. Failed work is kept
in the printed private directory; successful work and all children are removed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def wait_for(description, check, seconds=90):
    end = time.monotonic() + seconds
    while True:
        result = check()
        if result:
            return result
        if time.monotonic() >= end:
            raise RuntimeError("timed out waiting for " + description)
        time.sleep(0.25)


def request(url, data=None, method=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(),
                                 headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--prometheus", type=Path, required=True)
    parser.add_argument("--loop-wasm", type=Path, required=True)
    args = parser.parse_args()
    dbl = (args.install_root / "bin/dbl").resolve(strict=True)
    payload = dbl.parent.parent
    prometheus = args.prometheus.resolve(strict=True)
    loop = args.loop_wasm.resolve(strict=True)
    source = Path(__file__).resolve().parent
    if "version 3.15.0" not in subprocess.check_output([prometheus, "--version"], text=True):
        raise RuntimeError("use the pinned Prometheus version")
    work = Path(tempfile.mkdtemp(prefix="debuglet-alert-drill-"))
    environment = dict(os.environ, HOME=str(work), XDG_CONFIG_HOME=str(work / "config"),
                       XDG_STATE_HOME=str(work / "state"))
    children, roles, events = [], {}, []
    passed = False
    prom_url = "http://127.0.0.1:19090"

    def cli(*arguments):
        result = subprocess.run([dbl, "--config", work / "client.json", "--output", "json", *arguments],
                                env=environment, capture_output=True, text=True, timeout=35)
        if result.returncode:
            (work / "cli-error.log").write_text(result.stderr)
            raise RuntimeError("CLI command failed; see private cli-error.log")
        return json.loads(result.stdout)

    def launch(kind, endpoint=None):
        state = work / kind
        command = [dbl, "--config", work / (kind + "-client.json"), "--output", "json",
                   kind, "up", "--state-dir", state, "--name", "alert-drill"]
        if kind == "dispatcher":
            previous = roles.get(kind)
            command += ["--port", str(urllib.parse.urlsplit(previous[1]["endpoint"]).port) if previous else "0",
                        "--grpc-port", previous[1]["grpc_address"].rsplit(":", 1)[1] if previous else "0"]
        else:
            command += ["--dispatcher", endpoint]
        with open(work / (kind + "-launcher.log"), "ab") as output:
            process = subprocess.Popen(command, env=environment, stdout=output, stderr=output)
        children.append(process)
        def started():
            if process.poll() is not None:
                raise RuntimeError(kind + " exited during startup")
            try:
                return json.loads((state / "ready.json").read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        record = wait_for(kind + " readiness", started, 40)
        roles[kind] = (process, record)
        return record

    def interrupt_daemon(kind):
        launcher = roles[kind][0]
        record = json.loads((work / kind / "child-ready.json").read_text())
        pid = record["pid"]
        # A readiness file alone does not grant permission to signal a process.
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        if int(stat[1]) != launcher.pid or executable != payload / "bin" / ("debuglet-" + kind):
            raise RuntimeError("daemon ownership check failed")
        os.kill(pid, signal.SIGKILL)
        launcher.wait(timeout=30)
        if launcher.returncode == 0:
            raise RuntimeError("abrupt daemon loss was not reported")

    def query(expression):
        try:
            answer = request(prom_url + "/api/v1/query?" + urllib.parse.urlencode({"query": expression}))
            return answer["data"]["result"]
        except (urllib.error.URLError, KeyError):
            return []

    def value(metric):
        result = query(metric + '{job="debuglet-dispatcher"}')
        return float(result[0]["value"][1]) if len(result) == 1 else None

    def firing():
        return bool(query('ALERTS{alertname="DebugletUnavailable",alertstate="firing"}'))

    def healthy():
        return (value("debuglet_api_ready") == 1 and (value("debuglet_executors_ready") or 0) >= 1
                and (value("debuglet_ready_capacity_bits_per_second") or 0) >= 1 and not firing())

    try:
        endpoint = launch("dispatcher")["endpoint"]
        launch("executor", endpoint)
        wait_for("registered executor", lambda: any(x.get("ready") for x in request(endpoint + "/executors") or []), 40)
        account = request(endpoint + "/user", {"name": "alert-drill"}, "PUT")
        subprocess.run([payload / "bin/debuglet-dispatcher", "--config", work / "dispatcher/service.toml",
                        "--grant-operator", account["id"]], env=environment, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        token = request(endpoint + "/auth/login", {"account_key": account["account_key"]}, "POST")["token"]
        credential = work / "session"
        credential.write_text(token)
        credential.chmod(0o600)
        key = work / "account-key"
        key.write_text(account["account_key"])
        key.chmod(0o600)
        cli("connect", endpoint, "--name", "alert-drill")
        cli("--dispatcher", "alert-drill", "login", "--account-key-file", str(key))
        config = work / "prometheus.yml"
        config.write_text("global:\n  scrape_interval: 15s\n  scrape_timeout: 5s\n  evaluation_interval: 15s\n"
                          + "rule_files:\n  - " + json.dumps(str(source / "alerts.yml")) + "\n"
                          + "scrape_configs:\n  - job_name: debuglet-dispatcher\n    metrics_path: /metrics\n"
                          + "    authorization:\n      credentials_file: " + json.dumps(str(credential)) + "\n"
                          + "    static_configs:\n      - targets: [" + json.dumps(urllib.parse.urlsplit(endpoint).netloc) + "]\n")
        with open(work / "prometheus.log", "wb") as output:
            prom = subprocess.Popen([prometheus, "--config.file=" + str(config),
                                     "--storage.tsdb.path=" + str(work / "prometheus"),
                                     "--web.listen-address=127.0.0.1:19090"], stdout=output, stderr=output)
        children.append(prom)
        wait_for("healthy monitored capacity", healthy, 45)
        events.append({"phase": "initial", "ready": True})
        run_id = cli("--dispatcher", "alert-drill", "run", "--wasm", str(loop), "--duration", "10m",
                     "--floor-bps", "1", "--ceil-bps", "1")["id"]
        wait_for("guest started", lambda: request(endpoint + "/debuglet/" + run_id + "/state", token=token)["state"] == "RunStateStarted", 35)
        for role in ("executor", "dispatcher"):
            began = time.monotonic()
            interrupt_daemon(role)
            wait_for(role + " loss alert", firing)
            event = {"phase": role + "_loss", "alert_firing_seconds": round(time.monotonic() - began, 3)}
            if role == "executor":
                event["dispatcher_still_live"] = request(endpoint + "/healthz")["status"] == "ok"
            events.append(event)
            if role == "dispatcher":
                old_executor = roles["executor"][0]
                if old_executor.poll() is None:
                    old_executor.send_signal(signal.SIGINT)
                old_executor.wait(timeout=30)
                launch("dispatcher")
            launch("executor", endpoint)
            began = time.monotonic()
            wait_for(role + " recovery", healthy, 45)
            wait_for("retained unknown outcome", lambda: (value("debuglet_retained_runs_unknown") or 0) >= 1, 30)
            retained = request(endpoint + "/debuglet/" + run_id + "/state", token=token)
            if retained["state"] == "RunStateExited":
                raise RuntimeError("recovery invented a terminal outcome for the lost run")
            events.append({"phase": role + "_recovery", "alert_clear_seconds": round(time.monotonic() - began, 3),
                           "retained_unknown": True, "retained_state": retained["state"]})
        passed = True
    finally:
        if not passed:
            (work / "observations.json").write_text(json.dumps({
                "events": events,
                "metrics": query('{__name__=~"debuglet_.*|up|ALERTS"}'),
            }, indent=2))
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
                if process.returncode != 0:
                    cleanup_errors.append("child did not complete a clean shutdown")
        if cleanup_errors:
            passed = False
        if passed:
            shutil.rmtree(work)
        else:
            print("Private drill diagnostics retained at " + str(work))
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
    print(json.dumps({"passed": True, "observation_budget_seconds": 90, "events": events}, indent=2))


if __name__ == "__main__":
    main()
