#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""A bounded six-pod CPU demonstration, controlled from an always-on Linux host."""

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.runpod.io/v2"
ROLES = ["dispatcher"] + [f"executor-{n}" for n in range(1, 6)]
DEFAULT_REGIONS = "EU-RO-1,EU-CZ-1,EU-NL-1,US-CA-2,US-GA-2,US-NC-2"
DISK_GB = {role: 10 if role == "dispatcher" else 5 for role in ROLES}
# Container disk price from https://docs.runpod.io/pods/pricing; compute is quoted live.
DISK_USD_GB_MONTH = 0.10


class Failure(RuntimeError):
    pass


class APIError(Failure):
    def __init__(self, status, diagnostic=None):
        self.status = status
        self.diagnostic = diagnostic or {"status": status}
        super().__init__(f"Runpod HTTP {status}; response body suppressed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, key):
        if not key or "\n" in key or "\r" in key:
            raise Failure("Set RUNPOD_API_KEY to a valid Runpod API key")
        self.key = key
        self.opener = urllib.request.build_opener(NoRedirect())

    def open(self, method, path, body=None):
        req = urllib.request.Request(API_URL + path, method=method,
            headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"},
            data=None if body is None else json.dumps(body).encode())
        try:
            return self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as exc:
            diagnostic = {"status": exc.code}
            try:
                with exc:
                    data = exc.read(4097)
                body = json.loads(data) if len(data) <= 4096 else {}
                for field in ("title", "detail"):
                    value = body.get(field) if isinstance(body, dict) else None
                    if isinstance(value, str):
                        value = value.replace(self.key, "[REDACTED]")
                        diagnostic[field] = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)[:600]
            except (OSError, ValueError):
                pass  # Preserve the HTTP status even when diagnostics are unreadable.
            raise APIError(exc.code, diagnostic) from None
        except (OSError, urllib.error.URLError):
            raise Failure("Runpod transport failed; a create may have succeeded; do not repeat it") from None

    def call(self, method, path, body=None):
        with self.open(method, path, body) as response:
            data = response.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024:
                raise Failure("Runpod response exceeded the limit")
            try:
                return json.loads(data) if data else None
            except ValueError:
                raise Failure("Runpod returned invalid JSON; a create outcome may be unknown") from None

    def pods(self):
        result, cursor, seen = [], None, set()
        while True:
            suffix = "?limit=1000" + ("&cursor=" + urllib.parse.quote(cursor, safe="") if cursor else "")
            page = self.call("GET", "/pods" + suffix)
            if not isinstance(page, dict) or not isinstance(page.get("pods"), list):
                raise Failure("Unrecognized pod listing; refusing an incomplete inventory")
            result.extend(page["pods"])
            pagination = page.get("pagination", {})
            if pagination.get("hasNextPage") is False:
                return result
            cursor = pagination.get("nextCursor")
            if not isinstance(cursor, str) or not cursor or cursor in seen or len(seen) >= 100:
                raise Failure("Incomplete or repeating Runpod pagination")
            seen.add(cursor)


def save(path, value):
    """Publish durable state; never leave a truncated inventory after interruption."""
    fd, temporary = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, indent=2, allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(state, name="inventory"):
    with (state / (name + ".lock")).open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def read(state):
    return json.loads((state / "inventory.json").read_text())


def update(state, change):
    with lock(state):
        inventory = read(state)
        result = change(inventory)
        save(state / "inventory.json", inventory)
        return result


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def package_metadata(directory, version, console):
    directory, console = directory.resolve(), console.resolve()
    if not re.fullmatch(r"v[0-9A-Za-z.+-]+", version):
        raise Failure("Invalid package version")
    archive = directory / f"debuglet-{version}-linux-amd64.tar.gz"
    checksums = directory / "SHA256SUMS"
    expected = {}
    for line in checksums.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            expected[parts[1].lstrip("*")] = parts[0]
    for path in (archive, directory / "install.sh"):
        if expected.get(path.name) != digest(path):
            raise Failure(f"Package checksum mismatch or missing entry for {path.name}")
    return {"directory": str(directory), "version": version, "archive": str(archive),
        "sha256": digest(archive), "installer_sha256": digest(directory / "install.sh"),
        "checksums_sha256": digest(checksums), "console_archive": str(console),
        "console_sha256": digest(console)}


def quote(api, flavor, regions, hours, budget):
    if not math.isfinite(hours) or not 0 < hours <= 4 or not math.isfinite(budget) or not 0 < budget <= 10:
        raise Failure("Lifetime must be at most 4 hours and budget at most 10 USD")
    catalog = api.call("GET", "/catalog/cpus?include=AVAILABILITY&product=POD&vcpuCount=2")
    cpu = next((c for c in catalog["cpus"] if c["id"] == flavor), None)
    if cpu is None or not cpu["vcpu"]["min"] <= 2 <= cpu["vcpu"]["max"] or cpu["ramGbPerVcpu"] < 2:
        raise Failure("Selected CPU flavor must provide two vCPUs and at least 4 GB RAM")
    available = {d["id"] for d in cpu.get("dataCenters", []) if d.get("availability") in ("HIGH", "MEDIUM", "LOW")}
    if not set(regions).issubset(available):
        raise Failure("One or more selected regions lack advertised CPU capacity; choose available regions before creating")
    compute = float(cpu["price"]["securePerVcpu"]) * 2
    if not math.isfinite(compute) or compute <= 0:
        raise Failure("Missing or invalid current CPU price")
    # A 25% reserve covers price movement; an actual pod exceeding its reserved
    # rate is terminated by the guard. This estimate is not a provider billing cap.
    rates = {role: 1.25 * (compute + DISK_GB[role] * DISK_USD_GB_MONTH / 720) for role in ROLES}
    estimate = sum(rates.values()) * hours
    if estimate > budget:
        raise Failure(f"Reserved estimate {estimate:.2f} USD exceeds budget {budget:.2f} USD")
    return {"checked_at": time.time(), "cpu_flavor": flavor, "reserved_hourly": rates,
        "estimated_usd": estimate, "budget_usd": budget, "hours": hours}


def plan(args, api):
    regions = args.regions.split(",")
    if len(regions) != len(ROLES) or any(not re.fullmatch(r"[A-Z0-9-]+", r) for r in regions):
        raise Failure("Supply exactly six comma-separated regions: dispatcher, then five executors")
    package = package_metadata(args.package_dir, args.version, args.console_archive)
    if package["sha256"] != args.archive_sha256 or package["console_sha256"] != args.console_sha256:
        raise Failure("Archive or console hash differs from the supplied artifact identity")
    priced = quote(api, args.cpu, regions, args.hours, args.budget)
    baseline = [p["id"] for p in api.pods()]
    state = args.state
    state.mkdir(parents=True, mode=0o700, exist_ok=False)
    run_id = secrets.token_hex(8)
    inventory = {"schema_version": 1, "run_id": run_id, "expires_at": time.time() + args.hours * 3600,
        "quote": priced, "package": package, "image": args.image, "baseline_ids": baseline,
        "planned": [{"role": role, "name": f"debuglet-demo-{run_id}-{role}", "region": region}
            for role, region in zip(ROLES, regions)], "attempts": [], "pods": [], "terminate": False}
    save(state / "inventory.json", inventory)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(state / "ssh_key")], check=True)
    print(json.dumps({"run_id": run_id, "expires_at": inventory["expires_at"], **priced}, indent=2))


def unit_name(inventory):
    run_id = inventory["run_id"]
    if not re.fullmatch(r"[0-9a-f]{16}", run_id):
        raise Failure("Invalid run identity")
    return "debuglet-demo-" + run_id + ".service"


def arm(state, key, docker_image=None):
    """Install an independent system service or a persistent Docker container."""
    if sys.platform != "linux" or (not docker_image and os.geteuid() != 0):
        raise Failure("Arm on an always-on Linux controller using sudo or --docker-image")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(state)):
        raise Failure("Guard state path must be absolute without spaces or shell characters")
    inventory = read(state)
    if time.time() >= inventory["expires_at"]:
        raise Failure("Plan already expired; do not extend it")
    owner = pwd.getpwuid(state.stat().st_uid)
    unit = unit_name(inventory)
    container = unit.removesuffix(".service")
    if docker_image:
        if not re.fullmatch(r"(?:sha256:|[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:)[0-9a-f]{64}", docker_image):
            raise Failure("Docker guard requires an immutable local image ID or repository@sha256 digest")
        if owner.pw_uid != os.getuid():
            raise Failure("Run Docker arming as the owner of the private state directory")
        subprocess.run(["docker", "image", "inspect", docker_image], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if subprocess.run(["docker", "container", "inspect", container],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise Failure("A container with this guard name already exists; inspect it instead of replacing it")
    snapshot = state / "guard-demo.py"
    shutil.copyfile(__file__, snapshot)
    keyfile = state / ".runpod-api-key"
    keyfile.write_text(key)
    for path in (snapshot, keyfile):
        path.chmod(0o600)
        os.chown(path, owner.pw_uid, owner.pw_gid)
    frozen = state / "guard-plan.json"
    if frozen.exists() and json.loads(frozen.read_text()) != {"run_id": inventory["run_id"], "expires_at": inventory["expires_at"]}:
        raise Failure("The armed deadline cannot be extended")
    save(frozen, {"run_id": inventory["run_id"], "expires_at": inventory["expires_at"]})
    os.chown(frozen, owner.pw_uid, owner.pw_gid)
    if docker_image:
        subprocess.run(["docker", "run", "--detach", "--pull", "never", "--name", container,
            "--restart", "unless-stopped", "--user", f"{os.getuid()}:{os.getgid()}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--log-opt", "max-size=1m",
            "--log-opt", "max-file=2", "--mount", f"type=bind,src={state},dst={state}",
            "--entrypoint", "/usr/bin/python3", docker_image, str(snapshot), "--state", str(state), "guard"],
            check=True, stdout=subprocess.DEVNULL)
        print(f"Armed container {container}; wait for a healthy guard heartbeat before up")
        return
    content = f"""[Unit]
Description=Debuglet demonstration expiry cleanup
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
User={owner.pw_name}
ExecStart=/usr/bin/python3 {snapshot} --state {state} guard
Restart=on-failure
RestartSec=15
NoNewPrivileges=yes
UMask=0077
[Install]
WantedBy=multi-user.target
"""
    destination = Path("/etc/systemd/system") / unit
    if destination.exists() and destination.read_text() != content:
        raise Failure("Refusing to replace a different cleanup service")
    destination.write_text(content)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", unit], check=True)
    print(f"Armed {unit}; wait for a healthy guard heartbeat before up")


def guard_ready(state, inventory):
    try:
        status = json.loads((state / "guard.json").read_text())
    except (OSError, ValueError):
        raise Failure("Independent expiry guard has not published readiness") from None
    if (status.get("run_id") != inventory["run_id"] or status.get("expires_at") != inventory["expires_at"]
            or not status.get("healthy") or time.time() - status.get("checked_at", 0) > 90):
        raise Failure("Independent expiry guard is not healthy and current")
    if inventory["terminate"] or time.time() >= inventory["expires_at"]:
        raise Failure("This plan is terminating or expired; no further creation is allowed")


def pod_path(pod_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", pod_id):
        raise Failure("Invalid provider pod ID")
    return "/pods/" + pod_id


def owned(inventory, pods):
    """Match exact attempted names, retaining baseline exclusions and known IDs."""
    expected = {f"debuglet-demo-{inventory['run_id']}-{role}" for role in ROLES}
    names = {a["name"] for a in inventory["attempts"]}
    if not names.issubset(expected):
        raise Failure("Creation records contain a name outside this demonstration")
    recorded = {p["id"]: p["name"] for p in inventory["pods"]}
    found = []
    for pod in pods:
        if pod["id"] in inventory["baseline_ids"]:
            continue
        if pod["id"] in recorded and pod["name"] != recorded[pod["id"]]:
            continue  # cleanup_once diagnoses it without blocking cleanup of other owned pods.
        if pod["name"] in names:
            found.append(pod)
    return found


def adopt(inventory, pods):
    for pod in pods:
        attempt = next(a for a in inventory["attempts"] if a["name"] == pod["name"])
        if not any(p["id"] == pod["id"] for p in inventory["pods"]):
            inventory["pods"].append({"id": pod["id"], "name": pod["name"], "role": attempt["role"],
                "region": attempt["region"], "hostkey_nonce": attempt["hostkey_nonce"]})
        attempt["outcome"] = "found"


def cleanup_once(state, api):
    inventory = read(state)
    targets = owned(inventory, api.pods())
    update(state, lambda inv: adopt(inv, targets))
    errors = []
    # Also inspect recorded IDs absent from a listing; absence alone is not proof.
    for pod in read(state)["pods"]:
        try:
            try:
                current = api.call("GET", pod_path(pod["id"]))
            except APIError as exc:
                if exc.status == 404:
                    continue
                raise
            if current["id"] != pod["id"] or current["id"] in inventory["baseline_ids"] or current["name"] != pod["name"]:
                raise Failure("Pod identity/name guard refused termination")
            try:
                api.call("DELETE", pod_path(pod["id"]))
            except APIError as exc:
                if exc.status != 404:
                    raise
            try:
                api.call("GET", pod_path(pod["id"]))
                errors.append(pod["role"] + ": termination not yet confirmed")
            except APIError as exc:
                if exc.status != 404:
                    raise
        except Failure as exc:
            errors.append(pod["role"] + ": " + str(exc))
    uncertain = any(a["outcome"] == "unknown" for a in read(state)["attempts"])
    complete = not errors and not uncertain
    save(state / "cleanup.json", {"run_id": inventory["run_id"], "checked_at": time.time(),
        "complete": complete, "uncertain_create": uncertain, "errors": errors})
    return complete


def guard_once(state, api, frozen=None):
    inventory = read(state)
    frozen = frozen or {"run_id": inventory["run_id"], "expires_at": inventory["expires_at"]}
    if inventory["run_id"] != frozen["run_id"]:
        raise Failure("Armed guard identity differs from inventory")
    # Expiry and requested cleanup must not depend on optional billing fields.
    if time.time() >= frozen["expires_at"]:
        update(state, lambda inv: inv.update(terminate=True))
    if not read(state)["terminate"]:
        pods = owned(inventory, api.pods())
        def observe(inv):
            adopt(inv, pods)
            for pod in pods:
                role = next(a["role"] for a in inv["attempts"] if a["name"] == pod["name"])
                try:
                    cost = float(pod.get("cost"))
                except (TypeError, ValueError, OverflowError):
                    inv["terminate"] = True
                    continue
                mounts = pod.get("mounts") or {}
                if (not math.isfinite(cost) or cost < 0 or cost > inv["quote"]["reserved_hourly"][role]
                        or pod.get("gpu") or not isinstance(mounts, dict) or any(mounts.values())):
                    inv["terminate"] = True
        update(state, observe)
    inventory = read(state)
    save(state / "guard.json", {"run_id": inventory["run_id"], "expires_at": frozen["expires_at"],
        "checked_at": time.time(), "healthy": True, "terminating": inventory["terminate"]})
    return inventory["terminate"] and cleanup_once(state, api)


def guard(state, api):
    with lock(state, "guard"):
        frozen = json.loads((state / "guard-plan.json").read_text())
        while True:
            try:
                if guard_once(state, api, frozen):
                    return
            except Exception:
                # Remote bodies, environment and API credentials never reach logs.
                inventory = read(state)
                save(state / "guard.json", {"run_id": inventory["run_id"], "expires_at": inventory["expires_at"],
                    "checked_at": time.time(), "healthy": False})
            time.sleep(15)


def create_body(inventory, planned, public_key, nonce):
    startup = f"""set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openssh-server ca-certificates python3 supervisor curl xz-utils openssl nginx
install -d -m 700 /root/.ssh
printf '%s\\n' "$PUBLIC_KEY" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
mkdir -p /run/sshd
ssh-keygen -A
printf 'DEBUGLET_HOSTKEY {nonce} '
cat /etc/ssh/ssh_host_ed25519_key.pub
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=prohibit-password
"""
    return {"name": planned["name"], "image": inventory["image"], "cloud": "SECURE",
        "cpu": {"id": inventory["quote"]["cpu_flavor"], "vcpuCount": 2}, "disk": DISK_GB[planned["role"]],
        "dataCenterIds": [planned["region"]], "globalNetworking": False,
        "ports": ["22/tcp"] + (["9000/tcp", "9001/tcp", "8080/http"] if planned["role"] == "dispatcher" else ["70000/tcp"]),
        "env": {"PUBLIC_KEY": public_key}, "entrypoint": ["/bin/bash", "-lc"], "cmd": [startup]}


def up(state, api):
    with lock(state, "up"):
        inv = read(state)
        pkg = inv["package"]
        if package_metadata(Path(pkg["directory"]), pkg["version"], Path(pkg["console_archive"])) != pkg:
            raise Failure("Package inputs changed after planning")
        fresh = quote(api, inv["quote"]["cpu_flavor"], [p["region"] for p in inv["planned"]],
            inv["quote"]["hours"], inv["quote"]["budget_usd"])
        if fresh["estimated_usd"] > inv["quote"]["estimated_usd"]:
            raise Failure("Current price exceeds the reviewed plan; no creation attempted")
        for planned in inv["planned"]:
            current = read(state)
            guard_ready(state, current)
            if any(a["outcome"] == "unknown" for a in current["attempts"]):
                raise Failure("Uncertain create retained; use status to reconcile, never repeat POST")
            prior = [a for a in current["attempts"] if a["role"] == planned["role"]]
            if prior:
                if prior[0]["outcome"] in ("created", "found"):
                    continue
                raise Failure("This role already had a creation attempt; inspect it instead of recreating")
            if any(p["name"] == planned["name"] for p in api.pods()):
                raise Failure("Planned name already exists; refusing duplicate creation")
            attempt = {**planned, "hostkey_nonce": secrets.token_hex(16), "outcome": "unknown", "requested_at": time.time()}
            def begin(x):
                guard_ready(state, x)
                x["attempts"].append(attempt)
            update(state, begin)
            # Deliberately one POST, with its intent durably recorded first.
            try:
                created = api.call("POST", "/pods", create_body(current, planned, (state / "ssh_key.pub").read_text(), attempt["hostkey_nonce"]))
            except APIError as exc:
                if exc.status in (400, 422):
                    def reject(x):
                        recorded = next(a for a in x["attempts"] if a["name"] == planned["name"])
                        recorded.update(outcome=f"rejected_http_{exc.status}", rejection=exc.diagnostic)
                    update(state, reject)
                    raise Failure(f"Runpod rejected this create (HTTP {exc.status}); inspect the private inventory diagnostic, "
                                  "then replan the region/specification. Do not blindly retry this request.") from None
                raise
            pod_id = created.get("id") if isinstance(created, dict) else None
            if not isinstance(pod_id, str) or not pod_id:
                raise Failure("Create response has no ID; reconcile the exact name before continuing")
            def retain(x):
                if not any(p["id"] == pod_id for p in x["pods"]):
                    x["pods"].append({**planned, "id": pod_id, "hostkey_nonce": attempt["hostkey_nonce"]})
                next(a for a in x["attempts"] if a["name"] == planned["name"])["outcome"] = "created"
            update(state, retain)
            if created.get("name") != planned["name"]:
                raise Failure("Create returned an unexpected name; retained ID requires inspection")
            print(f"Created {planned['role']}", flush=True)
        refresh(state, api, wait_seconds=900)


def metadata(pod, response, inventory):
    if response["id"] != pod["id"] or response["name"] != pod["name"]:
        raise Failure("Pod identity/name mismatch")
    if response.get("dataCenterId") not in (None, pod["region"]):
        raise Failure("Provider placed a pod outside its requested region")
    cpu = response.get("cpu") or {}
    if cpu and (cpu.get("id") != inventory["quote"]["cpu_flavor"] or cpu.get("vcpuCount") != 2):
        raise Failure("Actual CPU differs from the plan")
    cost = float(response.get("cost", 0))
    if (not math.isfinite(cost) or cost > inventory["quote"]["reserved_hourly"][pod["role"]]
            or response.get("gpu") or any((response.get("mounts") or {}).values())):
        raise Failure("Actual pod shape or cost exceeds the plan; expiry guard will terminate it")
    fields = {"status": response["status"], "cost_per_hour": cost}
    direct = (response.get("ssh") or {}).get("direct")
    ports = (response.get("runtime") or {}).get("ports") or []
    if direct and ipaddress.ip_address(direct["host"]).version == 4 and ipaddress.ip_address(direct["host"]).is_global:
        fields.update(public_ip=direct["host"], ssh_port=int(direct["port"]))
    if pod["role"] == "dispatcher":
        for private, key in ((9000, "api_port"), (9001, "control_port")):
            match = next((p for p in ports if p["private"] == private and p["type"] == "tcp"), None)
            if match:
                fields[key] = match["public"]
        fields["console_url"] = f"https://{pod['id']}-8080.proxy.runpod.net"
    else:
        symmetric = [p for p in ports if p["type"] == "tcp" and p["private"] == p["public"] and 1024 <= p["public"] <= 65535]
        if len(symmetric) == 1:
            fields["peer_port"] = symmetric[0]["public"]
    return fields


def host_key(api, pod):
    marker = "DEBUGLET_HOSTKEY " + pod["hostkey_nonce"] + " "
    until = time.monotonic() + 30
    with api.open("GET", pod_path(pod["id"]) + "/logs?source=container&tail=5000") as response:
        for line in response:
            if time.monotonic() > until:
                break
            if not line.startswith(b"data:"):
                continue
            event = json.loads(line[5:])
            message = event.get("line", "")
            if marker in message:
                key = message.split(marker, 1)[1].strip()
                if re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+=*(?: [^\r\n]*)?", key):
                    return " ".join(key.split()[:2])
    raise Failure("Bootstrap host key is not yet present in authenticated provider logs")


def refresh(state, api, wait_seconds=0):
    until = time.monotonic() + wait_seconds
    while True:
        inv = read(state)
        matches = owned(inv, api.pods())
        update(state, lambda x: adopt(x, matches))
        ready = 0
        for pod in read(state)["pods"]:
            response = api.call("GET", pod_path(pod["id"]))
            fields = metadata(pod, response, inv)
            if "host_public_key" not in pod and fields.get("ssh_port"):
                try:
                    fields["host_public_key"] = host_key(api, pod)
                except Failure:
                    pass
            update(state, lambda x: next(p for p in x["pods"] if p["id"] == pod["id"]).update(fields))
            merged = {**pod, **fields}
            required = ["public_ip", "ssh_port", "host_public_key"] + (["api_port", "control_port"] if pod["role"] == "dispatcher" else ["peer_port"])
            ready += all(merged.get(k) for k in required)
        inv = read(state)
        known = [p["id"] + " " + p["host_public_key"] for p in inv["pods"] if p.get("host_public_key")]
        (state / "known_hosts").write_text("\n".join(known) + "\n")
        if ready == len(ROLES) or time.monotonic() >= until:
            print(json.dumps({"management_ready_pods": ready, "required_pods": len(ROLES), "expires_at": inv["expires_at"],
                "uncertain_create": any(a["outcome"] == "unknown" for a in inv["attempts"]),
                "pods": [{k: p[k] for k in ("role", "id", "status", "public_ip", "peer_port", "console_url") if k in p} for p in inv["pods"]]}, indent=2))
            if wait_seconds and ready != len(ROLES):
                raise Failure("Pods did not become ready; guard remains armed; inspect status or run down")
            return
        if inv["terminate"] or time.time() >= inv["expires_at"]:
            raise Failure("Plan expired while waiting; guard will terminate pods")
        time.sleep(10)


def fault(state, source, target):
    if (source, target) != (-1, -1) and not (0 <= source < 5 and 0 <= target < 5 and source != target):
        raise Failure("Use -1/-1 for healthy, or two distinct roles between 0 and 4")
    result = {"label": "Healthy" if source == -1 else "Simulated connection failure",
        "scope": "Next trial only; application suppresses a directed pair before TCP dial/write. No network packet loss is injected.",
        "guest_args": [f"-blocked-from={source}", f"-blocked-to={target}"]}
    save(state / "fault.json", result)
    print(json.dumps(result, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=lambda p: Path(p).resolve())
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("plan", help="Read-only cloud quote; create a local immutable four-hour plan")
    p.add_argument("--package-dir", type=Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--console-archive", type=Path, required=True)
    p.add_argument("--archive-sha256", required=True)
    p.add_argument("--console-sha256", required=True)
    p.add_argument("--regions", default=DEFAULT_REGIONS)
    p.add_argument("--cpu", default="cpu3c")
    p.add_argument("--image", default="ubuntu:24.04")
    p.add_argument("--hours", type=float, default=4)
    p.add_argument("--budget", type=float, default=10)
    p = commands.add_parser("arm")
    p.add_argument("--docker-image", help="Use an existing immutable local Python/CA image instead of systemd")
    for name in ("up", "status", "bootstrap", "down", "guard"):
        commands.add_parser(name)
    p = commands.add_parser("fault")
    p.add_argument("--from-role", type=int, default=-1)
    p.add_argument("--to-role", type=int, default=-1)
    args = parser.parse_args()
    if args.command == "fault":
        fault(args.state, args.from_role, args.to_role)
        return
    if args.command == "bootstrap":
        guard_ready(args.state, read(args.state))
        subprocess.run([sys.executable, str(Path(__file__).with_name("bootstrap.py")), "--state", str(args.state)], check=True)
        return
    key = (args.state / ".runpod-api-key").read_text() if args.command == "guard" else os.environ.get("RUNPOD_API_KEY", "")
    api = API(key)
    if args.command == "plan":
        plan(args, api)
    elif args.command == "arm":
        arm(args.state, key, args.docker_image)
    elif args.command == "up":
        up(args.state, api)
    elif args.command == "status":
        refresh(args.state, api)
    elif args.command == "guard":
        guard(args.state, api)
    elif args.command == "down":
        update(args.state, lambda x: x.update(terminate=True))
        if not cleanup_once(args.state, api):
            raise Failure("Cleanup is incomplete; guard continues retrying; inspect cleanup.json")
        print("Confirmed all recorded pods absent; independent guard will also reconcile attempted names")


if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        # Provider response bodies and subprocess output are intentionally excluded.
        print(str(exc) if isinstance(exc, Failure) else f"{type(exc).__name__}: operation failed; inspect local state", file=sys.stderr)
        sys.exit(1)
