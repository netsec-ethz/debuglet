#!/usr/bin/env python3
"""Auditable isolation checks for the privileged kernel CI lane.

The kernel lane loads eBPF programs, so it runs on a separate runner with a
small set of extra capabilities. This script records what that runner actually
handed the job and fails the job when the guarantees the lane depends on are
absent:

* CI runs on a fresh GitHub-hosted Linux VM at the event's exact commit;
* the job holds no release or deployment credentials, in its environment or on
  disk, and no route to the host's container daemon;
* its capabilities are limited to the ones eBPF loading needs;
* it runs in its own process namespace;
* it leaves behind no process, and no BPF program, map or link handle, that it
  did not hold before its tests.

Subcommands:

    assert              check the guarantees above and record the evidence
    snapshot <label>    record owned BPF handles and processes
    compare             compare the "before" and "after" snapshots

`compare` diffs the process table and the per-process BPF file descriptors of
the two snapshots. The pinned bpffs listing and the bpftool output the
snapshots also carry are recorded for review, not diffed: enumerating BPF
objects by id needs CAP_SYS_ADMIN, which this lane deliberately does not hold,
so `bpftool prog show` usually records a permission error here.

Outside GitHub Actions the checks are recorded but never fail, so `make ci-kernel`
stays usable on a developer machine. Set DEBUGLET_CI_ISOLATION_ENFORCE=1 to
enforce them anyway; the checks that read GitHub's own job variables then fail,
because those variables do not exist outside CI. The variable cannot turn
enforcement off inside CI. The provisioning profile these checks describe is in
deploy/ci/README.md.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping

EVIDENCE_DIR = os.path.join(".cache", "ci", "ci-image-evidence")

CAPABILITIES = (
    "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID "
    "CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_LINUX_IMMUTABLE "
    "CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_ADMIN CAP_NET_RAW "
    "CAP_IPC_LOCK CAP_IPC_OWNER CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_CHROOT "
    "CAP_SYS_PTRACE CAP_SYS_PACCT CAP_SYS_ADMIN CAP_SYS_BOOT CAP_SYS_NICE "
    "CAP_SYS_RESOURCE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_MKNOD CAP_LEASE "
    "CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_SETFCAP CAP_MAC_OVERRIDE "
    "CAP_MAC_ADMIN CAP_SYSLOG CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_AUDIT_READ "
    "CAP_PERFMON CAP_BPF CAP_CHECKPOINT_RESTORE"
).split()

# Loading and attaching the tagger and packet counter needs these.
REQUIRED_CAPABILITIES = ("CAP_BPF", "CAP_PERFMON", "CAP_NET_ADMIN", "CAP_SYS_RESOURCE")

# Any of these would let the job leave its own boundary.
FORBIDDEN_CAPABILITIES = (
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_DAC_READ_SEARCH",
    "CAP_MAC_ADMIN",
)

# Environment names that would indicate release or deployment material.
CREDENTIAL_PATTERNS = (
    "*TOKEN*", "*PASSWORD*", "*PASSWD*", "*SECRET*", "*CREDENTIAL*",
    "*PASSPHRASE*", "*PRIVATE_KEY*", "*SIGNING*", "*_KEY", "*KEYFILE*",
    "AWS_*", "VAULT_*", "ANSIBLE_VAULT*", "DEPLOY_*", "RELEASE_*",
    "DOCKER_AUTH_CONFIG", "NETRC", "SSH_AUTH_SOCK",
)

CREDENTIAL_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc/gitlab-runner/config.toml",
    "/actions-runner/.credentials",
    ".runner",
    ".credentials",
    ".credentials_rsaparams",
    "~/.netrc",
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.docker/config.json",
    "~/.gitlab-runner",
    "deploy/certs",
    "deploy/ansible/hosts.yml",
    "deploy/ansible/hosts.dev.yml",
)

FORBIDDEN_MOUNTS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/etc/gitlab-runner",
    "/root/.ssh",
    "/root/.docker",
)

HOST_INIT_NAMES = ("systemd", "init", "upstart")


def enforcing() -> bool:
    """CI always enforces; the override can only add enforcement elsewhere."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return True
    return os.environ.get("DEBUGLET_CI_ISOLATION_ENFORCE") == "1"


def github_metadata_checks(environ: Mapping[str, str], checkout_sha: str) -> list[dict]:
    """Check platform facts forwarded by the trusted container launcher."""
    results: list[dict] = []
    check(results, "github-actions", environ.get("GITHUB_ACTIONS") == "true",
          "the kernel lane requires GitHub Actions metadata")
    event = environ.get("GITHUB_EVENT_NAME", "")
    check(results, "workflow-event", event in ("push", "pull_request", "workflow_dispatch"),
          f"event {event!r} must be push, pull_request or workflow_dispatch")
    repository = environ.get("GITHUB_REPOSITORY", "")
    check(results, "repository", repository == "netsec-ethz/debuglet",
          f"repository {repository!r} must be netsec-ethz/debuglet")

    ref = environ.get("GITHUB_REF", "")
    allowed_ref = (
        event == "push" and ref in ("refs/heads/main", "refs/heads/dev", "refs/heads/hardening")
        or event == "workflow_dispatch" and ref.startswith("refs/heads/")
        or event == "pull_request" and re.fullmatch(r"refs/pull/[0-9]+/merge", ref) is not None
        and environ.get("GITHUB_BASE_REF") in ("main", "dev")
    )
    check(results, "event-ref", allowed_ref,
          f"ref {ref!r} must match a configured push, pull request or manual run")

    sha = environ.get("GITHUB_SHA", "")
    check(results, "checkout-revision",
          re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha == checkout_sha,
          f"event revision {sha!r} must match checkout {checkout_sha!r}")
    runner_ok = (
        environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and environ.get("RUNNER_OS") == "Linux"
        and environ.get("RUNNER_ARCH") == "X64"
    )
    check(results, "kernel-runner", runner_ok,
          "the kernel lane requires a fresh GitHub-hosted Linux X64 VM")
    return results


def read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def write_evidence(name: str, payload: dict) -> str:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    destination = os.path.join(EVIDENCE_DIR, name)
    with open(destination, "w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2, sort_keys=True)
        output.write("\n")
    return destination


def command_output(*command: str) -> str | None:
    """Run a read-only inspection command, tolerating absence or refusal."""
    if shutil.which(command[0]) is None:
        return None
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
    except OSError as error:
        return f"unavailable: {error}"
    if result.returncode != 0:
        return f"exit {result.returncode}: {(result.stderr or '').strip()}"
    return result.stdout.strip()


def effective_capabilities() -> list[str]:
    status = read_text("/proc/self/status") or ""
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            mask = int(line.split()[1], 16)
            return [
                name
                for bit, name in enumerate(CAPABILITIES)
                if mask & (1 << bit)
            ]
    return []


def mount_points() -> list[dict]:
    mounts = []
    for line in (read_text("/proc/self/mountinfo") or "").splitlines():
        fields = line.split(" - ")
        if len(fields) != 2:
            continue
        left, right = fields[0].split(), fields[1].split()
        if len(left) < 6 or len(right) < 2:
            continue
        mounts.append(
            {
                "target": left[4],
                "options": left[5],
                "type": right[0],
                "source": right[1],
            }
        )
    return mounts


def process_table() -> tuple[dict, list[str]]:
    """Read every process in this namespace in one pass."""
    processes: dict[str, dict] = {}
    problems: list[str] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        comm = read_text(f"/proc/{entry}/comm")
        status = read_text(f"/proc/{entry}/status")
        if comm is None or status is None:
            continue  # exited while being read
        parent, state = "0", "?"
        for line in status.splitlines():
            if line.startswith("PPid:"):
                parent = line.split()[1]
            elif line.startswith("State:"):
                state = line.split()[1]
        handles = []
        try:
            for descriptor in os.listdir(f"/proc/{entry}/fd"):
                try:
                    target = os.readlink(f"/proc/{entry}/fd/{descriptor}")
                except OSError:
                    continue
                if "bpf" in target:
                    handles.append(target)
        except PermissionError:
            problems.append(f"cannot read file descriptors of pid {entry}")
        except OSError:
            continue
        processes[entry] = {
            "comm": comm.strip(),
            "ppid": parent,
            "state": state,
            "bpf_handles": sorted(handles),
        }
    return processes, problems


def self_chain(processes: dict) -> list[str]:
    chain, current = [], str(os.getpid())
    while current in processes and current not in chain:
        chain.append(current)
        current = processes[current]["ppid"]
    return chain


def bpf_filesystem() -> list[str] | str:
    try:
        return sorted(os.listdir("/sys/fs/bpf"))
    except OSError as error:
        return f"unavailable: {error}"


def check(results: list, name: str, ok: bool, detail: str) -> None:
    results.append({"check": name, "status": "pass" if ok else "fail", "detail": detail})


def do_assert() -> int:
    results: list[dict] = []
    # When enforcement is requested outside CI these checks still run, and fail,
    # because the variables they read only exist in a GitHub Actions job.
    in_ci = enforcing()

    if in_ci:
        results.extend(github_metadata_checks(os.environ, command_output("git", "rev-parse", "HEAD") or ""))
    else:
        results.append(
            {
                "check": "github-metadata",
                "status": "skip",
                "detail": "not running under GitHub Actions",
            }
        )

    exposed = sorted(
        name
        for name in os.environ
        if any(fnmatch.fnmatch(name.upper(), pattern) for pattern in CREDENTIAL_PATTERNS)
    )
    check(
        results,
        "release-credential-separation",
        not exposed,
        f"credential-shaped environment names present: {exposed}" if exposed
        else "no release or deployment credential names in the environment",
    )

    reachable = sorted(
        path for path in CREDENTIAL_PATHS if os.path.exists(os.path.expanduser(path))
    )
    check(
        results,
        "credential-paths",
        not reachable,
        f"credential or daemon paths reachable: {reachable}" if reachable
        else "no credential store, runner configuration or container socket is reachable",
    )

    held = effective_capabilities()
    forbidden = [name for name in FORBIDDEN_CAPABILITIES if name in held]
    check(
        results,
        "capability-bounds",
        not forbidden,
        f"job holds capabilities beyond eBPF loading: {forbidden}" if forbidden
        else f"effective capabilities limited to {held}",
    )
    missing = [name for name in REQUIRED_CAPABILITIES if name not in held]
    if in_ci:
        check(
            results,
            "kernel-capabilities",
            not missing,
            f"kernel lane is missing {missing}; its load tests would not run" if missing
            else "the capabilities the load tests need are present",
        )
    else:
        results.append(
            {
                "check": "kernel-capabilities",
                "status": "skip",
                "detail": f"not running under GitHub Actions; missing {missing}" if missing
                else "not running under GitHub Actions",
            }
        )

    init_name = (read_text("/proc/1/comm") or "").strip()
    check(
        results,
        "process-namespace",
        init_name not in HOST_INIT_NAMES and init_name != "",
        f"pid 1 is {init_name!r}; the job must not share the host process namespace",
    )

    mounts = mount_points()
    intruding = sorted(
        {
            mount["target"]
            for mount in mounts
            if any(
                mount["target"] == path or mount["target"].startswith(path + "/")
                for path in FORBIDDEN_MOUNTS
            )
        }
    )
    check(
        results,
        "mounts",
        not intruding,
        f"host paths mounted into the job: {intruding}" if intruding
        else "no container socket or runner configuration is mounted into the job",
    )

    payload = {
        "mode": "enforcing" if enforcing() else "recording",
        "checks": results,
        "runner": {
            key.lower(): os.environ.get(key)
            for key in (
                "GITHUB_REPOSITORY",
                "GITHUB_EVENT_NAME",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
                "GITHUB_JOB",
                "GITHUB_REF",
                "GITHUB_BASE_REF",
                "GITHUB_REF_PROTECTED",
                "GITHUB_SHA",
                "RUNNER_NAME",
                "RUNNER_ENVIRONMENT",
                "RUNNER_OS",
                "RUNNER_ARCH",
            )
        },
        "effective_capabilities": held,
        "namespaces": {
            name: os.readlink(f"/proc/self/ns/{name}")
            for name in sorted(os.listdir("/proc/self/ns"))
            if os.path.islink(f"/proc/self/ns/{name}")
        },
        "mounts": mounts,
        "kernel": (read_text("/proc/sys/kernel/osrelease") or "").strip(),
    }
    destination = write_evidence("isolation-assert.json", payload)

    failed = [entry for entry in results if entry["status"] == "fail"]
    for entry in results:
        print(f"[{entry['status']}] {entry['check']}: {entry['detail']}")
    print(f"Runner isolation evidence written to {destination}.")
    if failed and enforcing():
        print("Kernel runner isolation requirements are not met.", file=sys.stderr)
        return 1
    if failed:
        print("Recorded only: isolation requirements apply to CI runs.")
    return 0


def do_snapshot(label: str) -> int:
    processes, problems = process_table()
    chain = self_chain(processes)
    owned = {
        pid: entry["bpf_handles"]
        for pid, entry in processes.items()
        if entry["bpf_handles"]
    }
    payload = {
        "label": label,
        "self_chain": chain,
        "processes": processes,
        "process_count": len(processes),
        "bpf_handles": owned,
        "bpf_handle_count": sum(len(handles) for handles in owned.values()),
        "bpf_filesystem": bpf_filesystem(),
        "bpftool_prog_show": command_output("bpftool", "prog", "show"),
        "bpftool_net_show": command_output("bpftool", "net", "show"),
        "unreadable": problems,
    }
    destination = write_evidence(f"isolation-{label}.json", payload)
    print(
        f"{label}: {payload['process_count']} processes, "
        f"{payload['bpf_handle_count']} BPF handles; evidence in {destination}."
    )
    return 0


def do_compare() -> int:
    snapshots = {}
    for label in ("before", "after"):
        content = read_text(os.path.join(EVIDENCE_DIR, f"isolation-{label}.json"))
        if content is None:
            print(
                f"No {label} ownership snapshot; the kernel lane cannot show that "
                "it released what it created.",
                file=sys.stderr,
            )
            return 1 if enforcing() else 0
        snapshots[label] = json.loads(content)

    before, after = snapshots["before"], snapshots["after"]
    excused = set(after["self_chain"])

    leaked_processes = sorted(
        (pid, entry)
        for pid, entry in after["processes"].items()
        if pid not in before["processes"]
        and pid not in excused
        and entry["state"] != "Z"
    )
    held_before = {
        (pid, handle)
        for pid, handles in before["bpf_handles"].items()
        for handle in handles
    }
    leaked_handles = sorted(
        (pid, sorted(handle for handle in handles if (pid, handle) not in held_before))
        for pid, handles in after["bpf_handles"].items()
        if any((pid, handle) not in held_before for handle in handles)
    )

    payload = {
        "process_count": {"before": before["process_count"], "after": after["process_count"]},
        "bpf_handle_count": {
            "before": before["bpf_handle_count"],
            "after": after["bpf_handle_count"],
        },
        "leaked_processes": {pid: entry for pid, entry in leaked_processes},
        "leaked_bpf_handles": {pid: handles for pid, handles in leaked_handles},
        "zombies": {
            pid: entry["comm"]
            for pid, entry in after["processes"].items()
            if entry["state"] == "Z"
        },
    }
    destination = write_evidence("isolation-compare.json", payload)

    for pid, entry in leaked_processes:
        print(f"Leaked process {pid} ({entry['comm']}).", file=sys.stderr)
    for pid, handles in leaked_handles:
        print(f"Leaked BPF handles held by pid {pid}: {handles}", file=sys.stderr)
    print(f"Ownership comparison written to {destination}.")
    if leaked_processes or leaked_handles:
        print("The kernel lane did not release the state it created.", file=sys.stderr)
        return 1
    print("The kernel lane released every process and BPF handle it created.")
    return 0


def main(argv: list[str]) -> int:
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    if command == "assert":
        return do_assert()
    if command == "snapshot":
        if len(argv) != 3 or argv[2] not in ("before", "after"):
            print("usage: kernel-isolation.py snapshot <before|after>", file=sys.stderr)
            return 2
        return do_snapshot(argv[2])
    if command == "compare":
        return do_compare()
    print(f"unknown subcommand {command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
