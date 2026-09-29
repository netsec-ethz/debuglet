#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Run one verified offline backup and publish its result for node_exporter.

The installed backup command owns SQLite/inventory verification. This wrapper
never starts services, schedules jobs, reads backup credentials or rotates data.
Only a completed command and its published manifest advance backup freshness.
"""
import argparse
from datetime import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def last_success(path):
    try:
        with path.open() as source:
            content = source.read(4097)
    except FileNotFoundError:
        return None
    if len(content) > 4096:
        raise ValueError("existing metrics file exceeds limit")
    found = re.findall(r"^debuglet_backup_last_verified_timestamp_seconds ([0-9.]+)$", content, re.M)
    if not found:
        return None
    if len(found) != 1 or not math.isfinite(float(found[0])):
        raise ValueError("invalid previous verified timestamp")
    return float(found[0])


def verified_manifest(output, destination, began):
    if len(output) > 65536:
        raise ValueError("backup result exceeds limit")
    result = json.loads(output)
    if not isinstance(result, dict) or type(result.get("schema_version")) is not int or result["schema_version"] != 1 or result.get("layout") not in ("local", "dispatcher", "executor"):
        raise ValueError("unsupported backup result")
    if not isinstance(result.get("roles"), list) or not result["roles"] or not isinstance(result.get("files"), dict) or not result["files"]:
        raise ValueError("missing backup inventory")
    for role in result["roles"]:
        if not isinstance(role, dict) or role.get("role") not in ("dispatcher", "executor") or not isinstance(role.get("identity"), str) or not role["identity"] or type(role.get("schema_version")) is not int:
            raise ValueError("invalid role identity")
    for record in result["files"].values():
        if not isinstance(record, dict) or not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")) or type(record.get("bytes")) is not int or record["bytes"] < 0:
            raise ValueError("invalid file inventory")
    package = result.get("package", {})
    if not isinstance(package, dict) or not re.fullmatch(r"[0-9a-f]{40}", package.get("source_sha", "")) or not package.get("version"):
        raise ValueError("missing package identity")
    if not isinstance(result.get("observed_at"), str):
        raise ValueError("missing backup observation time")
    observed = datetime.fromisoformat(result["observed_at"].replace("Z", "+00:00"))
    if observed.tzinfo is None or not began - 5 <= observed.timestamp() <= time.time() + 5:
        raise ValueError("invalid backup observation time")
    with (destination / "backup.json").open() as manifest:
        published = manifest.read(65537)
    if len(published) > 65536 or json.loads(published) != result:
        raise ValueError("published backup manifest differs from successful result")


def publish(path, success, completed, verified):
    values = {"last_completed_success": int(success), "last_completed_timestamp_seconds": completed}
    if verified is not None:
        values["last_verified_timestamp_seconds"] = verified
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".backup-", delete=False) as output:
        temporary = Path(output.name)
        try:
            os.fchmod(output.fileno(), 0o644)  # Contains no credential or path.
            for name, value in values.items():
                output.write(f"# TYPE debuglet_backup_{name} gauge\ndebuglet_backup_{name} {value}\n")
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dbl", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--metrics-file", type=Path, required=True)
    parser.add_argument("--offline", action="store_true", required=True)
    args = parser.parse_args()
    path = args.metrics_file.absolute()
    info = path.parent.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022 or path.is_symlink():
        parser.error("metrics directory must be owned and not writable by other users; file must not be a symlink")
    with (path.parent / (path.name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verified = last_success(path)
        success = False
        began = time.time()
        try:
            result = subprocess.run([str(args.dbl.resolve(strict=True)), "--output", "json", "--timeout", "5m",
                                     "backup", "--state-dir", str(args.state_dir), "--destination", str(args.destination),
                                     "--offline"], capture_output=True, timeout=310, check=True)
            verified_manifest(result.stdout, args.destination, began)
            verified = time.time()
            success = True
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # The command's diagnostic can contain private state paths. The
            # collector receives only its completed success/failure outcome.
            print("backup failed or returned an unverifiable result", file=sys.stderr)
        publish(path, success, time.time(), verified)
        return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
