#!/usr/bin/python3
"""Read-only dpkg removal guard; no runtime import or service-manager dependency.

Installed as the payload's prerm, outside its unchanged distribution manifest.
The constants below are filled by package.py. Keep the retained-record policy
consistent with internal/demo/service/prune.go.
"""

import json
import os
from pathlib import Path
import stat
import sys

PAYLOAD_ROOT = "@PAYLOAD_ROOT@"
PAYLOAD_PACKAGE = "@PAYLOAD_PACKAGE@"
DEBIAN_VERSION = "@DEBIAN_VERSION@"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def inside(path, candidate):
    return path == candidate or path.startswith(candidate + "/")


def check_removal(candidate, records=Path("/etc/debuglet/services"),
                  proc=Path("/proc"), bins=(Path("/usr/bin"), Path("/usr/local/bin"))):
    """Refuse unknown state as well as known references, without changing it."""
    for path in (records, *records.parents):
        if path.is_symlink():
            raise ValueError(f"cannot inspect service records through symlink {path}")
    if records.exists() or records.is_symlink():
        if records.is_symlink() or not records.is_dir():
            raise ValueError(f"cannot inspect retained service records at {records}")
        for path in sorted(records.glob("*.json")):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                raise ValueError(f"cannot inspect retained service record {path}")
            record = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
            root = record.get("payload_root") if isinstance(record, dict) else None
            if not isinstance(root, str) or not root.startswith("/"):
                raise ValueError(f"invalid retained service record {path}")
            if os.path.normpath(root) == candidate or os.path.realpath(root) == candidate:
                raise ValueError(
                    f"retained service {path.name} references this payload. "
                    "Drain and back up the role, then explicitly replace its package "
                    "while stopped and disabled. Uninstall without --purge retains "
                    "this recovery reference; --purge also deletes that role's data")
    for directory in bins:
        if not directory.exists():
            continue
        for path in directory.iterdir():
            if path.is_symlink() and inside(os.path.realpath(path), candidate):
                raise ValueError(f"command {path} still selects this payload; upgrade or remove the debuglet selector first")
    for process in proc.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            executable = os.readlink(process / "exe")
        except FileNotFoundError:
            continue  # exited process or kernel thread
        if inside(executable, candidate):
            raise ValueError(f"process {process.name} is executing this payload; stop it before removal")


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action == "upgrade":
        if len(sys.argv) < 3 or sys.argv[2] != DEBIAN_VERSION:
            raise ValueError("different payload versions must use separately named packages; upgrade the debuglet selector instead")
        return  # same-version repair restores the same signed payload bytes
    if action not in ("remove", "deconfigure"):
        return
    check_removal(PAYLOAD_ROOT)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"{PAYLOAD_PACKAGE}: removal refused: {error}. "
              f"This payload and all state have been retained. See /usr/share/doc/{PAYLOAD_PACKAGE}/debian.md", file=sys.stderr)
        sys.exit(1)
