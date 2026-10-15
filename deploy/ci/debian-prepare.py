#!/usr/bin/env python3
"""Create disposable repository trust material for the Debian acceptance check."""

import json
from pathlib import Path
import subprocess


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    run("python3", "/source/tools/test_apt_repository.py")
    work = Path("/work")
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    command = ["gpg", "--homedir", str(home), "--batch", "--yes"]
    fingerprints = []
    for name, filename in (("Repository acceptance", "key.asc"), ("Wrong repository", "wrong-key.asc")):
        run(*command, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", name, "rsa2048", "sign", "1d")
        listing = run(*command, "--with-colons", "--list-keys", name)
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        (work / filename).write_text(run(*command, "--armor", "--export", fingerprint))
        fingerprints.append(fingerprint)
    repository = work / "repository"
    run("python3", "/source/tools/apt_repository.py", "build", "--packages", "/packages", "--out", str(repository))
    release = repository / "dists/stable/Release"
    run(*command, "--local-user", fingerprints[0], "--clearsign", "--output", str(release.with_name("InRelease")), str(release))
    run(*command, "--local-user", fingerprints[0], "--armor", "--detach-sign", "--output", str(release.with_name("Release.gpg")), str(release))
    run("python3", "/source/tools/apt_repository.py", "verify", "--directory", str(repository), "--key", str(work / "key.asc"), "--fingerprint", fingerprints[0])
    print(json.dumps({"check": "disposable_repository_prepared", "passed": True, "fingerprint": fingerprints[0]}), flush=True)


if __name__ == "__main__":
    main()
