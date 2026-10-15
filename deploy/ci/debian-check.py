#!/usr/bin/env python3
"""Exercise apt's authentication and the installed Debian package lifecycle.

The caller supplies a repository signed by a disposable test key, its exported
public key, a different exported key, and the package inventory. No network or
source toolchain is needed in the fresh Ubuntu 24.04 container.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import tempfile
import time


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=120)
    if check and result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result


def event(check, **details):
    print(json.dumps({"check": check, "passed": True, **details}), flush=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def interrupt_unpack(package, package_name, log):
    """Kill the owned dpkg process group after its half-installed status event."""
    reader, writer = os.pipe()
    process = None
    buffer = b""
    observed = False
    try:
        with log.open("wb") as output:
            process = subprocess.Popen(["dpkg", "--status-fd", str(writer), "--unpack", str(package)],
                                       stdout=output, stderr=output, pass_fds=(writer,), start_new_session=True)
            os.close(writer)
            writer = None
            deadline = time.monotonic() + 45
            while process.poll() is None and time.monotonic() < deadline:
                if not select.select([reader], [], [], 1)[0]:
                    continue
                chunk = os.read(reader, 4096)
                if not chunk:
                    break
                buffer += chunk
                if f"status: {package_name}: half-installed".encode() in buffer:
                    os.killpg(process.pid, signal.SIGKILL)
                    observed = True
                    break
            process.wait(timeout=15)
        assert observed and process.returncode != 0, f"did not interrupt unpack: {buffer!r}\n{log.read_text()}"
    finally:
        os.close(reader)
        if writer is not None:
            os.close(writer)
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--wrong-key", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DEBUGLET_DEBIAN_FIXTURE") == "1"
    assert Path("/.dockerenv").exists(), "refusing to modify a non-container system"
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    assert release["ID"].strip('"') == "ubuntu" and release["VERSION_ID"].strip('"') == "24.04"
    assert run("dpkg", "--print-architecture").stdout.strip() == "amd64"
    assert run("dpkg-query", "-W", "-f=${db:Status-Status}", "debuglet", check=False).stdout.strip() != "installed"
    assert not Path("/etc/debuglet").exists() and not Path("/var/lib/debuglet").exists()
    inventory = json.loads(args.inventory.read_text())
    payload_package = inventory["payload_package"]
    payload_root = Path(inventory["payload_root"])
    assert payload_package.startswith("debuglet-payload-")
    assert str(payload_root).startswith("/usr/lib/debuglet/debian/")

    with tempfile.TemporaryDirectory(prefix="debuglet-debian-") as directory:
        work = Path(directory)
        work.chmod(0o755)
        repository = work / "repository"
        shutil.copytree(args.repository, repository)
        for path in [repository, *repository.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        key = work / "archive-key.asc"
        source = work / "debuglet.sources"
        source.write_text(f"Types: deb\nURIs: file:{repository}\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: {key}\n")
        source.chmod(0o644)
        lists = work / "lists"
        archives = work / "archives"
        for path in (lists / "partial", archives / "partial"):
            path.mkdir(parents=True)
        options = ["-o", f"Dir::Etc::sourcelist={source}", "-o", "Dir::Etc::sourceparts=-",
                   "-o", f"Dir::State::lists={lists}", "-o", f"Dir::Cache::archives={archives}",
                   "-o", "APT::Get::List-Cleanup=0", "-o", "Acquire::Languages=none",
                   "-o", "Acquire::Retries=0", "-o", "APT::Update::Error-Mode=any"]

        def apt(*arguments, check=True):
            return run("apt-get", *options, *arguments, check=check)

        def clear_lists():
            shutil.rmtree(lists)
            (lists / "partial").mkdir(parents=True)

        def reject(label, *arguments, diagnostic):
            result = apt(*arguments, check=False)
            text = result.stdout + result.stderr
            assert result.returncode != 0 and any(item in text for item in diagnostic), text
            assert run("dpkg-query", "-W", "-f=${db:Status-Status}", "debuglet", check=False).stdout.strip() != "installed"
            event(label, exit_code=result.returncode)

        shutil.copyfile(args.wrong_key, key)
        key.chmod(0o644)
        reject("wrong_scoped_key_rejected", "update", diagnostic=("NO_PUBKEY", "signature verification failed"))
        shutil.copyfile(args.key, key)
        clear_lists()
        inrelease = repository / "dists/stable/InRelease"
        authentic_release = inrelease.read_bytes()
        inrelease.write_bytes(authentic_release.replace(b"Suite: stable", b"Suite: broken", 1))
        assert inrelease.read_bytes() != authentic_release, "test repository must declare Suite: stable"
        reject("modified_signed_metadata_rejected", "update", diagnostic=("BADSIG", "invalid signature", "signatures were invalid"))
        inrelease.write_bytes(authentic_release)
        clear_lists()
        indexes = {path: path.read_bytes() for path in (repository / "dists/stable/main/binary-amd64").rglob("*") if path.is_file()}
        for path, contents in indexes.items():
            path.write_bytes(contents + b"modified index\n")
        reject("modified_package_index_rejected", "update", diagnostic=("Hash Sum mismatch", "File has unexpected size"))
        for path, contents in indexes.items():
            path.write_bytes(contents)
        clear_lists()
        apt("update")
        event("signed_index_authenticated")
        packages = sorted((repository / "pool").rglob("*.deb"))
        assert packages, "repository has no Debian packages"
        selected = next(path for path in packages if run("dpkg-deb", "-f", str(path), "Package").stdout.strip() == payload_package)
        authentic_package = selected.read_bytes()
        selected.write_bytes(authentic_package + b"tampered\n")
        reject("modified_package_rejected", "--download-only", "-y", "install", "debuglet", diagnostic=("Hash Sum mismatch", "File has unexpected size"))
        selected.write_bytes(authentic_package)
        apt("-y", "install", "debuglet")
        assert Path("/usr/bin/dbl").resolve() == payload_root / "bin/dbl"
        identity = json.loads(run("/usr/bin/dbl", "--output", "json", "version").stdout)
        assert identity["version"] == inventory["upstream_version"] and identity["revision"] == inventory["source_sha"]
        assert not identity["modified"]
        assert not list(Path("/etc/systemd/system").glob("debuglet-*.service")), "apt install activated a service"
        event("fresh_apt_install", version=identity["version"], revision=identity["revision"], payload_root=str(payload_root))

        state = Path("/var/lib/debuglet/debian-check")
        config = Path("/etc/debuglet/debian-check.conf")
        state.mkdir(parents=True, mode=0o700)
        config.parent.mkdir(exist_ok=True)
        config.write_text("preserve this operator configuration\n")
        secret = state / "identity.key"
        secret.write_text("owned fixture identity\n")
        secret.chmod(0o600)
        kept = {str(path): (digest(path), path.stat().st_uid, path.stat().st_gid, path.stat().st_mode) for path in (config, secret)}
        # Reinstall the actual immutable payload, including repairing a damaged
        # non-running member, without creating a new version or identity.
        member = next(path for path in payload_root.rglob("*.wasm") if path.is_file())
        original_member = member.read_bytes()
        member.write_bytes(b"damaged fixture member\n")
        apt("-y", "--reinstall", "install", payload_package)
        assert member.read_bytes() == original_member
        event("same_payload_reinstall_repaired_member")
        interrupt_unpack(selected, payload_package, work / "interrupted-unpack.log")
        interrupted_status = run("dpkg-query", "-W", "-f=${db:Status-Status}", payload_package).stdout.strip()
        # apt correctly refuses an interrupted dpkg journal until dpkg has
        # processed it. A half-installed payload can then need reinstallation.
        configured = run("dpkg", "--configure", "-a", check=False)
        apt("-y", "--fix-broken", "--reinstall", "install", payload_package, "debuglet")
        assert member.read_bytes() == original_member
        assert run("dpkg-query", "-W", "-f=${db:Status-Status}", payload_package).stdout.strip() == "installed"
        event("interrupted_payload_unpack_recovered", observed_status=interrupted_status,
              configure_exit_code=configured.returncode)
        # Model the documented dpkg interruption boundary: unpacked but not yet
        # configured. Repeating apt install must finish configuration safely.
        selector = next(path for path in packages if run("dpkg-deb", "-f", str(path), "Package").stdout.strip() == "debuglet")
        run("dpkg", "--unpack", str(selector))
        assert run("dpkg-query", "-W", "-f=${db:Status-Status}", "debuglet").stdout.strip() == "unpacked"
        apt("-y", "install", "debuglet")
        assert run("dpkg-query", "-W", "-f=${db:Status-Status}", "debuglet").stdout.strip() == "installed"
        run("/usr/bin/dbl", "--help")
        event("unpacked_configuration_retry")
        apt("-y", "purge", "debuglet", payload_package)
        assert not payload_root.exists() and not Path("/usr/bin/dbl").exists()
        assert kept == {str(path): (digest(path), path.stat().st_uid, path.stat().st_gid, path.stat().st_mode) for path in (config, secret)}
        event("package_purge_preserved_operator_data")
        secret.unlink()
        state.rmdir()
        config.unlink()


if __name__ == "__main__":
    main()
