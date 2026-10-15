#!/usr/bin/env python3
"""Wrap the existing verified full tar payload in co-installable Debian packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?\Z")


def debian_version(version):
    if len(version) > 128 or not VERSION.fullmatch(version):
        raise ValueError("invalid upstream version")
    return version[1:].replace("-", "~", 1) + "-1"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def template(name, root, package, version):
    return ((HERE / name).read_text().replace("@PAYLOAD_ROOT@", root)
            .replace("@PAYLOAD_PACKAGE@", package).replace("@DEBIAN_VERSION@", version))


def control(name, version, description, depends):
    return (f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: Debuglet maintainers\n"
            "Section: net\nPriority: optional\n"
            "Homepage: https://github.com/netsec-ethz/debuglet\n"
            f"Depends: {depends}\nDescription: {description}\n")


def assemble(archive, checksums, output):
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("Debian assembly requires Linux amd64")
    installer = archive.parent / "install.sh"
    for path in (archive, checksums, installer):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"input must be a regular file: {path}")
    sums = {}
    for line in checksums.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid or duplicate checksum entry")
        sums[match[2]] = match[1]
    if set(sums) != {archive.name, "install.sh"}:
        raise ValueError("checksums must name exactly the full archive and install.sh")
    for path in (archive, installer):
        if digest(path) != sums[path.name]:
            raise ValueError(f"checksum mismatch: {path.name}")
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("share/debuglet/manifest.json")
        if not member.isfile() or member.size > 65536:
            raise ValueError("invalid full payload manifest")
        manifest_bytes = bundle.extractfile(member).read()
        manifest = json.loads(manifest_bytes)
    upstream = manifest["version"]
    version = debian_version(upstream)
    if (manifest.get("component") or manifest.get("schema_version") != 1
            or manifest.get("dirty") is not False or manifest.get("goos") != "linux"
            or manifest.get("goarch") != "amd64"
            or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_sha", ""))
            or archive.name != f"debuglet-{upstream}-linux-amd64.tar.gz"):
        raise ValueError("Debian assembly requires a clean full Linux amd64 payload")
    identity = hashlib.sha256(manifest_bytes).hexdigest()
    payload_package = "debuglet-payload-" + identity[:24]
    payload_root = "/usr/lib/debuglet/debian/" + identity
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Debian output directory must be empty")
    with tempfile.TemporaryDirectory(prefix="debuglet-deb-") as temporary:
        work = Path(temporary)
        # Use the existing installer to verify exact members, modes and all
        # hashes. No Debian-specific payload variant or executable is built.
        subprocess.run(["sh", str(installer), "--archive", str(archive), "--checksums", str(checksums),
                        "--version", upstream, "--prefix", str(work / "verified"), "--stage-only"], check=True)
        verified = work / "verified/lib/debuglet" / upstream
        if (verified / "share/debuglet/manifest.json").read_bytes() != manifest_bytes:
            raise ValueError("manifest changed during staging")
        payload, selector = work / "payload", work / "selector"
        shutil.copytree(verified, payload / payload_root.lstrip("/"))
        write(payload / "DEBIAN/control", control(payload_package, version,
              "immutable full Debuglet payload", "python3"))
        write(payload / "DEBIAN/preinst", template("payload-preinst", payload_root, payload_package, version), 0o755)
        write(payload / "DEBIAN/prerm", template("payload_guard.py", payload_root, payload_package, version), 0o755)
        write(selector / "DEBIAN/control", control("debuglet", version,
              "Debuglet command selector and local setup", f"{payload_package} (= {version}), adduser"))
        write(selector / "DEBIAN/postinst", (HERE / "selector-postinst").read_text(), 0o755)
        for command in ("dbl", "debuglet-dispatcher", "debuglet-executor"):
            link = selector / "usr/bin" / command
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("../lib/debuglet/debian/" + identity + "/bin/" + command)
        for tree, name in ((payload, payload_package), (selector, "debuglet")):
            documentation = tree / "usr/share/doc" / name
            write(documentation / "copyright", (REPO / "LICENSE").read_text())
            write(documentation / "debian.md", (REPO / "docs/operations/debian.md").read_text())
            # Stable timestamps/root ownership keep builds independent of the
            # invoking user. gzip is supported by Ubuntu's dpkg without extras.
            for path in tree.rglob("*"):
                os.utime(path, (0, 0), follow_symlinks=False)
            filename = "debuglet" if name == "debuglet" else "debuglet-payload"
            package_file = output / f"{filename}-{upstream}-linux-amd64.deb"
            subprocess.run(["dpkg-deb", "--root-owner-group", "-Zgzip", "-z6", "--build", str(tree), str(package_file)],
                           env={**os.environ, "SOURCE_DATE_EPOCH": "0"}, check=True)
    packages = [{"name": path.name, "sha256": digest(path), "bytes": path.stat().st_size}
                for path in sorted(output.glob("*.deb"))]
    result = {"schema_version": 1, "upstream_version": upstream, "debian_version": version,
              "architecture": "amd64", "source_sha": manifest["source_sha"],
              "payload_package": payload_package, "payload_root": payload_root, "files": packages,
              "manifest_sha256": identity,
              "archive": {"name": archive.name, "sha256": sums[archive.name], "bytes": archive.stat().st_size}}
    write(output / "deb-packages.json", json.dumps(result, indent=2) + "\n")
    write(output / "SHA256SUMS-debian", "".join(
        f"{digest(path)}  {path.name}\n" for path in [*sorted(output.glob("*.deb")), output / "deb-packages.json"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, default=Path(os.environ.get("CI_PACKAGE_DIR", ".cache/ci/packages")))
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if bool(args.archive) != bool(args.checksums):
        parser.error("--archive and --checksums must be supplied together")
    if args.archive:
        archive, checksums = args.archive, args.checksums
    else:
        archives = list(args.package_dir.glob("debuglet-v*-linux-amd64.tar.gz"))
        if len(archives) != 1:
            parser.error("--package-dir must contain exactly one full archive")
        archive, checksums = archives[0], args.package_dir / "SHA256SUMS"
    result = assemble(archive.absolute(), checksums.absolute(), (args.out or args.package_dir / "debian").absolute())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        sys.exit(f"package-deb: {error}")
