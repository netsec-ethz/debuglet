"""Focused package assembly and read-only removal regressions (Linux only)."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package = load("debian_package", "package.py")
guard = load("payload_guard", "payload_guard.py")


class Versions(unittest.TestCase):
    def test_prerelease_and_dev_sort_before_final(self):
        for upstream, expected in (("v1.2.3", "1.2.3-1"), ("v1.2.3-rc.1", "1.2.3~rc.1-1"),
                                   ("v0.0.0-dev.abcdef012345", "0.0.0~dev.abcdef012345-1")):
            self.assertEqual(package.debian_version(upstream), expected)
        subprocess.run(["dpkg", "--compare-versions", package.debian_version("v1.2.3-rc.1"),
                        "lt", package.debian_version("v1.2.3")], check=True)
        for invalid in ("1.2.3", "v01.2.3", "v1.2.3+dirty", "v1.2.3-../x", "v1.2.3-"):
            with self.assertRaises(ValueError):
                package.debian_version(invalid)


class Removal(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.records, self.proc, self.bin = [self.root / name for name in ("records", "proc", "bin")]
        for path in (self.records, self.proc, self.bin):
            path.mkdir()
        self.candidate = "/usr/lib/debuglet/debian/" + "a" * 64

    def check(self):
        guard.check_removal(self.candidate, self.records, self.proc, (self.bin,))

    def test_inactive_unreferenced_payload_can_be_removed(self):
        self.check()

    def test_retained_record_pins_stopped_payload(self):
        (self.records / "executor-worker.json").write_text(json.dumps({"payload_root": self.candidate}))
        with self.assertRaisesRegex(ValueError, "retained service"):
            self.check()
        self.assertTrue((self.records / "executor-worker.json").exists())

    def test_corrupt_and_unreadable_records_fail_closed(self):
        record = self.records / "executor-worker.json"
        for content in ("{", "[]", "{}", '{"payload_root":"/a","payload_root":"/b"}', " " * 4097):
            record.write_text(content)
            with self.assertRaises(ValueError):
                self.check()
        record.unlink()
        record.symlink_to(self.root / "missing")
        with self.assertRaises(ValueError):
            self.check()

    def test_unknown_proc_error_fails_closed(self):
        (self.proc / "12").mkdir()
        (self.proc / "12/exe").write_text("not a proc link")
        with self.assertRaises(OSError):
            self.check()

    def test_executing_payload_and_command_alias_pin_it(self):
        (self.proc / "123").mkdir()
        (self.proc / "123/exe").symlink_to(self.candidate + "/bin/debuglet-executor")
        with self.assertRaisesRegex(ValueError, "process 123"):
            self.check()
        (self.proc / "123/exe").unlink()
        (self.bin / "old-dbl").symlink_to(self.candidate + "/bin/dbl")
        with self.assertRaisesRegex(ValueError, "command"):
            self.check()

    def test_unrelated_process_and_record_do_not_pin(self):
        (self.records / "executor-other.json").write_text(json.dumps({"payload_root": "/usr/local/lib/debuglet/v1.0.0"}))
        (self.proc / "456").mkdir()
        (self.proc / "456/exe").symlink_to("/usr/bin/python3")
        self.check()

    def test_same_version_reinstall_does_not_remove_retained_payload(self):
        with mock.patch.object(guard, "DEBIAN_VERSION", "1.2.3-1"):
            with mock.patch.object(guard.sys, "argv", ["prerm", "upgrade", "1.2.3-1"]):
                guard.main()
            with mock.patch.object(guard.sys, "argv", ["prerm", "upgrade", "1.2.4-1"]):
                with self.assertRaisesRegex(ValueError, "separately named"):
                    guard.main()


class Assembly(unittest.TestCase):
    def test_full_payload_manifest_and_modes_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = "v1.2.3-rc.1"
            modes = {"LICENSE": 0o644, "README-install.md": 0o644,
                     "bin/dbl": 0o755, "bin/debuglet-executor": 0o755, "bin/debuglet-dispatcher": 0o755,
                     "share/debuglet/demo.wasm": 0o644, "share/debuglet/hello.wasm": 0o644}
            contents = {name: ("fixture " + name).encode() for name in modes}
            manifest = {"schema_version": 1, "version": upstream, "source_sha": "a" * 40,
                        "dirty": False, "go_version": "go1.26.10", "goos": "linux", "goarch": "amd64",
                        "guest_abi": "debuglet-go-wasi-imports-v1", "build_pipeline_url": "",
                        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                                  for name, data in contents.items()}}
            contents["share/debuglet/manifest.json"] = json.dumps(manifest).encode()
            modes["share/debuglet/manifest.json"] = 0o644
            archive = root / f"debuglet-{upstream}-linux-amd64.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, data in sorted(contents.items()):
                    member = tarfile.TarInfo(name)
                    member.mode, member.size = modes[name], len(data)
                    bundle.addfile(member, io.BytesIO(data))
            installer = (package.REPO / "scripts/install.sh").read_text()
            sums = "\n".join(f"{hashlib.sha256(data).hexdigest()}  {name}" for name, data in sorted(contents.items()))
            installer = installer.replace("@VERSION@", upstream).replace("@SOURCE_SHA@", "a" * 40).replace("@COMPONENT@", "").replace("@PAYLOAD_SUMS@", sums)
            (root / "install.sh").write_text(installer)
            checksums = root / "SHA256SUMS"
            checksums.write_text("".join(f"{package.digest(path)}  {path.name}\n" for path in (archive, root / "install.sh")))
            output = root / "debs"
            old_umask = os.umask(0o077)
            try:
                result = package.assemble(archive, checksums, output)
            finally:
                os.umask(old_umask)
            payload = output / f"debuglet-payload-{upstream}-linux-amd64.deb"
            with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(
                    ["dpkg-deb", "--fsys-tarfile", str(payload)]))) as package_tar:
                for member in package_tar:
                    self.assertEqual((member.uid, member.gid), (0, 0))
                    if member.isdir():
                        self.assertEqual(member.mode, 0o755, member.name)
            extracted = root / "extracted"
            subprocess.run(["dpkg-deb", "--extract", str(payload), str(extracted)], check=True)
            installed = extracted / result["payload_root"].lstrip("/")
            for name, data in contents.items():
                self.assertEqual((installed / name).read_bytes(), data)
                self.assertEqual((installed / name).stat().st_mode & 0o777, modes[name])
            # Existing prune requires prefix/lib/debuglet/<valid version>.
            # A Debian hash root has no such valid version path component.
            self.assertIsNone(package.VERSION.fullmatch(installed.name))
            selector = output / f"debuglet-{upstream}-linux-amd64.deb"
            with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(
                    ["dpkg-deb", "--fsys-tarfile", str(selector)]))) as package_tar:
                for member in package_tar:
                    self.assertEqual((member.uid, member.gid), (0, 0))
                    if member.isdir():
                        self.assertEqual(member.mode, 0o755, member.name)
            subprocess.run(["dpkg-deb", "--extract", str(selector), str(root / "selector")], check=True)
            self.assertEqual(os.readlink(root / "selector/usr/bin/dbl"),
                             "../lib/debuglet/debian/" + installed.name + "/bin/dbl")
            self.assertIn(result["payload_package"], subprocess.check_output(["dpkg-deb", "--field", str(selector), "Depends"], text=True))
            subprocess.run(["sha256sum", "--check", "SHA256SUMS-debian"], cwd=output, check=True)
            archive.write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                package.assemble(archive, checksums, root / "corrupt-output")


if __name__ == "__main__":
    unittest.main()
