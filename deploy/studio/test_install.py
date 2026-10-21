#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Installer trust, archive boundaries, rerun and tamper checks."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package, installer = load('package'), load('install')
SOURCE = 'a' * 40


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        stage = self.root / 'stage'
        for directory in package.RUNTIME_DIRECTORIES | {'bin', 'go/bin', 'sdk'}:
            (stage / directory).mkdir(parents=True, exist_ok=True)
        for name in ('bin/dbl-studio', 'go/bin/go', 'sdk/go.mod'):
            (stage / name).write_bytes(b'fixture ' + name.encode())
        self.manifest = package.manifest(stage, SOURCE, {})
        self.archive = self.root / f'debuglet-studio-{SOURCE}-linux-amd64.tar.gz'
        package.archive(stage, self.archive)
        self.snapshot = self.archive.read_bytes()
        self.release = dict(schema_version=1, source_sha=SOURCE, go_version='go1.26.10',
                            archive=self.archive.name, archive_sha256=package.digest(self.archive)['sha256'],
                            archive_bytes=self.archive.stat().st_size)
        (self.root / 'studio-release.json').write_text(json.dumps(self.release))

    def verify(self, expected=None):
        return installer.verify_release(self.root, SOURCE, expected_digest=expected or self.release['archive_sha256'])

    def test_exact_digest_installs_and_reruns_but_detects_modified_payload(self):
        self.verify()
        manifest = installer.inspect_archive(self.snapshot, SOURCE)
        prefix = self.root / 'installed'
        self.assertTrue(installer.install(self.snapshot, manifest, prefix))
        self.assertFalse(installer.install(self.snapshot, manifest, prefix))
        (prefix / SOURCE / 'sdk/go.mod').write_text('tampered')
        with self.assertRaisesRegex(ValueError, 'installed Studio file differs'):
            installer.install(self.snapshot, manifest, prefix)

    def test_swapping_staging_archive_after_verification_cannot_change_install(self):
        _, snapshot = self.verify()
        self.archive.write_bytes(b'swapped after verification')
        manifest = installer.inspect_archive(snapshot, SOURCE)
        self.archive.unlink()
        self.archive.symlink_to('/etc/passwd')
        prefix = self.root / 'installed'
        self.assertTrue(installer.install(snapshot, manifest, prefix))
        self.assertEqual((prefix / SOURCE / 'sdk/go.mod').read_bytes(), b'fixture sdk/go.mod')

    def test_untrusted_record_and_changed_archive_cannot_install(self):
        with self.assertRaisesRegex(ValueError, 'provide trusted signer'):
            installer.verify_release(self.root, SOURCE)
        with self.assertRaisesRegex(ValueError, 'independently verified archive checksum'):
            self.verify('b' * 64)
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'archive checksum differs'):
            self.verify()

    def test_signed_subject_and_tamper(self):
        if not shutil.which('ssh-keygen'):
            self.skipTest('OpenSSH is required for signature fixture')
        key = self.root / 'signing-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        trust = self.root / 'allowed-signers'
        trust.write_text('fixture ' + key.with_suffix('.pub').read_text())
        subject = self.root / 'studio-release.json'
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', installer.NAMESPACE,
                        str(subject)], check=True, capture_output=True)
        installer.verify_release(self.root, SOURCE, trust, 'fixture')
        subject.write_text(subject.read_text() + '\n')
        with self.assertRaises(subprocess.CalledProcessError):
            installer.verify_release(self.root, SOURCE, trust, 'fixture')

    def test_archive_cannot_escape_or_link(self):
        for name, kind in (('../outside', tarfile.REGTYPE), ('link', tarfile.SYMTYPE),
                           ('device', tarfile.CHRTYPE), ('./path', tarfile.REGTYPE)):
            with self.subTest(name=name):
                archive = self.root / 'bad.tar.gz'
                with tarfile.open(archive, 'w:gz') as output:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.mode = 0o644
                    member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                    output.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    installer.inspect_archive(archive.read_bytes(), SOURCE)

    def test_install_refuses_linked_parent_and_extra_installed_files(self):
        linked = self.root / 'linked'
        linked.symlink_to(self.root / 'stage', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked installation parent'):
            installer.install(self.snapshot, self.manifest, linked / 'prefix')
        prefix = self.root / 'installed'
        installer.install(self.snapshot, self.manifest, prefix)
        (prefix / SOURCE / 'extra').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'unexpected installed file'):
            installer.install(self.snapshot, self.manifest, prefix)

    def test_install_refuses_writable_or_foreign_owned_installation(self):
        prefix = self.root / 'installed'
        prefix.mkdir(mode=0o777)
        prefix.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'writable by another identity'):
            installer.install(self.snapshot, self.manifest, prefix)
        prefix.chmod(0o755)
        installer.install(self.snapshot, self.manifest, prefix)
        if os.geteuid() == 0:
            os.chown(prefix / SOURCE / 'sdk/go.mod', 65534, 65534)
            with self.assertRaisesRegex(ValueError, 'ownership differs'):
                installer.install(self.snapshot, self.manifest, prefix)
            os.chown(prefix / SOURCE / 'sdk/go.mod', 0, 0)
            os.chown(prefix, 65534, 65534)
            with self.assertRaisesRegex(ValueError, 'untrusted owner'):
                installer.install(self.snapshot, self.manifest, prefix)


if __name__ == '__main__':
    unittest.main()
