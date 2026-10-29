#!/usr/bin/env python3
"""Focused repository tests. Run on Linux with apt-utils, dpkg and gnupg."""
import http.server
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

import apt_repository as apt


class InputTests(unittest.TestCase):
    def test_published_release_requires_exact_tag(self):
        record = {'tag_name': 'v1.2.3', 'draft': False, 'prerelease': False,
                  'published_at': '2026-10-15T12:00:00Z'}
        apt.check_published_release(record, 'v1.2.3')
        for field, invalid in [('tag_name', 'v1.2.2'), ('draft', True), ('published_at', None)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                apt.check_published_release(dict(record, **{field: invalid}), 'v1.2.3')
        with self.assertRaises(ValueError):
            apt.check_published_release(record, '../main')

    def test_stable_channel_refuses_prereleases(self):
        record = {'tag_name': 'v1.0.0', 'draft': False, 'prerelease': False,
                  'published_at': '2026-10-15T12:00:00Z'}
        for version in ('v1.0.0', 'v1.0.0-rc.1'):
            for prerelease in (True, False, None):
                if version == 'v1.0.0' and prerelease is False:
                    continue
                with self.subTest(version=version, prerelease=prerelease), self.assertRaisesRegex(
                        ValueError, 'stable apt channel requires a final release'):
                    apt.check_published_release(dict(record, tag_name=version, prerelease=prerelease), version)

    def test_duplicate_metadata_and_path_escape_refused(self):
        with self.assertRaises(ValueError):
            apt.fields(b'Package: debuglet\nPackage: other\n')
        valid = ('Package: debuglet\nVersion: 1.2.3-1\nArchitecture: amd64\n'
                 'Filename: ../../outside.deb\nSize: 1\nSHA256: ' + 'a' * 64 + '\n').encode()
        with self.assertRaises(ValueError):
            apt.package_entries(valid)

    def test_workflow_signer_has_no_checkout_or_payload_execution(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/apt-publish.yml').read_text()
        sign = workflow.split('\n  sign:\n')[1].split('\n  deploy:\n')[0]
        self.assertNotIn('actions/checkout', sign)
        self.assertNotIn('tools/apt_repository.py', sign)
        self.assertIn('environment: release-signing', sign)
        self.assertIn('github.ref_protected', sign)
        self.assertIn('cmp "$GNUPGHOME/verified-release"', sign)
        self.assertNotIn('APT_SIGNING_KEY', workflow.split('\n  sign:\n')[0])


@unittest.skipUnless(all(shutil.which(name) for name in ('apt-ftparchive', 'dpkg-deb', 'gpg', 'gpgv')),
                     'requires Linux apt-utils, dpkg and gnupg')
class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='debuglet-apt-tests-')
        cls.root = Path(cls.temporary.name)
        cls.home = cls.root / 'gnupg'
        cls.home.mkdir(mode=0o700)
        cls.gpg = ['gpg', '--batch', '--no-options', '--homedir', str(cls.home)]
        cls.run_command(cls.gpg + ['--pinentry-mode', 'loopback', '--passphrase', '',
                                  '--quick-generate-key', 'Disposable apt test <apt@example.invalid>',
                                  'ed25519', 'sign', '0'])
        records = cls.run_command(cls.gpg + ['--with-colons', '--list-keys']).decode().splitlines()
        cls.fingerprint = next(line.split(':')[9] for line in records if line.startswith('fpr:'))
        cls.key = cls.root / 'key.asc'
        cls.key.write_bytes(cls.run_command(cls.gpg + ['--armor', '--export', cls.fingerprint]))
        cls.old_packages = cls.packages('1.0.0-1', 'a' * 24)
        cls.old = cls.root / 'old'
        apt.build(cls.old_packages, cls.old)
        cls.sign(cls.old)
        cls.new_packages = cls.packages('1.1.0-1', 'b' * 24)

    @classmethod
    def tearDownClass(cls):
        cls.run_command(['gpgconf', '--homedir', str(cls.home), '--kill', 'gpg-agent'])
        cls.temporary.cleanup()

    @staticmethod
    def run_command(args):
        return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=60)

    @classmethod
    def packages(cls, version, identity, content='example'):
        directory = cls.root / ('packages-' + version + '-' + content)
        directory.mkdir()
        payload = 'debuglet-payload-' + identity
        for name in ('debuglet', payload):
            staging = directory / name
            (staging / 'DEBIAN').mkdir(parents=True)
            control = (f'Package: {name}\nVersion: {version}\nArchitecture: amd64\n'
                       'Maintainer: Debuglet test <apt@example.invalid>\nDescription: apt fixture\n')
            if name == 'debuglet':
                control += f'Depends: {payload} (= {version})\n'
            (staging / 'DEBIAN/control').write_text(control)
            (staging / 'example').write_text(content)
            # Release input filenames need not match their Debian control names.
            filename = 'selector.deb' if name == 'debuglet' else 'payload.deb'
            cls.run_command(['dpkg-deb', '--root-owner-group', '--build', str(staging), str(directory / filename)])
        return directory

    @classmethod
    def sign(cls, directory):
        cls.run_command(cls.gpg + ['--yes', '--local-user', cls.fingerprint, '--clearsign',
                                  '--output', str(directory / apt.SUITE / 'InRelease'),
                                  str(directory / apt.SUITE / 'Release')])

    def copied(self, suffix):
        directory = self.root / (self._testMethodName + '-' + suffix)
        shutil.copytree(self.old, directory)
        return directory

    def test_signed_release_and_all_retained_packages(self):
        self.assertEqual(apt.verify(self.old, self.key, self.fingerprint)['packages'], 2)
        upgraded = self.root / 'upgraded'
        apt.build(self.new_packages, upgraded, self.old)
        self.sign(upgraded)
        self.assertEqual(apt.verify(upgraded, self.key, self.fingerprint)['packages'], 4)
        for old_file in (self.old / apt.POOL).glob('*.deb'):
            self.assertEqual(old_file.read_bytes(), (upgraded / apt.POOL / old_file.name).read_bytes())
        old_index = apt.regular(self.old / apt.SUITE / apt.INDEX)
        self.assertEqual((upgraded / apt.SUITE / apt.INDEX.parent / 'by-hash/SHA256' /
                          apt.digest(old_index)).read_bytes(), old_index)

    def test_conflicting_retained_package_refused(self):
        conflicting = self.packages('1.0.0-1', 'a' * 24, 'conflicting')
        with self.assertRaisesRegex(ValueError, 'replace a retained package'):
            apt.build(conflicting, self.root / 'conflict', self.old)

    def test_older_selector_refused(self):
        older = self.packages('0.9.0-1', 'c' * 24)
        with self.assertRaisesRegex(ValueError, 'older selector'):
            apt.build(older, self.root / 'older', self.old)

    def test_wrong_fingerprint_and_wrong_key_refused(self):
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            apt.verify(self.old, self.key, '0' * 40)
        self.run_command(self.gpg + ['--pinentry-mode', 'loopback', '--passphrase', '',
                                   '--quick-generate-key', 'Wrong apt test <wrong@example.invalid>',
                                   'ed25519', 'sign', '0'])
        records = self.run_command(self.gpg + ['--with-colons', '--list-keys', 'wrong@example.invalid']).decode().splitlines()
        fingerprint = next(line.split(':')[9] for line in records if line.startswith('fpr:'))
        key = self.root / 'wrong.asc'
        key.write_bytes(self.run_command(self.gpg + ['--armor', '--export', fingerprint]))
        with self.assertRaises(subprocess.CalledProcessError):
            apt.verify(self.old, key, fingerprint)

    def test_each_hash_binding_refuses_modified_bytes(self):
        targets = ['dists/stable/InRelease', str(apt.SUITE / apt.INDEX),
                   str(next((self.old / apt.POOL).glob('*.deb')).relative_to(self.old))]
        for index, target in enumerate(targets):
            with self.subTest(target=target):
                directory = self.copied(str(index))
                path = directory / target
                if target.endswith('InRelease'):
                    path.write_bytes(path.read_bytes().replace(b'Origin: Debuglet', b'Origin: Tampered'))
                else:
                    path.write_bytes(path.read_bytes() + b'corruption')
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    apt.verify(directory, self.key, self.fingerprint)

    def test_fetch_verifies_before_retaining_and_bootstrap_is_explicit(self):
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(RepositoryTests.root), **kwargs)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            with self.assertRaises(ValueError):
                apt.fetch(url + '/old', self.root / 'no-http', self.key, self.fingerprint)
            result = apt.fetch(url + '/old', self.root / 'fetched', self.key, self.fingerprint, allow_local_http=True)
            self.assertEqual(result['packages'], 2)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                apt.fetch(url + '/old', self.root / 'bootstrap-existing', self.key, self.fingerprint,
                          bootstrap=True, allow_local_http=True)
            result = apt.fetch(url + '/absent', self.root / 'bootstrap', self.key, self.fingerprint,
                               bootstrap=True, allow_local_http=True)
            self.assertTrue(result['bootstrap'])
            with self.assertRaises(OSError):
                apt.fetch(url + '/absent', self.root / 'missing', self.key, self.fingerprint, allow_local_http=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
