#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Small package-format checks; the build's own smoke check compiles offline."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('studio_package', Path(__file__).with_name('package.py'))
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def payload(self):
        stage = self.root / 'payload'
        for directory in package.RUNTIME_DIRECTORIES | {'bin'}:
            (stage / directory).mkdir(parents=True, exist_ok=True)
        (stage / 'bin/dbl-studio').write_bytes(b'fixture binary')
        (stage / 'bin/dbl-studio').chmod(0o755)
        (stage / 'LICENSE').write_bytes(b'fixture license\n')
        return stage

    def test_archive_is_independent_of_mtime_and_output_name(self):
        stage = self.payload()
        manifest = package.manifest(stage, 'a' * 40, {'modules': {}})
        first, second = self.root / 'first.tar.gz', self.root / 'second.tar.gz'
        package.archive(stage, first)
        for path in stage.rglob('*'):
            os.utime(path, (1234, 1234))
        package.archive(stage, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            members = archive.getmembers()
            self.assertEqual([entry.name for entry in members], sorted(entry.name for entry in members))
            self.assertTrue(all(entry.uid == 0 and entry.gid == 0 and entry.mtime == 0 for entry in members))
            self.assertTrue(all(entry.isfile() or entry.isdir() for entry in members))
            self.assertEqual(archive.extractfile('LICENSE').read(), b'fixture license\n')
            self.assertEqual(json.load(archive.extractfile('studio-manifest.json')), manifest)
        self.assertEqual(manifest['files']['bin/dbl-studio']['mode'], 0o755)
        self.assertEqual(manifest['files']['LICENSE']['mode'], 0o644)
        self.assertTrue(package.RUNTIME_DIRECTORIES <= set(manifest['directories']))
        self.assertNotIn('studio-manifest.json', manifest['files'])

    def test_manifest_detects_changed_payload(self):
        stage = self.payload()
        manifest = package.manifest(stage, 'b' * 40, {})
        (stage / 'LICENSE').write_text('changed')
        self.assertNotEqual(package.digest(stage / 'LICENSE')['sha256'],
                            manifest['files']['LICENSE']['sha256'])

    def test_archive_refuses_links_and_special_files(self):
        stage = self.payload()
        (stage / 'escape').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'linked payload'):
            package.archive(stage, self.root / 'linked.tar.gz')
        (stage / 'escape').unlink()
        os.mkfifo(stage / 'pipe')
        with self.assertRaisesRegex(ValueError, 'nonregular payload'):
            package.archive(stage, self.root / 'fifo.tar.gz')

    def test_input_tree_refuses_links(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'escape').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'linked input'):
            package.copy_tree(source, self.root / 'destination')

    def test_source_must_be_clean_and_identified(self):
        with patch.object(package, 'command', return_value=' M go.mod'):
            with self.assertRaisesRegex(ValueError, 'clean committed'):
                package.clean_source(self.root)
        with patch.object(package, 'command', side_effect=['', 'not-a-revision']):
            with self.assertRaisesRegex(ValueError, 'invalid source'):
                package.clean_source(self.root)

    def test_environment_disables_downloads_and_ignores_go_settings(self):
        with patch.dict(os.environ, {'GOFLAGS': '-race', 'GOTOOLCHAIN': 'auto',
                                     'GOPROXY': 'https://example.invalid', 'GOROOT': '/untrusted'}):
            env = package.environment()
        self.assertEqual(env['GOPROXY'], 'off')
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertEqual(env['GOFLAGS'], '')
        self.assertEqual(env['CGO_ENABLED'], '0')
        self.assertNotIn('GOROOT', env)

    def test_static_check_rejects_interpreter(self):
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', header, 32, 64)
        struct.pack_into('<HH', header, 54, 56, 1)
        path = self.root / 'binary'
        path.write_bytes(header + struct.pack('<I', 3) + bytes(52))
        with self.assertRaisesRegex(ValueError, 'dynamically linked'):
            package.require_static(path)
        path.write_bytes(header + struct.pack('<I', 1) + bytes(52))
        package.require_static(path)

    def test_path_policy(self):
        for name in ('../outside', '/absolute', './relative', 'double//slash',
                     'line\nbreak', 'back\\slash', 'trailing/'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                package.safe_name(name)
        self.assertEqual(package.safe_name('sdk/internal/guestio/abi.go'),
                         'sdk/internal/guestio/abi.go')

    def test_sdk_must_use_tracked_regular_source(self):
        source = self.root / 'source'
        source.mkdir()
        for name in ('go.mod', 'go.sum', 'LICENSE', 'NOTICE'):
            (source / name).write_text('fixture')
        tracked = {name: '100644' for name in ('go.mod', 'go.sum', 'LICENSE')}
        with self.assertRaisesRegex(ValueError, 'tracked regular'):
            package.copy_sdk(source, self.root / 'payload', [], tracked)


if __name__ == '__main__':
    unittest.main()
