"""Isolated bootstrap checks using release assets and a fake HTTP downloader."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


BOOTSTRAP = Path(__file__).resolve().parents[1] / 'scripts' / 'bootstrap.sh'
VERSION = 'v0.0.0-dev.0123456789ab'
ARCHIVE = f'debuglet-{VERSION}-linux-amd64.tar.gz'
RELEASE_URL = 'https://github.com/netsec-ethz/debuglet/releases/download/'
FAKE_CURL = r'''#!PYTHON
import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['TEST_CURL_LOG'], 'a') as log:
    log.write(json.dumps({'url': args[-1], 'args': args}) + '\n')
name = args[-1].rsplit('/', 1)[1]
asset = Path(os.environ['TEST_ASSETS']) / name
status, exit_code = '200', '0'
if name == os.environ.get('TEST_FAILURE_ASSET', name):
    status = os.environ.get('TEST_HTTP_STATUS', status)
    exit_code = os.environ.get('TEST_CURL_EXIT', exit_code)
if not asset.is_file():
    status, exit_code = '404', '22'
if status == '200':
    shutil.copyfile(asset, args[args.index('--output')+1])
print(status, end='')
sys.exit(int(exit_code))
'''
INSTALLER = r'''#!/bin/sh
set -eu
printf '%s\n' "$@" > "$TEST_INSTALL_LOG"
if [ "${TEST_INSTALL_EXIT:-0}" != 0 ]; then exit "$TEST_INSTALL_EXIT"; fi
prefix=
while [ "$#" -gt 0 ]; do
    if [ "$1" = --prefix ]; then prefix=$2; fi
    shift 2
done
mkdir -p "$prefix/bin"
printf '#!/bin/sh\nexit 0\n' > "$prefix/bin/dbl"
chmod +x "$prefix/bin/dbl"
'''


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        for name in ('sha256sum', 'tar', 'sh'):
            self.assertIsNotNone(shutil.which(name), f'required test tool: {name}')
        self.temp = tempfile.TemporaryDirectory(prefix='debuglet-bootstrap-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        fake = self.tools / 'curl'
        fake.write_text(FAKE_CURL.replace('PYTHON', sys.executable, 1))
        fake.chmod(0o755)
        self.tmp = self.root / 'scratch'
        self.tmp.mkdir()
        self.prefix = self.root / "prefix with spaces and 'quote"
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.curl_log = self.root / 'curl.jsonl'
        self.install_log = self.root / 'install.args'
        self.env = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ['PATH'],
                        DEBUGLET_VERSION=VERSION, HOME=str(self.root / 'home'), TMPDIR=str(self.tmp),
                        DEBUGLET_PREFIX=str(self.prefix), TEST_ASSETS=str(self.assets),
                        TEST_CURL_LOG=str(self.curl_log), TEST_INSTALL_LOG=str(self.install_log))
        for key in ('TEST_HTTP_STATUS', 'TEST_CURL_EXIT', 'TEST_FAILURE_ASSET', 'TEST_INSTALL_EXIT'):
            self.env.pop(key, None)
        self.make_assets()

    def make_assets(self, archive=b'tiny fixture package', installer=INSTALLER.encode(),
                    version=VERSION):
        archive_name = f'debuglet-{version}-linux-amd64.tar.gz'
        for name, data in {
            archive_name: archive, 'install.sh': installer,
            'SHA256SUMS': (hashlib.sha256(archive).hexdigest() + '  ' + archive_name + '\n' +
                          hashlib.sha256(installer).hexdigest() + '  install.sh\n').encode(),
        }.items():
            (self.assets / name).write_bytes(data)

    def run_bootstrap(self, extra=None, trace=False):
        env = dict(self.env)
        if extra:
            env.update(extra)
        args = ['/bin/sh'] + (['-x'] if trace else []) + [str(BOOTSTRAP)]
        result = subprocess.run(args, cwd=self.root, env=env, capture_output=True,
                                text=True, timeout=8, check=False)
        self.assertEqual(list(self.tmp.iterdir()), [], 'bootstrap left temporary files')
        return result

    def calls(self):
        return [json.loads(line) for line in self.curl_log.read_text().splitlines()]

    def assert_not_installed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.install_log.exists(), 'unverified installer executed')
        self.assertFalse(self.prefix.exists())

    def test_pinned_release_installs_and_prints_usable_commands(self):
        result = self.run_bootstrap(trace=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([call['url'] for call in calls],
                         [RELEASE_URL + VERSION + '/' + name
                          for name in (ARCHIVE, 'install.sh', 'SHA256SUMS')])
        for call in calls:
            args = call['args']
            self.assertEqual(args[0], '-q')
            self.assertIn('--location', args)
            self.assertEqual(args[args.index('--max-redirs') + 1], '5')
            self.assertEqual(args[args.index('--proto') + 1], '=https')
            self.assertEqual(args[args.index('--proto-redir') + 1], '=https')
            self.assertNotIn('--header', args)
        args = self.install_log.read_text().splitlines()
        self.assertEqual(args[-4:], ['--version', VERSION, '--prefix', str(self.prefix)])
        self.assertTrue((self.prefix / 'bin/dbl').is_file())
        commands = result.stdout.split('Next commands:\n', 1)[1]
        check = subprocess.run(['/bin/sh', '-c', commands + '\nprintf "%s\\n" "$PATH"'],
                               env=self.env, text=True, capture_output=True, timeout=3, check=False)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertTrue(check.stdout.startswith(str(self.prefix / 'bin') + ':'))

    def test_valid_release_versions(self):
        for version in ('v1.2.3', 'v1.2.3-rc.1'):
            with self.subTest(version=version):
                self.make_assets(version=version)
                result = self.run_bootstrap({'DEBUGLET_VERSION': version})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls()[-1]['url'], RELEASE_URL + version + '/SHA256SUMS')

    def test_default_and_relative_prefix(self):
        self.env.pop('DEBUGLET_PREFIX')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((Path(self.env['HOME']) / '.local/bin/dbl').is_file())
        result = self.run_bootstrap({'DEBUGLET_PREFIX': 'relative prefix'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'relative prefix/bin/dbl').is_file())

    def test_http_and_transfer_failures_do_not_install(self):
        for name in (ARCHIVE, 'install.sh', 'SHA256SUMS'):
            for status, exit_code in [('403', '22'), ('404', '22'), ('000', '7'),
                                      ('200', '18'), ('302', '0')]:
                with self.subTest(name=name, status=status, exit_code=exit_code):
                    result = self.run_bootstrap({'TEST_FAILURE_ASSET': name,
                                                 'TEST_HTTP_STATUS': status,
                                                 'TEST_CURL_EXIT': exit_code})
                    self.assert_not_installed(result)

    def test_invalid_version_does_not_download(self):
        for version in ('', 'latest', 'main', '../v1.2.3', 'v1.2.3/other', 'v1.2.3?x=1',
                        'v1.2.3\n', 'v1.2.3;touch x', 'v01.2.3', 'v1.2', 'v1.2.3.4',
                        'v1.2.3-', 'v1.2.3-rc..1', 'v1.2.3-' + 'a' * 128):
            with self.subTest(version=version):
                result = self.run_bootstrap({'DEBUGLET_VERSION': version})
                self.assert_not_installed(result)
                self.assertFalse(self.curl_log.exists())

    def test_checksum_failure_prevents_installer_execution(self):
        for filename in (ARCHIVE, 'install.sh'):
            with self.subTest(filename=filename):
                self.make_assets()
                with (self.assets / filename).open('ab') as asset:
                    asset.write(b'corrupted after checksumming')
                result = self.run_bootstrap()
                self.assert_not_installed(result)
                self.assertIn('checksum verification failed', result.stderr)

    def test_missing_assets_are_refused(self):
        for name in (ARCHIVE, 'install.sh', 'SHA256SUMS'):
            with self.subTest(name=name):
                self.make_assets()
                (self.assets / name).unlink()
                self.assert_not_installed(self.run_bootstrap())

    def test_malformed_or_ambiguous_checksums_are_refused(self):
        checksums = (self.assets / 'SHA256SUMS').read_text()
        archive_sum, installer_sum = checksums.splitlines(keepends=True)
        for value in ('', archive_sum, installer_sum, checksums + archive_sum,
                      checksums + installer_sum, checksums.replace('  ', ' ', 1),
                      checksums.replace(ARCHIVE, '../' + ARCHIVE),
                      checksums + '0' * 64 + '  unrelated\n',
                      checksums[1:], 'z' + checksums[1:]):
            with self.subTest(value=value):
                (self.assets / 'SHA256SUMS').write_text(value)
                self.assert_not_installed(self.run_bootstrap())

    def test_installer_failure_propagates_and_cleans_download(self):
        result = self.run_bootstrap({'TEST_INSTALL_EXIT': '19'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('package installer failed', result.stderr)
        self.assertTrue(self.install_log.exists())
        self.assertFalse(self.prefix.exists())


if __name__ == '__main__':
    unittest.main()
