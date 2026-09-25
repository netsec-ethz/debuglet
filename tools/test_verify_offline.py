"""Focused negative checks for the offline witness, not runtime acceptance."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('offline', Path(__file__).with_name('verify-offline.py'))
offline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offline)


class WrapperCleanupTest(unittest.TestCase):
    def run_fixture(self, leak):
        with tempfile.TemporaryDirectory(prefix='debuglet-witness-test-') as temp:
            root = Path(temp)
            tmp = root / 'tmp'
            tmp.mkdir()
            proc = root / 'proc'
            proc.mkdir()
            (proc / '1').mkdir()
            commands = root / 'tools'
            commands.mkdir()
            for name in ['id', 'mkdir', 'cat']:
                (commands / name).symlink_to(shutil.which(name))
            guest = root / 'fixture'
            # This is deliberately a fake program: a successful receipt alone
            # must not conceal an observed file or process left behind.
            guest.write_text('#!/bin/sh\nif [ \"$5\" = version ]; then printf \"{}\\n\"; exit 0; fi\n' + leak.format(tmp=tmp, proc=proc) + '\nprintf "{{}}\\n"\n')
            guest.chmod(0o755)
            wrapper = offline.WRAPPER
            wrapper = wrapper.replace('  [ \"$pid\" = \"$$\" ] && continue', '  [ \"$pid\" = 1 ] && continue')
            wrapper = wrapper.replace('/tmp', str(tmp)).replace('/proc/', str(proc) + '/')
            wrapper = wrapper.replace('/opt/debuglet/bin/dbl', str(guest))
            wrapper = wrapper.replace('[ "$(id -u)" = 65532 ]', f'[ "$(id -u)" = {os.getuid()} ]')
            return subprocess.run(['/bin/sh', '-c', wrapper], cwd=root,
                                  env={'PATH': str(commands)}, capture_output=True,
                                  timeout=3, check=False)

    def test_clean_fixture_is_observed(self):
        result = self.run_fixture(':')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'CLEANUP_OBSERVED_BEFORE_CONTAINER_EXIT=1', result.stderr)

    def test_leaks_are_not_success(self):
        for script in [
            ': > "{tmp}/work/leak"', ': > "{tmp}/state/leak"',
            ': > "{tmp}/leak"', ': > "{tmp}/.hidden"',
            '/bin/mkdir "{proc}/999999"',
        ]:
            with self.subTest(script=script):
                result = self.run_fixture(script)
                self.assertNotEqual(result.returncode, 0, result.stderr.decode())
                self.assertNotIn(b'CLEANUP_OBSERVED_BEFORE_CONTAINER_EXIT=1', result.stderr)
                self.assertRegex(result.stderr.decode(), 'remaining|unexpected temporary')


if __name__ == '__main__':
    unittest.main()
