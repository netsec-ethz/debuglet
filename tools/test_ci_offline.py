"""Offline witness failure controls; no Docker or binaries execute here."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('offline', Path(__file__).with_name('check-offline.py'))
OFFLINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OFFLINE)
RESULT = {'version': 'v0.0.0-dev.aaaaaaaaaaaa', 'state': 'RunStateExited', 'cleanup': 'complete',
          'executor_id': 'fixture-executor', 'run_id': 'fixture-run', 'response': 'DEBUGLET/1 fixture'}
SHA = 'a' * 40


class OfflineWitnessTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        manifest = self.root / 'share/debuglet/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'source_sha': SHA, 'dirty': False, 'version': RESULT['version']}))
        self.archive = self.root / 'candidate.tar.gz'
        self.archive.write_bytes(b'fixture payload')
        self.evidence = self.root / 'evidence'

    def witness(self, *, output=None, status=0, remaining=''):
        def check_output(command, **kwargs):
            return 'sha256:fixture' if command[1:3] == ['image', 'inspect'] else ('debuglet-offline-fixture' if remaining else '')

        def run(command, **kwargs):
            if command[1] == 'run':
                self.assertIn('--pull=never', command)
                self.assertEqual(command[command.index('--network') + 1], 'none')
                self.assertEqual(command[command.index('--cap-drop') + 1], 'ALL')
                self.assertIn('--read-only', command)
                self.assertEqual(command.count('--mount'), 1)
                self.assertIn('target=/payload,readonly', command[command.index('--mount') + 1])
                return subprocess.CompletedProcess(command, status, output or json.dumps(RESULT), '')
            return subprocess.CompletedProcess(command, 0)

        with patch.object(OFFLINE.uuid, 'uuid4', return_value=type('ID', (), {'hex': 'fixture'})()), \
                patch.object(OFFLINE.subprocess, 'check_output', side_effect=check_output), \
                patch.object(OFFLINE.subprocess, 'run', side_effect=run):
            return OFFLINE.witness('fixture@sha256:pinned', self.root, self.archive, SHA, self.evidence)

    def test_success_binds_the_payload_and_observes_cleanup(self):
        record = self.witness()
        self.assertEqual(record['source_sha'], SHA)
        self.assertEqual(len(record['archive_sha256']), 64)
        self.assertTrue(record['ownership_checked_before_teardown'])
        self.assertTrue(record['container_removed'])

    def test_missing_image_never_pulls_or_runs(self):
        with patch.object(OFFLINE.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, 'inspect')), \
                patch.object(OFFLINE.subprocess, 'run') as run:
            with self.assertRaises(subprocess.CalledProcessError):
                OFFLINE.witness('missing', self.root, self.archive, SHA, self.evidence)
            run.assert_not_called()

    def test_failed_or_malformed_witness_remains_failed_after_cleanup(self):
        for changes in ({'status': 42}, {'output': '{'}, {'output': '{}'},
                        {'output': json.dumps(dict(RESULT, cleanup='incomplete'))}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.witness(**changes)
            record = json.loads((self.evidence / 'witness.json').read_text())
            self.assertTrue(record['container_removed'])
            self.assertNotIn('ownership_checked_before_teardown', record)

    def test_container_remaining_after_cleanup_rejects_success(self):
        with self.assertRaisesRegex(ValueError, 'not removed'):
            self.witness(remaining='owned-container-id')
        self.assertFalse(json.loads((self.evidence / 'witness.json').read_text())['container_removed'])


if __name__ == '__main__':
    unittest.main()
