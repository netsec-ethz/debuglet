"""Scanner failure-path controls; no network or production credentials."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SECRETS = load('scan-secrets')


class SecretScanTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.report = Path(self.temporary.name) / 'safe.json'

    def run_scan(self, code, findings):
        def run(args, **kwargs):
            self.assertIn('--redact=100', args)
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            raw = Path(args[args.index('--report-path') + 1])
            raw.write_text(json.dumps(findings))
            return subprocess.CompletedProcess(args, code)
        with patch.object(SECRETS.subprocess, 'run', side_effect=run):
            return SECRETS.scan('fixture-scanner', ['dir', 'fixture'], self.report)

    def test_match_values_are_never_retained_or_printed(self):
        value = 'invalid-canary-match-value'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertTrue(self.run_scan(10, [{'RuleID': 'fixture', 'File': 'fixture.txt',
                                              'StartLine': 1, 'Match': value, 'Secret': value}]))
        self.assertNotIn(value, output.getvalue() + self.report.read_text())
        self.assertEqual(set(json.loads(self.report.read_text())[0]), {'RuleID', 'File', 'StartLine'})

    def test_execution_failure_and_incomplete_report_fail_closed(self):
        for code, findings in ((2, []), (0, None), (0, [{'Secret': 'fixture'}]), (10, [])):
            with self.subTest(code=code, findings=findings), self.assertRaises(ValueError):
                self.run_scan(code, findings)

    def test_clean_scan_is_explicit_empty_report(self):
        self.assertFalse(self.run_scan(0, []))
        self.assertEqual(json.loads(self.report.read_text()), [])


if __name__ == '__main__':
    unittest.main()
