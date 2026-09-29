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
        self.exceptions = Path(self.temporary.name) / 'exceptions'
        self.exceptions.write_text('# reviewed\nfixture.txt:github-pat:1\n')
        self.source = Path(self.temporary.name) / 'source'
        self.source.mkdir()

    def run_scan(self, code, findings):
        def run(args, **kwargs):
            self.assertIn('--redact=100', args)
            self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
            self.assertEqual(args[args.index('--gitleaks-ignore-path') + 1], str(self.exceptions))
            self.assertEqual(args[-1], str(self.source))
            raw = Path(args[args.index('--report-path') + 1])
            raw.write_text(json.dumps(findings))
            return subprocess.CompletedProcess(args, code)
        with patch.object(SECRETS.subprocess, 'run', side_effect=run):
            return SECRETS.scan('fixture-scanner', ['dir', str(self.source)], self.report, self.exceptions)

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

    def test_exceptions_must_name_one_exact_finding(self):
        for entry in ('internal/', 'internal/:generic-api-key:1', 'pkg/*.go:generic-api-key:1',
                      'pkg/a.go:generic-api-key', 'pkg/a.go:generic-api-key:0',
                      'pkg/a.go:*:1', 'pkg/a b.go:generic-api-key:1', 'abc:pkg/a.go:rule:1'):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.exceptions.write_text(entry + '\n')
                self.run_scan(0, [])
        self.exceptions.write_text('pkg/a.go:generic-api-key:1\n' + 'a' * 40 + ':pkg/a.go:github-pat:2\n')
        self.assertFalse(self.run_scan(0, []))

    def test_unreviewed_scanner_configuration_is_refused(self):
        def attempt(arguments):
            with patch.object(SECRETS.subprocess, 'run') as run, self.assertRaises(ValueError):
                SECRETS.scan('fixture-scanner', arguments, self.report, self.exceptions)
            run.assert_not_called()
        for flag in ('--config=x.toml', '-c', '--baseline-path=b.json', '-i', '--gitleaks-ignore-path=.'):
            with self.subTest(flag=flag):
                attempt(['dir', flag, str(self.source)])
        attempt(['dir'])
        with patch.dict(SECRETS.os.environ, {'GITLEAKS_CONFIG_TOML': '[allowlist]'}):
            attempt(['dir', str(self.source)])
        (self.source / '.gitleaksignore').write_text('other.txt:github-pat:1\n')
        attempt(['dir', str(self.source)])
        (self.source / '.gitleaksignore').write_bytes(self.exceptions.read_bytes())
        self.assertFalse(self.run_scan(0, []))
        (self.source / '.gitleaks.toml').write_text('[allowlist]\n')
        attempt(['dir', str(self.source)])


if __name__ == '__main__':
    unittest.main()
