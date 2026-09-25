"""Controls for the race lane's evidence check, not a race-detector run."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECK = Path(__file__).resolve().parents[1] / 'tools' / 'check-race-evidence.py'
MODULE = 'github.com/netsec-ethz/debuglet'
SCHEDULER = './internal/executor/scheduler/memory'
SESSION = './internal/controlsession'


def events(root, *, tests=(('TestFixture', 'pass'),), result='pass', output=()):
    package = MODULE + root[1:]
    lines = [{'Action': 'start', 'Package': package}]
    for name, action in tests:
        lines.append({'Action': 'run', 'Package': package, 'Test': name})
        lines.append({'Action': action, 'Package': package, 'Test': name, 'Elapsed': 0.1})
    for text in output:
        lines.append({'Action': 'output', 'Package': package, 'Output': text})
    lines.append({'Action': result, 'Package': package, 'Elapsed': 1.5})
    return lines


class RaceEvidenceTest(unittest.TestCase):
    def check(self, lines, roots=(SCHEDULER, SESSION)):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as evidence:
            for line in lines:
                evidence.write(json.dumps(line) + '\n')
            path = evidence.name
        self.addCleanup(Path(path).unlink, missing_ok=True)
        return subprocess.run([sys.executable, str(CHECK), '--evidence', path, *roots],
                              capture_output=True, timeout=60, check=False)

    def test_executed_tests_pass(self):
        result = self.check(events(SCHEDULER) + events(SESSION))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'under the race detector', result.stdout)

    def test_package_without_tests_is_not_evidence(self):
        result = self.check(events(SCHEDULER) + events(SESSION, tests=()))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'no passing test in required package', result.stderr)

    def test_missing_package_fails(self):
        result = self.check(events(SCHEDULER))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'no result for required package', result.stderr)

    def test_only_skipped_tests_fail(self):
        result = self.check(events(SCHEDULER) +
                            events(SESSION, tests=(('TestFixture', 'skip'),)))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'Skipped test', result.stderr)
        self.assertIn(b'no passing test in required package', result.stderr)

    def test_failed_test_fails(self):
        result = self.check(events(SCHEDULER) +
                            events(SESSION, tests=(('TestFixture', 'pass'),
                                                   ('TestOther', 'fail')), result='fail'))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'failed test', result.stderr)

    def test_reported_race_fails_a_passing_package(self):
        result = self.check(events(SCHEDULER) + events(
            SESSION, output=('==================\n', 'WARNING: DATA RACE\n')))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'data race reported', result.stderr)

    def test_build_failure_fails(self):
        lines = events(SCHEDULER) + events(SESSION)
        lines.append({'Action': 'build-fail', 'ImportPath': MODULE + SESSION[1:] + ' [build]'})
        result = self.check(lines)
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'build failed', result.stderr)

    def test_unrequested_package_fails(self):
        result = self.check(events(SCHEDULER) + events(SESSION) +
                            events('./internal/artifact'))
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(b'unrequested package in race results', result.stderr)

    def test_unreadable_results_fail(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as evidence:
            evidence.write('{"Action": "pass"\n')
            path = evidence.name
        self.addCleanup(Path(path).unlink, missing_ok=True)
        result = subprocess.run([sys.executable, str(CHECK), '--evidence', path, SCHEDULER],
                                capture_output=True, timeout=60, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode())
        self.assertIn(b'unreadable Go JSON result', result.stderr)

    def test_wildcard_roots_are_rejected(self):
        result = self.check(events(SCHEDULER), roots=('./internal/...',))
        self.assertNotEqual(result.returncode, 0, result.stdout.decode())
        self.assertIn(b'explicit package root', result.stderr)


if __name__ == '__main__':
    unittest.main()
