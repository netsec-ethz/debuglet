"""Scanner failure-path controls; no network or production credentials."""
import datetime
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VULNERABILITIES = load('check-vulnerabilities')
CONFIG = {'config': {'protocol_version': 'v1.0.0', 'scanner_name': 'govulncheck',
                     'scanner_version': 'v1.7.0', 'scan_mode': 'source', 'scan_level': 'symbol',
                     'db': 'https://vuln.go.dev', 'db_last_modified': '2026-09-28T00:00:00Z'}}
SBOM = {'SBOM': {'roots': ['fixture.invalid/control']}}
FINDING = {'finding': {'osv': 'GO-2021-0113', 'trace': [
    {'module': 'golang.org/x/text', 'package': 'golang.org/x/text/language', 'function': 'Parse'}]}}
TODAY = datetime.date(2026, 9, 28)


def stream(*events):
    return '\n'.join(json.dumps(event, indent=2) for event in events)


class VulnerabilityPolicyTest(unittest.TestCase):
    def test_reachable_symbol_fails_and_uncalled_module_is_informational(self):
        _, findings = VULNERABILITIES.check(stream(CONFIG, SBOM, FINDING), [], TODAY)
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]['exception'])
        uncalled = {'finding': {'osv': 'GO-2021-0113', 'trace': [{'module': 'golang.org/x/text'}]}}
        self.assertEqual(VULNERABILITIES.check(stream(CONFIG, SBOM, uncalled), [], TODAY)[1], [])

    def test_missing_malformed_or_wrong_level_output_fails(self):
        bad = json.loads(json.dumps(CONFIG))
        bad['config']['scan_level'] = 'module'
        for evidence in ('', '{}', '{', stream(CONFIG), stream(bad, SBOM),
                         stream(CONFIG, SBOM, {'finding': {}}), stream(CONFIG, SBOM, {'unknown': {}})):
            with self.subTest(evidence=evidence), self.assertRaises((ValueError, KeyError)):
                VULNERABILITIES.check(evidence, [], TODAY)

    def test_exception_is_exact_reviewed_and_expires(self):
        exception = {'id': 'GO-2021-0113', 'module': 'golang.org/x/text',
                     'expires': '2026-10-05', 'reason': 'Fixture', 'review': 'https://example.invalid/review'}
        evidence = stream(CONFIG, SBOM, FINDING)
        self.assertEqual(VULNERABILITIES.check(evidence, [exception], TODAY)[1][0]['exception'], exception)
        for changes in ({'expires': '2026-09-27'}, {'expires': '2026-11-01'}, {'review': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                VULNERABILITIES.check(evidence, [dict(exception, **changes)], TODAY)
        self.assertIsNone(VULNERABILITIES.check(evidence, [dict(exception, module='other')], TODAY)[1][0]['exception'])


if __name__ == '__main__':
    unittest.main()
