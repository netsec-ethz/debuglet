import copy
import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('image_policy', Path(__file__).with_name('check-image-vulnerabilities.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
TODAY = datetime.date(2026, 9, 30)
IDENTITY = 'sha256:' + '1' * 64


def report(severity='High'):
    return {
        'descriptor': {'name': 'grype', 'version': '0.119.0',
                       'db': {'status': {'valid': True, 'schemaVersion': 'v6.1.9',
                                         'built': '2026-09-30T06:32:47Z', 'from': 'https://grype.anchore.io/databases/fixture'}},
                       'configuration': {'only-fixed': False, 'only-notfixed': False,
                                         'exclude': [], 'vex-documents': [], 'search': {'scope': 'squashed'}}},
        'source': {'type': 'image', 'target': {'imageID': IDENTITY, 'os': 'linux', 'architecture': 'amd64'}},
        'matches': [{'vulnerability': {'id': 'CVE-2026-12345', 'namespace': 'debian:distro:debian:12',
                                      'severity': severity, 'dataSource': 'https://security-tracker.debian.org/tracker/CVE-2026-12345',
                                      'fix': {'state': 'not-fixed', 'versions': []}},
                     'artifact': {'name': 'example', 'version': '1.0', 'type': 'deb',
                                  'purl': 'pkg:deb/debian/example@1.0', 'locations': [{'path': '/var/lib/dpkg/status'}]}}],
    }


class ImagePolicyTests(unittest.TestCase):
    def check(self, scan, exceptions=None, role='executor'):
        return policy.check(scan, exceptions or [], role, IDENTITY, today=TODAY)[1]

    def test_all_findings_remain_visible_including_unfixed(self):
        for severity in ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']:
            findings = self.check(report(severity))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0][0]['severity'], severity)
            self.assertIsNone(findings[0][2])

    def test_exception_is_exact_and_time_limited(self):
        exception = {'role': 'executor', 'id': 'CVE-2026-12345', 'package': 'pkg:deb/debian/example@1.0',
                     'expires': '2026-10-07', 'reason': 'Reviewed fixture', 'review': 'https://example.invalid/review/1'}
        self.assertEqual(self.check(report(), [exception])[0][2], exception)
        self.assertIsNone(self.check(report(), [exception], role='cli')[0][2])
        for key, value in [('expires', '2026-09-29'), ('expires', '2026-10-31'), ('review', 'http://example.invalid'),
                           ('role', '*'), ('id', '*'), ('package', '*'), ('reason', ''), ('review', 'https://example.invalid/a b')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(report(), [dict(exception, **{key: value})])
        with self.assertRaises(ValueError):
            self.check(report(), [exception, exception])

    def test_missing_or_malformed_output_never_passes(self):
        mutations = [
            lambda d: d.clear(),
            lambda d: d.pop('matches'),
            lambda d: d.update(matches=None),
            lambda d: d['descriptor'].update(version='different'),
            lambda d: d['descriptor']['db']['status'].update(valid=False),
            lambda d: d['descriptor']['db']['status'].update(built='2026-09-20T00:00:00Z'),
            lambda d: d['descriptor']['db']['status'].update(built='2026-10-01T00:00:00Z'),
            lambda d: d['descriptor']['configuration'].update(**{'only-fixed': True}),
            lambda d: d.update(ignoredMatches=[d['matches'][0]]),
            lambda d: d['source']['target'].update(imageID='sha256:' + '2' * 64),
            lambda d: d['matches'][0]['vulnerability'].update(severity='Invalid'),
            lambda d: d['matches'][0]['artifact'].update(locations=[]),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, KeyError, TypeError)):
                scan = report()
                mutate(scan)
                self.check(scan)

    def test_duplicate_truncated_and_oversize_reports_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.json'
            for raw in ['{"matches":[],"matches":[]}', '{', 'NaN', json.dumps(report())]:
                path.write_text(raw)
                with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                    policy.read_json(path, 32)

    def test_control_is_pinned_and_cannot_substitute_for_image(self):
        scan = copy.deepcopy(report())
        scan['source'] = {'type': 'purl', 'target': policy.CONTROL}
        self.assertEqual(len(self.check(scan, role='control')), 1)
        with self.assertRaises((ValueError, TypeError)):
            self.check(scan)

    def test_nvd_match_with_unspecified_fix_stays_visible(self):
        scan = report('High')
        scan['matches'][0]['vulnerability']['fix'] = {'versions': [], 'state': ''}
        findings = self.check(scan)
        self.assertEqual(findings[0][0]['severity'], 'High')
        self.assertIsNone(findings[0][2])


if __name__ == '__main__':
    unittest.main()
