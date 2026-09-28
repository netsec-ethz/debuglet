"""Release authorization and immutable-subject regression checks."""
import copy
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
VERSION = 'v1.2.3'
SOURCE = 'a' * 40
BUILDER = 'https://github.com/netsec-ethz/debuglet/actions/runs/123'


def run_fixture():
    return {'id': 123, 'repository': {'full_name': release.REPOSITORY},
            'head_repository': {'full_name': release.REPOSITORY}, 'path': release.WORKFLOW,
            'head_sha': SOURCE, 'head_branch': VERSION, 'event': 'push', 'status': 'completed',
            'conclusion': 'success', 'html_url': BUILDER, 'pull_requests': [], 'run_attempt': 2}


def job_fixture():
    return [{'id': index + 1, 'name': name, 'run_id': 123, 'run_attempt': 2,
             'status': 'completed', 'conclusion': 'success'} for index, name in enumerate(sorted(release.LANES))]


class ReleaseTests(unittest.TestCase):
    def test_signing_environment_requires_independent_review(self):
        configured = {'name': 'release-signing', 'protection_rules': [
            {'type': 'required_reviewers', 'prevent_self_review': True,
             'reviewers': [{'type': 'Team', 'reviewer': {'id': 1}}]}]}
        release.check_environment(configured)
        for broken in ({'name': 'release-signing'}, {'name': 'other', 'protection_rules': configured['protection_rules']},
                       {'name': 'release-signing', 'protection_rules': [
                           {'type': 'required_reviewers', 'prevent_self_review': False, 'reviewers': [{}]}]},
                       {'name': 'release-signing', 'protection_rules': [
                           {'type': 'required_reviewers', 'prevent_self_review': True, 'reviewers': []}]}):
            with self.assertRaises(ValueError):
                release.check_environment(broken)

    def test_exact_complete_successful_run_is_eligible(self):
        gates = release.check_gates(run_fixture(), job_fixture(), VERSION, SOURCE)
        release.validate_gates(gates, VERSION, SOURCE, BUILDER)
        self.assertEqual(set(gates['jobs']), release.LANES)

    def test_untrusted_or_different_runs_cannot_be_signed(self):
        changes = {'repository': {'full_name': 'other/debuglet'},
                   'head_repository': {'full_name': 'fork/debuglet'}, 'path': 'other.yml',
                   'head_sha': 'b' * 40, 'head_branch': 'main', 'event': 'pull_request',
                   'status': 'in_progress', 'conclusion': 'failure',
                   'html_url': 'https://example.test/actions/runs/123',
                   'pull_requests': [{'number': 1}], 'run_attempt': 0}
        for key, value in changes.items():
            with self.subTest(key=key):
                run = run_fixture()
                run[key] = value
                with self.assertRaises(ValueError):
                    release.check_gates(run, job_fixture(), VERSION, SOURCE)

    def test_missing_skipped_failed_duplicate_or_other_attempt_lane_fails(self):
        for field, value in [('status', 'queued'), ('conclusion', 'skipped'),
                             ('conclusion', 'failure'), ('run_id', 124), ('run_attempt', 1)]:
            jobs = job_fixture()
            jobs[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                release.check_gates(run_fixture(), jobs, VERSION, SOURCE)
        for jobs in (job_fixture()[:-1], job_fixture() + job_fixture()[:1]):
            with self.assertRaises(ValueError):
                release.check_gates(run_fixture(), jobs, VERSION, SOURCE)

    def test_signed_gate_metadata_cannot_change_source_or_builder(self):
        original = release.check_gates(run_fixture(), job_fixture(), VERSION, SOURCE)
        for field, value in [('source_sha', 'b' * 40), ('builder', BUILDER + '4'),
                             ('protected', False), ('ref', 'refs/heads/main')]:
            gates = copy.deepcopy(original)
            gates[field] = value
            with self.assertRaises(ValueError):
                release.validate_gates(gates, VERSION, SOURCE, BUILDER)

    def test_stage_requires_exact_component_set_and_preserves_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packages = root / 'packages'
            packages.mkdir()
            expected = release.package_names(VERSION)
            for name in expected:
                (packages / name).write_bytes(name.encode())
            release.stage(packages, root / 'release', VERSION)
            self.assertEqual({p.name for p in (root / 'release').iterdir()}, expected)
            for path in (root / 'release').iterdir():
                self.assertEqual(path.read_bytes(), path.name.encode())
            (packages / 'unexpected').write_text('never sign')
            with self.assertRaises(ValueError):
                release.stage(packages, root / 'bad', VERSION)

    def test_subject_checksums_and_source_are_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = release.package_names(VERSION) | release.METADATA
            for name in expected:
                (root / name).write_bytes(name.encode())
            subject = {'schema_version': 1, 'version': VERSION, 'source_sha': SOURCE, 'builder': BUILDER,
                       'files': {name: release.digest(root / name) for name in expected}}
            (root / 'release.json').write_text(json.dumps(subject))
            release.load_subject(root, VERSION, SOURCE, BUILDER)
            for source, builder in [('b' * 40, BUILDER), (SOURCE, BUILDER + '4')]:
                with self.assertRaises(ValueError):
                    release.load_subject(root, VERSION, source, builder)
            (root / 'extra').write_text('not signed')
            with self.assertRaises(ValueError):
                release.load_subject(root, VERSION)
            (root / 'extra').unlink()
            (root / 'install.sh').write_text('changed')
            with self.assertRaises(ValueError):
                release.load_subject(root, VERSION)


class SecretRangeTests(unittest.TestCase):
    def test_tag_creation_scans_history_and_ordinary_update_scans_the_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / 'scripts'
            scripts.mkdir()
            source = Path(__file__).resolve().parents[1] / 'scripts' / 'ci-secrets.sh'
            shutil.copyfile(source, scripts / source.name)
            environment = dict(os.environ, GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.test',
                               GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@example.test')
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, env=environment, text=True).strip()
            git('init', '-q')
            (root / 'record').write_text('first')
            git('add', 'record')
            git('commit', '-qm', 'first')
            first = git('rev-parse', 'HEAD')
            (root / 'record').unlink()
            git('add', '-u')
            git('commit', '-qm', 'second')
            for base, count in [('', 2), ('0' * 40, 2), (first, 1)]:
                result = subprocess.run(['bash', '-c', 'source "$1"; secret_scan_range "$2"', '--',
                                         str(scripts / source.name), base], cwd=root, env=environment,
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(git('rev-list', result.stdout.strip()).splitlines()), count)
            result = subprocess.run(['bash', '-c', 'source "$1"; secret_scan_range "$2"', '--',
                                     str(scripts / source.name), 'f' * 40], cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
