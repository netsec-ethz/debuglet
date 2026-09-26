"""GitHub metadata and container-boundary fixtures; no Docker or Go execution."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kernel_isolation', ROOT / 'deploy/ci/kernel-isolation.py')
ISOLATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ISOLATION)
SHA = 'a' * 40
METADATA = {
    'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'netsec-ethz/debuglet',
    'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main',
    'GITHUB_REF_PROTECTED': 'false', 'GITHUB_SHA': SHA,
    'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64',
    'RUNNER_NAME': 'GitHub Actions 1',
}


class MetadataTest(unittest.TestCase):
    def test_hosted_branch_and_pull_request_commits_pass(self):
        for changes in ({}, {'GITHUB_REF_PROTECTED': 'true'},
                        {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/feature'},
                        {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/12/merge',
                         'GITHUB_BASE_REF': 'main'}):
            with self.subTest(changes=changes):
                results = ISOLATION.github_metadata_checks(dict(METADATA, **changes), SHA)
                self.assertTrue(all(item['status'] == 'pass' for item in results), results)

    def test_untrusted_or_incomplete_metadata_fails(self):
        changes = {
            'GITHUB_ACTIONS': '', 'GITHUB_REPOSITORY': 'fork/debuglet',
            'GITHUB_EVENT_NAME': 'pull_request_target', 'GITHUB_REF': 'refs/heads/unreviewed',
            'GITHUB_SHA': 'b' * 40,
            'RUNNER_ENVIRONMENT': 'self-hosted', 'RUNNER_OS': 'Darwin',
            'RUNNER_ARCH': 'ARM64',
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                results = ISOLATION.github_metadata_checks(dict(METADATA, **{key: value}), SHA)
                self.assertTrue(any(item['status'] == 'fail' for item in results), results)
        self.assertTrue(any(item['status'] == 'fail'
                            for item in ISOLATION.github_metadata_checks({}, SHA)))

    def test_ci_enforcement_cannot_be_disabled(self):
        for environment, expected in (({}, False), ({'DEBUGLET_CI_ISOLATION_ENFORCE': '1'}, True),
                                      ({'GITHUB_ACTIONS': 'true', 'DEBUGLET_CI_ISOLATION_ENFORCE': '0'}, True)):
            with self.subTest(environment=environment), patch.dict(os.environ, environment, clear=True):
                self.assertEqual(ISOLATION.enforcing(), expected)


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='debuglet-ci-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for path in ('scripts/ci-github.sh', 'deploy/ci/images.env'):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'Fixture'], cwd=self.root, check=True)
        self.sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        binary = self.root / 'bin'
        binary.mkdir()
        docker = binary / 'docker'
        docker.write_text(f'#!{sys.executable}\n' + '''import json, os, sys
with open(os.environ['DOCKER_CALLS'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1] == os.environ.get('DOCKER_FAIL_COMMAND'):
    sys.exit(43)
if sys.argv[1:3] == ['image', 'inspect']:
    print('sha256:fixture')
elif sys.argv[1] == 'run':
    sys.exit(int(os.environ.get('DOCKER_RESULT', '0')))
''')
        docker.chmod(0o755)
        self.calls = self.root / 'calls.jsonl'
        self.environment = dict(dict(os.environ, **METADATA), GITHUB_SHA=self.sha,
                                GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1',
                                GITHUB_SERVER_URL='https://github.com',
                                PATH=str(binary) + os.pathsep + os.environ['PATH'],
                                DOCKER_CALLS=str(self.calls))

    def launch(self, lane='test', **changes):
        return subprocess.run(['bash', 'scripts/ci-github.sh', lane], cwd=self.root,
                              env=dict(self.environment, **changes), capture_output=True, text=True, timeout=10)

    def arguments(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_container_receives_only_public_metadata_and_scoped_mounts(self):
        result = self.launch(GITHUB_TOKEN='fixture-secret', SSH_AUTH_SOCK='/fixture/ssh-agent',
                             DEPLOY_PASSWORD='fixture-secret')
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(args for args in self.arguments() if args[0] == 'run')
        forwarded = [args[i + 1].split('=', 1)[0] for i, arg in enumerate(args) if arg == '--env']
        for secret in ('GITHUB_TOKEN', 'SSH_AUTH_SOCK', 'DEPLOY_PASSWORD'):
            self.assertNotIn(secret, forwarded)
        self.assertIn('GITHUB_SHA', forwarded)
        self.assertEqual(self.arguments()[0], ['pull', 'golang:1.25.11-bookworm@sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38'])
        self.assertFalse(any(call[0] == 'build' for call in self.arguments()))
        self.assertIn('--pull=never', args)
        self.assertNotIn('--cap-add', args)
        self.assertNotIn('--privileged', args)
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertEqual(mounts[0], f'type=bind,source={self.root},target=/workspace')
        self.assertTrue(all(mount.startswith('type=volume,source=debuglet-ci-go-') for mount in mounts[1:]))
        self.assertNotIn('fixture-secret', json.dumps(args))
        self.assertEqual(self.arguments()[-1][0:2], ['rm', '--force'])

    def test_kernel_adds_only_required_capabilities(self):
        result = self.launch('kernel')
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(args for args in self.arguments() if args[0] == 'run')
        self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == '--cap-add'],
                         ['BPF', 'NET_ADMIN', 'NET_RAW', 'PERFMON', 'SYS_RESOURCE'])
        self.assertNotIn('--privileged', args)
        build = next(call for call in self.arguments() if call[0] == 'build')
        self.assertIn('deploy/ci/Dockerfile', build)
        self.assertIn('BASE_DIGEST=sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38', build)
        self.assertIn('DEBIAN_SNAPSHOT=20260623T000000Z', build)

    def test_rejects_untrusted_metadata_before_launch(self):
        for changes in ({'GITHUB_SHA': SHA}, {'GITHUB_EVENT_NAME': 'pull_request'},
                        {'GITHUB_EVENT_NAME': 'pull_request_target'}, {'GITHUB_REPOSITORY': 'fork/debuglet'},
                        {'GITHUB_REF': 'refs/heads/unreviewed'}, {'RUNNER_ENVIRONMENT': 'self-hosted'},
                        {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/12/merge',
                         'GITHUB_BASE_REF': 'other'},
                        {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/not-a-number/merge',
                         'GITHUB_BASE_REF': 'main'}):
            with self.subTest(changes=changes):
                result = self.launch(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())

    def test_pull_request_merge_ref_runs_without_protected_branch(self):
        result = self.launch('kernel', GITHUB_EVENT_NAME='pull_request',
                             GITHUB_REF='refs/pull/12/merge', GITHUB_BASE_REF='main',
                             GITHUB_REF_PROTECTED='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(call for call in self.arguments() if call[0] == 'run')
        self.assertIn('GITHUB_BASE_REF', args)

    def test_image_preparation_failure_stops_before_container(self):
        for command in ('pull', 'build'):
            with self.subTest(command=command):
                self.calls.unlink(missing_ok=True)
                result = self.launch('kernel', DOCKER_FAIL_COMMAND=command)
                self.assertEqual(result.returncode, 43, result.stderr)
                self.assertFalse(any(call[0] == 'run' for call in self.arguments()))

    def test_local_reproduction_uses_prepared_images(self):
        result = self.launch(GITHUB_ACTIONS='')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[0] in ('pull', 'build') for call in self.arguments()))

    def test_failure_propagates_and_removes_container(self):
        result = self.launch(DOCKER_RESULT='42')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(self.arguments()[-1][0:2], ['rm', '--force'])


if __name__ == '__main__':
    unittest.main()
