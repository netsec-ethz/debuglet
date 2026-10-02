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

    def test_only_protected_version_tag_push_metadata_passes(self):
        valid = dict(METADATA, GITHUB_REF='refs/tags/v1.2.3-rc.1', GITHUB_REF_PROTECTED='true')
        self.assertTrue(all(item['status'] == 'pass' for item in ISOLATION.github_metadata_checks(valid, SHA)))
        for changes in ({'GITHUB_REF_PROTECTED': 'false'}, {'GITHUB_REF_PROTECTED': ''},
                        {'GITHUB_REF': 'refs/tags/v01.2.3'}, {'GITHUB_REF': 'refs/tags/v1.2.3-'},
                        {'GITHUB_REF': 'refs/tags/v1.2.3-' + 'a' * 123},
                        {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_BASE_REF': 'main'},
                        {'GITHUB_EVENT_NAME': 'workflow_dispatch'}, {'GITHUB_SHA': 'b' * 40}):
            with self.subTest(changes=changes):
                results = ISOLATION.github_metadata_checks(dict(valid, **changes), SHA)
                self.assertTrue(any(item['status'] == 'fail' for item in results), results)


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='debuglet-ci-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for path in ('scripts/ci-github.sh', 'deploy/ci/images.env'):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        # Record the host hook beside the fake Docker calls. These launcher
        # fixtures verify ordering and status propagation, not real cgroups.
        (self.root / 'scripts/ci-shared-workers.sh').write_text('''#!/usr/bin/env bash
printf '["shared-workers"]\\n' >> "$DOCKER_CALLS"
exit "${SHARED_WORKER_RESULT:-0}"
''')
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

    def test_protected_lightweight_and_annotated_tags_reach_packager(self):
        for tag, annotated in (('v1.2.3', False), ('v1.2.4-rc.1', True)):
            with self.subTest(tag=tag):
                self.calls.unlink(missing_ok=True)
                args = ['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'tag']
                args += ['-a', '-m', 'Fixture tag'] if annotated else []
                subprocess.run(args + [tag], cwd=self.root, check=True)
                result = self.launch('package', GITHUB_REF='refs/tags/' + tag, GITHUB_REF_PROTECTED='true')
                self.assertEqual(result.returncode, 0, result.stderr)
                run = next(call for call in self.arguments() if call[0] == 'run')
                self.assertIn('CI_COMMIT_TAG=' + tag, run)
                self.assertIn('GITHUB_REF_PROTECTED', run)

    def test_invalid_tag_authority_stops_before_docker(self):
        subprocess.run(['git', 'tag', 'v1.2.3'], cwd=self.root, check=True)
        valid = {'GITHUB_REF': 'refs/tags/v1.2.3', 'GITHUB_REF_PROTECTED': 'true'}
        for changes in ({'GITHUB_REF_PROTECTED': 'false'}, {'GITHUB_REF_PROTECTED': ''},
                        {'GITHUB_REF': 'refs/tags/v01.2.3'}, {'GITHUB_REF': 'refs/tags/v1.2.3-'},
                        {'GITHUB_REF': 'refs/tags/v1.2.3-' + 'a' * 123},
                        {'GITHUB_REF': 'refs/tags/v9.9.9'}, {'GITHUB_SHA': SHA},
                        {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_BASE_REF': 'main'},
                        {'GITHUB_EVENT_NAME': 'workflow_dispatch'}):
            with self.subTest(changes=changes):
                result = self.launch('package', **dict(valid, **changes))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--allow-empty', '-qm', 'Next fixture revision'], cwd=self.root, check=True)
        current = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        result = self.launch('package', **dict(valid, GITHUB_SHA=current))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists(), 'tag pointing at a different commit reached Docker')

    def test_container_receives_only_public_metadata_and_scoped_mounts(self):
        result = self.launch(GITHUB_TOKEN='fixture-secret', SSH_AUTH_SOCK='/fixture/ssh-agent',
                             DEPLOY_PASSWORD='fixture-secret')
        self.assertEqual(result.returncode, 0, result.stderr)
        args = next(args for args in self.arguments() if args[0] == 'run')
        forwarded = [args[i + 1].split('=', 1)[0] for i, arg in enumerate(args) if arg == '--env']
        for secret in ('GITHUB_TOKEN', 'SSH_AUTH_SOCK', 'DEPLOY_PASSWORD'):
            self.assertNotIn(secret, forwarded)
        self.assertIn('GITHUB_SHA', forwarded)
        self.assertIn('CI_COMMIT_TAG=', args)
        self.assertEqual(self.arguments()[0], ['pull', 'golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d'])
        self.assertFalse(any(call[0] == 'build' for call in self.arguments()))
        self.assertIn('--pull=never', args)
        self.assertNotIn('--cap-add', args)
        self.assertNotIn('--privileged', args)
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertEqual(mounts[0], f'type=bind,source={self.root},target=/workspace')
        self.assertTrue(all(mount.startswith('type=volume,source=debuglet-ci-go-') for mount in mounts[1:]))
        self.assertNotIn('fixture-secret', json.dumps(args))
        self.assertNotIn(['shared-workers'], self.arguments())
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
        self.assertIn('BASE_DIGEST=sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d', build)
        self.assertIn('DEBIAN_SNAPSHOT=20260918T000000Z', build)
        calls = self.arguments()
        self.assertEqual(calls.count(['shared-workers']), 1)
        run_index = next(i for i, call in enumerate(calls) if call[0] == 'run')
        self.assertEqual(calls[run_index + 1], ['shared-workers'])
        self.assertEqual(calls[run_index + 2][0:2], ['rm', '--force'])

    def test_kernel_failure_does_not_run_shared_workers(self):
        result = self.launch('kernel', DOCKER_RESULT='42')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn(['shared-workers'], self.arguments())
        self.assertEqual(self.arguments()[-1][0:2], ['rm', '--force'])

    def test_shared_worker_failure_is_preserved_after_cleanup(self):
        result = self.launch('kernel', SHARED_WORKER_RESULT='44')
        self.assertEqual(result.returncode, 44, result.stderr)
        self.assertEqual(self.arguments().count(['shared-workers']), 1)
        self.assertEqual(self.arguments()[-1][0:2], ['rm', '--force'])

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

    def test_scheduled_fixtures_run_in_a_bounded_network_namespace(self):
        for lane in ('faults', 'soak'):
            with self.subTest(lane=lane):
                self.calls.unlink(missing_ok=True)
                result = self.launch(lane, GITHUB_EVENT_NAME='schedule')
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [call for call in self.arguments() if call[0] == 'run']
                self.assertEqual(len(runs), 2)
                self.assertEqual(runs[0][-3:], ['go', 'mod', 'download'])
                args = runs[1]
                for option, value in (('--network', 'none'), ('--cpus', '4'),
                                      ('--memory', '4g'), ('--pids-limit', '512')):
                    self.assertEqual(args[args.index(option) + 1], value)
                self.assertNotIn('--cap-add', args)
                self.assertNotIn(['shared-workers'], self.arguments())
                marker = 'FAULT' if lane == 'faults' else 'SOAK'
                self.assertIn(f'DEBUGLET_{marker}_ISOLATED=1', args)
                cleanup = json.loads((self.root / f'.cache/ci/{lane}/cleanup.json').read_text())
                self.assertTrue(cleanup['removed'])

    def test_fixture_failure_is_preserved_after_container_cleanup(self):
        for lane in ('faults', 'soak'):
            with self.subTest(lane=lane):
                result = self.launch(lane, GITHUB_EVENT_NAME='schedule', DOCKER_RESULT='42')
                self.assertEqual(result.returncode, 42, result.stderr)
                cleanup = json.loads((self.root / f'.cache/ci/{lane}/cleanup.json').read_text())
                self.assertEqual(cleanup['test_status'], 42)
                self.assertTrue(cleanup['removed'])

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
