"""Owned archive fixtures; these do not establish GitHub publication or access."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import zipfile

from tools import release
from tools.test_release import job_fixture, run_fixture
from tools import test_release_inventory as inventory_tests
from tools.test_release_inventory import VERSION, SOURCE, BUILDER

TOOL = Path(__file__).with_name('release.py')
REPOSITORY = 'example/release-archive'
REVISION = 'c' * 40
FAKE_GH = r'''#!PYTHON
import base64, hashlib, json, os, shutil, sys
from pathlib import Path
root = Path(os.environ['TEST_ARCHIVE'])
state = json.loads((root / 'state.json').read_text())
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\n')
def save():
    (root / 'state.json').write_text(json.dumps(state))
def fail():
    print('https://fixture-secret@example.invalid/access denied', file=sys.stderr)
    sys.exit(1)
if state.get('deny'): fail()
if args[:2] == ['release', 'upload']:
    if '--clobber' in args: fail()
    row = next(r for r in state['releases'] if r['tag_name'] == args[2])
    paths = args[args.index('--repo') + 2:]
    for name in paths:
        if any(a['name'] == name for a in row['assets']): fail()
        ident = state['next_id']; state['next_id'] += 1
        data = Path(name).read_bytes()
        (root / str(ident)).write_bytes(data)
        row['assets'].append({'id': ident, 'name': name, 'size': len(data), 'state': 'uploaded',
                              'digest': 'sha256:' + hashlib.sha256(data).hexdigest()})
        save()
        if state.get('interrupt_upload'): fail()
    sys.exit(0)
if args[0] != 'api': fail()
endpoint = next(a for a in args if a.startswith('repos/'))
method = args[args.index('--method') + 1] if '--method' in args else 'GET'
body = json.load(sys.stdin) if '--input' in args else None
suffix = endpoint.split('/', 3)[3] if endpoint.count('/') >= 3 else ''
if '/actions/artifacts/' in endpoint:
    ident = endpoint.split('/')[-2]
    sys.stdout.buffer.write((root / ('artifact-' + ident)).read_bytes()); sys.exit(0)
if suffix == '':
    result = {'full_name': 'example/release-archive', 'private': state['private'], 'default_branch': 'main'}
elif suffix == 'immutable-releases': result = {'enabled': state['immutable']}
elif suffix.startswith('git/ref/tags/'):
    if suffix.removeprefix('git/ref/tags/') not in state['tags']: fail()
    result = {'ref': 'refs/tags/' + suffix.removeprefix('git/ref/tags/')}
elif suffix.startswith('branches/'):
    result = {'protected': state['protected'], 'commit': {'sha': state['revision']}}
elif suffix.startswith('contents/retention.json?ref='):
    if state['policy'] is None: fail()
    result = {'encoding': 'base64', 'type': 'file', 'content': base64.b64encode(json.dumps(state['policy']).encode()).decode()}
elif suffix.startswith('releases/assets/'):
    data = (root / suffix.split('/')[-1]).read_bytes()
    if state.get('corrupt_download'): data += b'changed'
    sys.stdout.buffer.write(data); sys.exit(0)
elif suffix == 'releases' and method == 'POST':
    result = dict(body, id=state['next_id'], immutable=False, assets=[])
    state['next_id'] += 1; state['releases'].append(result); save()
elif suffix.startswith('releases/') and method == 'PATCH':
    result = next(r for r in state['releases'] if r['id'] == int(suffix.split('/')[-1]))
    result.update(body, immutable=state['immutable'])
    if state.get('change_at_publish'): result['assets'][0]['digest'] = 'sha256:' + '0'*64
    if state.get('retag_at_publish'): result['tag_name'] = 'v9.9.9'
    save()
elif suffix.startswith('releases?'): result = [state['releases']]
else: fail()
print(json.dumps(result))
'''


class RetentionTests(unittest.TestCase):
    def setUp(self):
        # Reuse the small package/inventory fixture; no second package model.
        self.inventory = inventory_tests.InventoryTests('test_complete_inventory_binds_exact_bytes_without_rebuilding')
        self.inventory.setUp()
        self.addCleanup(self.inventory.doCleanups)
        self.directory = self.inventory.root
        self.archive = self.directory.parent / (self.directory.name + '-archive')
        self.archive.mkdir()
        self.addCleanup(shutil.rmtree, self.archive)
        self.bin = self.archive / 'bin'; self.bin.mkdir()
        gh = self.bin / 'gh'
        gh.write_text(FAKE_GH.replace('PYTHON', sys.executable, 1)); gh.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'], TEST_ARCHIVE=str(self.archive))
        self.state = {'private': True, 'immutable': True, 'protected': True, 'revision': REVISION,
                      'tags': [VERSION], 'releases': [], 'next_id': 1000, 'policy': None}
        self.save()
        run = run_fixture(); run['run_attempt'] = 1
        jobs = job_fixture()
        for job in jobs: job['run_attempt'] = 1
        self.gates = release.check_gates(run, jobs, VERSION, SOURCE)
        (self.directory / 'gates.json').write_text(json.dumps(self.gates))
        self.inventory.generate()
        self.artifacts = []
        for number, lane in enumerate(sorted(release.EVIDENCE_LANES), 1):
            path = self.archive / ('artifact-' + str(number))
            with zipfile.ZipFile(path, 'w') as zipped:
                zipped.writestr('result.json', json.dumps({'lane': lane, 'source': SOURCE}))
            data = path.read_bytes()
            self.artifacts.append({'id': number, 'name': f'evidence-{lane}-{SOURCE}-1', 'expired': False,
                                   'workflow_run': {'id': 123, 'head_sha': SOURCE}, 'size_in_bytes': len(data),
                                   'digest': 'sha256:' + hashlib.sha256(data).hexdigest()})
        self.artifacts_path = self.archive / 'artifacts.json'
        self.artifacts_path.write_text(json.dumps(self.artifacts))
        self.key = self.archive / 'key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True, capture_output=True, timeout=10)
        self.trust = self.archive / 'allowed_signers'
        self.trust.write_text('fixture ' + self.key.with_suffix('.pub').read_text())

    def save(self):
        (self.archive / 'state.json').write_text(json.dumps(self.state))

    def read_state(self):
        self.state = json.loads((self.archive / 'state.json').read_text())
        return self.state

    def command(self, command, *args, directory=True, signing=False):
        argv = [sys.executable, str(TOOL), command, *args]
        if directory: argv += ['--directory', str(self.directory)]
        if signing: argv += ['--trust', str(self.trust), '--signer', 'fixture']
        return subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=45)

    def signed(self, version=VERSION):
        result = self.command('evidence', '--artifacts', str(self.artifacts_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command('prepare', '--version', version, '--source', SOURCE, '--builder', BUILDER)
        self.assertEqual(result.returncode, 0, result.stderr)
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', release.NAMESPACE,
                        str(self.directory / release.SUBJECT)], check=True, capture_output=True, timeout=10)
        (self.archive / 'calls.jsonl').unlink(missing_ok=True)

    def promote(self, version=VERSION):
        return self.command('promote', '--repository', REPOSITORY, '--version', version, signing=True)

    def calls(self):
        path = self.archive / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_evidence_is_signed_and_survives_source_artifact_removal(self):
        self.signed()
        for path in self.archive.glob('artifact-*'): path.unlink()
        result = self.command('audit', '--version', VERSION, signing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['published'])
        evidence = next(self.directory.glob('evidence-*.zip'))
        evidence.unlink()
        result = self.command('audit', '--version', VERSION, signing=True)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_stale_duplicate_expired_and_mismatched_evidence_refuse_before_download(self):
        alternatives = [self.artifacts[:-1], self.artifacts + self.artifacts[:1]]
        for key, value in [('expired', True), ('workflow_run', {'id': 124, 'head_sha': SOURCE}),
                           ('workflow_run', {'id': 123, 'head_sha': 'b'*40}), ('name', 'wrong-attempt'),
                           ('digest', 'missing'), ('size_in_bytes', release.MAX_EVIDENCE_BYTES + 1)]:
            changed = copy.deepcopy(self.artifacts); changed[0][key] = value; alternatives.append(changed)
        for data in alternatives:
            self.artifacts_path.write_text(json.dumps(data))
            result = self.command('evidence', '--artifacts', str(self.artifacts_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [])
        result = self.command('prepare', '--version', VERSION, '--source', SOURCE, '--builder', BUILDER)
        self.assertNotEqual(result.returncode, 0)

    def test_artifact_bytes_must_match_before_index_is_written(self):
        path = self.archive / 'artifact-1'; path.write_bytes(b'changed')
        result = self.command('evidence', '--artifacts', str(self.artifacts_path))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / 'evidence.json').exists())

    def test_wrong_evidence_index_refuses_preparation(self):
        result = self.command('evidence', '--artifacts', str(self.artifacts_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        path = self.directory / 'evidence.json'
        value = json.loads(path.read_text()); value['run_attempt'] = 2; path.write_text(json.dumps(value))
        result = self.command('prepare', '--version', VERSION, '--source', SOURCE, '--builder', BUILDER)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / release.SUBJECT).exists())

    def test_private_draft_verified_then_published_without_touching_old_versions(self):
        self.signed()
        old = {'id': 40, 'tag_name': 'v0.1.0', 'draft': False, 'immutable': True, 'assets': []}
        self.state['releases'] = [old]; self.save()
        result = self.promote()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['published'])
        state = self.read_state()
        self.assertEqual(state['releases'][0], old)
        self.assertIsNone(state['policy'])
        calls = self.calls()
        publish = next(i for i, call in enumerate(calls) if 'PATCH' in call)
        download = [i for i, call in enumerate(calls) if any('/releases/assets/' in word for word in call)]
        self.assertTrue(download and max(download) < publish)
        self.assertFalse(any('DELETE' in call or '--clobber' in call for call in calls))
        count = len(calls)
        result = self.promote()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['already_present'])
        self.assertFalse(any('POST' in call or 'PATCH' in call or 'upload' in call for call in self.calls()[count:]))

    def test_existing_version_conflict_refuses_without_writes(self):
        self.signed()
        result = self.promote(); self.assertEqual(result.returncode, 0, result.stderr)
        self.read_state()
        asset = self.state['releases'][0]['assets'][0]
        changed = b'conflicting existing release'
        (self.archive / str(asset['id'])).write_bytes(changed)
        asset.update(size=len(changed), digest='sha256:' + hashlib.sha256(changed).hexdigest())
        self.save(); (self.archive / 'calls.jsonl').unlink()
        result = self.promote()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('POST' in call or 'PATCH' in call or 'upload' in call for call in self.calls()))

    def test_public_archive_unprotected_release_and_missing_tag_refuse_writes(self):
        self.signed()
        for key, value in [('private', False), ('immutable', False), ('tags', [])]:
            with self.subTest(key=key):
                original = self.state[key]; self.state[key] = value; self.save()
                result = self.promote()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.read_state()['releases'], [])
                self.state[key] = original
        self.assertFalse(any('POST' in call or 'PATCH' in call for call in self.calls()))

    def test_partial_upload_and_failed_download_never_publish_or_delete(self):
        self.signed()
        for failure in ('interrupt_upload', 'corrupt_download'):
            with self.subTest(failure=failure):
                self.state['releases'] = []; self.state[failure] = True; self.save()
                result = self.promote()
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.read_state()['releases'][0]['draft'])
                self.state[failure] = False; self.save()
                # Existing drafts require inspection; retry cannot silently mutate one.
                result = self.promote()
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('PATCH' in call or 'DELETE' in call for call in self.calls()))

    def test_publication_checks_final_immutable_asset_identity(self):
        self.signed()
        for change in ('change_at_publish', 'retag_at_publish'):
            self.state['releases'] = []; self.state[change] = True; self.save()
            result = self.promote()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('"verified": true', result.stdout)
            self.read_state(); self.state[change] = False

    def test_expected_source_and_builder_refuse_before_remote_calls(self):
        self.signed()
        for option, value in [('--source', 'b' * 40), ('--builder', BUILDER + '4')]:
            result = self.command('promote', '--repository', REPOSITORY, '--version', VERSION,
                                  option, value, signing=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [])

    def test_untrusted_local_bundle_cannot_cause_any_remote_write(self):
        self.signed(); (self.directory / 'evidence-test.zip').write_bytes(b'changed')
        result = self.promote()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_missing_current_and_rollback_assets_are_reported_privately(self):
        self.signed()
        result = self.promote(); self.assertEqual(result.returncode, 0, result.stderr)
        self.read_state()
        pin = {'version': VERSION, 'source_sha': SOURCE,
               'manifest_sha256': release.digest(self.directory / release.SUBJECT)['sha256']}
        self.state['policy'] = {'schema_version': 1, 'current': pin, 'rollback': dict(pin, version='v0.1.0')}
        self.save()
        args = ('--repository', REPOSITORY, '--policy-revision', REVISION)
        result = self.command('retention-audit', *args, directory=False, signing=True)
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertTrue(report['releases']['current']['verified'])
        self.assertFalse(report['releases']['rollback']['verified'])
        self.assertIn('digests', report['releases']['current'])
        self.state['releases'][0]['assets'] = [a for a in self.state['releases'][0]['assets'] if a['name'] != 'evidence-test.zip']
        self.save()
        result = self.command('retention-audit', *args, directory=False, signing=True)
        self.assertIn('missing release assets: evidence-test.zip', result.stdout)
        self.assertNotIn('fixture-secret', result.stdout + result.stderr)
        self.state['protected'] = False; self.save()
        result = self.command('retention-audit', *args, directory=False, signing=True)
        self.assertNotEqual(result.returncode, 0)

    def test_both_protected_versions_verify_and_policy_is_not_changed(self):
        self.signed()
        result = self.promote(); self.assertEqual(result.returncode, 0, result.stderr)
        self.read_state()
        current = {'version': VERSION, 'source_sha': SOURCE,
                   'manifest_sha256': release.digest(self.directory / release.SUBJECT)['sha256']}
        rollback_version = 'v1.2.2'
        other = inventory_tests.InventoryTests('test_complete_inventory_binds_exact_bytes_without_rebuilding')
        with mock.patch.object(inventory_tests, 'VERSION', rollback_version):
            other.setUp(); self.addCleanup(other.doCleanups)
            self.directory = other.root
            (self.directory / 'gates.json').write_text(json.dumps(dict(self.gates, version=rollback_version, ref='refs/tags/' + rollback_version)))
            other.generate()
        self.signed(rollback_version)
        self.state['tags'].append(rollback_version); self.save()
        result = self.promote(rollback_version); self.assertEqual(result.returncode, 0, result.stderr)
        self.read_state()
        rollback = {'version': rollback_version, 'source_sha': SOURCE,
                    'manifest_sha256': release.digest(self.directory / release.SUBJECT)['sha256']}
        policy = {'schema_version': 1, 'current': current, 'rollback': rollback}
        self.state['policy'] = policy; self.save()
        result = self.command('retention-audit', '--repository', REPOSITORY, '--policy-revision', REVISION,
                              directory=False, signing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['verified'])
        self.assertEqual(self.read_state()['policy'], policy)
        for revision in ('invalid', 'd' * 40):
            result = self.command('retention-audit', '--repository', REPOSITORY, '--policy-revision', revision,
                                  directory=False, signing=True)
            self.assertNotEqual(result.returncode, 0)
        self.state['policy']['rollback'] = current; self.save()
        result = self.command('retention-audit', '--repository', REPOSITORY, '--policy-revision', REVISION,
                              directory=False, signing=True)
        self.assertNotEqual(result.returncode, 0)

    def test_authentication_failure_does_not_echo_credentials(self):
        self.signed(); self.state['deny'] = True; self.save()
        result = self.promote()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('fixture-secret', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
