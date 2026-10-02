#!/usr/bin/env python3
"""Prepare and verify immutable release subjects; signing uses OpenSSH."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import quote

REPOSITORY = 'netsec-ethz/debuglet'
WORKFLOW = '.github/workflows/ci.yml'
NAMESPACE = 'debuglet-release'
SUBJECT = 'release.json'
METADATA = {'build-inputs.json', 'sbom.cdx.json', 'provenance.json', 'gates.json', 'LICENSE', 'NOTICE'}
LANES = {'fmt', 'vet', 'generate', 'test', 'race', 'kernel', 'build', 'package',
         'demo', 'compatibility', 'local', 'secrets', 'offline', 'vulnerabilities', 'image-vulnerabilities', 'required'}
VERSION = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?\Z')
EVIDENCE_LANES = LANES - {'required'}
EVIDENCE_FILES = {'evidence.json'} | {f'evidence-{lane}.zip' for lane in EVIDENCE_LANES}
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
SOURCE = re.compile(r'[0-9a-f]{40}\Z')
BUILDER = re.compile(r'https://github\.com/netsec-ethz/debuglet/actions/runs/[1-9][0-9]*\Z')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def read_json(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('missing, linked or oversized JSON file: ' + path.name)
    return json.loads(path.read_text(), object_pairs_hook=unique)


def write_json(path, data):
    with path.open('x') as output:
        json.dump(data, output, indent=2, sort_keys=True)
        output.write('\n')


def identity(version, source, builder):
    if not VERSION.fullmatch(version) or not SOURCE.fullmatch(source) or not BUILDER.fullmatch(builder):
        raise ValueError('invalid release version, source or builder identity')


def digest(path):
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('release subjects must be regular files: ' + path.name)
    with path.open('rb') as data:
        return {'sha256': hashlib.file_digest(data, 'sha256').hexdigest(), 'bytes': path.stat().st_size}


def package_names(version):
    names = {'compatibility.json', 'SHA256SUMS-compatibility'}
    for component in ('', 'cli', 'executor', 'dispatcher'):
        suffix = '-' + component if component else ''
        names.update({f'debuglet{suffix}-{version}-linux-amd64.tar.gz',
                      f'install{suffix}.sh', f'SHA256SUMS{suffix}'})
    return names


def stage(packages, directory, version):
    if not VERSION.fullmatch(version):
        raise ValueError('invalid release version')
    expected = package_names(version)
    found = {}
    for path in packages.rglob('*'):
        if path.is_symlink():
            raise ValueError('linked package input')
        if path.is_file():
            if path.name not in expected or path.name in found:
                raise ValueError('unexpected or duplicate package input: ' + path.name)
            found[path.name] = path
    if set(found) != expected:
        raise ValueError('package artifact is incomplete')
    directory.mkdir(mode=0o700)
    for name, source in found.items():
        shutil.copyfile(source, directory / name)


def check_environment(environment):
    reviewers = [rule for rule in environment.get('protection_rules', [])
                 if rule.get('type') == 'required_reviewers']
    if (environment.get('name') != 'release-signing' or len(reviewers) != 1 or
        reviewers[0].get('prevent_self_review') is not True or
        not reviewers[0].get('reviewers')):
        raise ValueError('release-signing requires independent environment reviewers before signing')


def check_gates(run, jobs, version, source):
    builder = f'https://github.com/{REPOSITORY}/actions/runs/{run.get("id")}'
    identity(version, source, builder)
    if (run.get('repository', {}).get('full_name') != REPOSITORY or
        run.get('head_repository', {}).get('full_name') != REPOSITORY or
        run.get('path') != WORKFLOW or run.get('head_sha') != source or
        run.get('head_branch') != version or run.get('event') not in ('push', 'workflow_dispatch') or
        run.get('status') != 'completed' or run.get('conclusion') != 'success' or
        run.get('html_url') != builder or run.get('pull_requests') or
        type(run.get('run_attempt')) is not int or run['run_attempt'] < 1):
        raise ValueError('CI run is not an eligible exact-source release run')
    selected = {}
    for job in jobs:
        name = job.get('name')
        if name in selected:
            raise ValueError('duplicate CI lane: ' + str(name))
        if (name not in LANES or job.get('run_id') != run['id'] or
            job.get('run_attempt') != run['run_attempt'] or
            job.get('status') != 'completed' or job.get('conclusion') != 'success' or
            type(job.get('id')) is not int):
            raise ValueError('CI lane is missing, skipped, failed or from another attempt')
        selected[name] = {'id': job['id'], 'conclusion': 'success'}
    if set(selected) != LANES:
        raise ValueError('required release CI lanes are incomplete')
    return {'schema_version': 1, 'repository': REPOSITORY, 'source_sha': source,
            'version': version, 'builder': builder, 'run_id': run['id'],
            'run_attempt': run['run_attempt'], 'workflow': WORKFLOW,
            'event': run['event'], 'ref': 'refs/tags/' + version,
            'protected': True, 'jobs': selected}


def validate_gates(gates, version, source, builder):
    if (gates.get('schema_version') != 1 or gates.get('repository') != REPOSITORY or
        gates.get('version') != version or gates.get('source_sha') != source or
        gates.get('builder') != builder or gates.get('workflow') != WORKFLOW or
        gates.get('ref') != 'refs/tags/' + version or gates.get('protected') is not True or
        gates.get('event') not in ('push', 'workflow_dispatch') or
        type(gates.get('run_attempt')) is not int or gates['run_attempt'] < 1 or
        builder != f'https://github.com/{REPOSITORY}/actions/runs/{gates.get("run_id")}' or
        set(gates.get('jobs', {})) != LANES or
        any(value.get('conclusion') != 'success' or type(value.get('id')) is not int
            for value in gates.get('jobs', {}).values())):
        raise ValueError('release gates do not match the expected source and builder')


def subject(directory, version, source, builder):
    identity(version, source, builder)
    expected = package_names(version) | METADATA | EVIDENCE_FILES
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError('release subjects require the exact packages and complete metadata')
    validate_gates(read_json(directory / 'gates.json'), version, source, builder)
    verify_evidence(directory)
    from release_inventory import verify
    verify(directory, version, source, builder)
    return {'schema_version': 1, 'version': version, 'source_sha': source, 'builder': builder,
            'files': {name: digest(directory / name) for name in sorted(expected)}}


def load_subject(directory, version, source=None, builder=None):
    result = read_json(directory / SUBJECT)
    if set(result) != {'schema_version', 'version', 'source_sha', 'builder', 'files'} or result['schema_version'] != 1:
        raise ValueError('unsupported release subject document')
    identity(result['version'], result['source_sha'], result['builder'])
    if result['version'] != version or (source and result['source_sha'] != source) or (builder and result['builder'] != builder):
        raise ValueError('release source, version or builder does not match')
    if set(result['files']) != package_names(version) | METADATA | EVIDENCE_FILES:
        raise ValueError('release subject set is incomplete')
    if {path.name for path in directory.iterdir()} - set(result['files']) - {SUBJECT, SUBJECT + '.sig'}:
        raise ValueError('release directory contains unsigned extra files')
    for name, expected in result['files'].items():
        if (not isinstance(expected, dict) or set(expected) != {'sha256', 'bytes'} or
            not isinstance(expected['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', expected['sha256']) or
            type(expected['bytes']) is not int or expected['bytes'] < 0 or digest(directory / name) != expected):
            raise ValueError('release subject checksum mismatch: ' + name)
    return result


def verify_release(directory, trust, signer, version, source=None, builder=None):
    # Verify with independently supplied trust before interpreting signed metadata.
    command = ['ssh-keygen', '-Y', 'verify', '-f', str(trust), '-I', signer,
               '-n', NAMESPACE, '-s', str(directory / (SUBJECT + '.sig'))]
    for name, maximum in ((SUBJECT, 1024 * 1024), (SUBJECT + '.sig', 65536)):
        path = directory / name
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > maximum:
            raise ValueError('release signature inputs must be bounded regular files')
    with (directory / SUBJECT).open('rb') as data:
        result = subprocess.run(command, stdin=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
    if result.returncode:
        raise ValueError('release signature is missing, invalid or from an untrusted signer')
    release = load_subject(directory, version, source, builder)
    validate_gates(read_json(directory / 'gates.json'), version, release['source_sha'], release['builder'])
    verify_evidence(directory)
    from release_inventory import verify
    verify(directory, version, release['source_sha'], release['builder'])
    return release


def github(arguments, *, body=None, output=None, cwd=None):
    # Never echo gh stderr: authentication failures can include credential URLs.
    result = subprocess.run(['gh', *arguments], input=None if body is None else json.dumps(body).encode(),
                            stdout=output or subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, cwd=cwd)
    if result.returncode:
        raise ValueError('GitHub operation failed; check channel access and gh authentication')
    return result.stdout


def github_json(endpoint, *, body=None, method='GET', paginate=False):
    arguments = ['api', '--hostname', 'github.com', '--method', method, endpoint]
    if body is not None:
        arguments += ['--input', '-']
    if paginate:
        arguments += ['--paginate', '--slurp']
    value = json.loads(github(arguments, body=body), object_pairs_hook=unique)
    return [item for page in value for item in page] if paginate else value


def collect_evidence(directory, artifacts):
    gates = read_json(directory / 'gates.json')
    validate_gates(gates, gates['version'], gates['source_sha'], gates['builder'])
    selected = {}
    for lane in sorted(EVIDENCE_LANES):
        name = f"evidence-{lane}-{gates['source_sha']}-{gates['run_attempt']}"
        matches = [a for a in artifacts if a.get('name') == name]
        if len(matches) != 1:
            raise ValueError('missing or duplicate acceptance artifact: ' + lane)
        artifact = matches[0]
        run = artifact.get('workflow_run', {})
        if (artifact.get('expired') is not False or type(artifact.get('id')) is not int or artifact['id'] < 1 or
            run.get('id') != gates['run_id'] or run.get('head_sha') != gates['source_sha'] or
            type(artifact.get('size_in_bytes')) is not int or not 0 < artifact['size_in_bytes'] <= MAX_EVIDENCE_BYTES or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest') or '')):
            raise ValueError('expired or mismatched acceptance artifact: ' + lane)
        selected[lane] = {'artifact_id': artifact['id'], 'job_id': gates['jobs'][lane]['id'],
                          'name': name, 'sha256': artifact['digest'][7:], 'bytes': artifact['size_in_bytes']}
    # Refuse incomplete metadata before any download. ZIP bytes stay opaque.
    for lane, artifact in selected.items():
        path = directory / f'evidence-{lane}.zip'
        with path.open('xb') as output:
            github(['api', '--hostname', 'github.com',
                    f"repos/{REPOSITORY}/actions/artifacts/{artifact['artifact_id']}/zip"], output=output)
        if digest(path) != {k: artifact[k] for k in ('sha256', 'bytes')}:
            raise ValueError('acceptance artifact checksum mismatch: ' + lane)
    index = {key: gates[key] for key in ('repository', 'version', 'source_sha', 'builder', 'run_id', 'run_attempt')}
    write_json(directory / 'evidence.json', dict(index, schema_version=1, artifacts=selected))


def verify_evidence(directory):
    gates = read_json(directory / 'gates.json')
    index = read_json(directory / 'evidence.json')
    if (index.get('schema_version') != 1 or
        any(index.get(key) != gates[key] for key in ('repository', 'version', 'source_sha', 'builder', 'run_id', 'run_attempt')) or
        set(index.get('artifacts', {})) != EVIDENCE_LANES):
        raise ValueError('acceptance evidence is incomplete or from another invocation')
    ids = set()
    for lane, artifact in index['artifacts'].items():
        if (set(artifact) != {'artifact_id', 'job_id', 'name', 'sha256', 'bytes'} or
            type(artifact['artifact_id']) is not int or artifact['artifact_id'] < 1 or artifact['artifact_id'] in ids or
            artifact['job_id'] != gates['jobs'][lane]['id'] or
            artifact['name'] != f"evidence-{lane}-{gates['source_sha']}-{gates['run_attempt']}" or
            type(artifact['bytes']) is not int or not 0 < artifact['bytes'] <= MAX_EVIDENCE_BYTES or
            digest(directory / f'evidence-{lane}.zip') != {k: artifact[k] for k in ('sha256', 'bytes')}):
            raise ValueError('invalid acceptance evidence: ' + lane)
        ids.add(artifact['artifact_id'])


def private_archive(repository):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
        any(part in ('.', '..') for part in repository.split('/'))):
        raise ValueError('archive must be an explicit GitHub OWNER/REPOSITORY')
    metadata = github_json('repos/' + repository)
    if metadata.get('full_name', '').lower() != repository.lower() or metadata.get('private') is not True:
        raise ValueError('release archive must be private')
    return metadata


def archive_release(repository, version):
    releases = github_json(f'repos/{repository}/releases?per_page=100', paginate=True)
    selected = [r for r in releases if r.get('tag_name') == version]
    if len(selected) > 1:
        raise ValueError('duplicate archive release version')
    return selected[0] if selected else None


def download_release(repository, record, directory, version):
    expected = package_names(version) | METADATA | EVIDENCE_FILES | {SUBJECT, SUBJECT + '.sig'}
    assets = record.get('assets', [])
    names = [a.get('name') for a in assets]
    missing = sorted(expected - set(names))
    if missing:
        raise ValueError('missing release assets: ' + ', '.join(missing))
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError('duplicate or unsigned extra release assets')
    for asset in assets:
        if (asset.get('state') != 'uploaded' or type(asset.get('id')) is not int or asset['id'] < 1 or
            type(asset.get('size')) is not int or not 0 < asset['size'] <= 2 * 1024**3 or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or '')):
            raise ValueError('invalid release asset metadata: ' + asset['name'])
        path = directory / asset['name']
        with path.open('xb') as output:
            github(['api', '--hostname', 'github.com', '-H', 'Accept: application/octet-stream',
                    f"repos/{repository}/releases/assets/{asset['id']}"], output=output)
        if digest(path) != {'bytes': asset['size'], 'sha256': asset['digest'][7:]}:
            raise ValueError('downloaded release digest mismatch: ' + asset['name'])


def promote(repository, directory, version, trust, signer, source=None, builder=None):
    release = verify_release(directory, trust, signer, version, source, builder)
    private_archive(repository)
    if github_json(f'repos/{repository}/immutable-releases').get('enabled') is not True:
        raise ValueError('immutable releases must be enabled before promotion')
    tag = github_json(f'repos/{repository}/git/ref/tags/{version}')
    if tag.get('ref') != 'refs/tags/' + version:
        raise ValueError('archive version tag must already exist')
    record = archive_release(repository, version)
    existing = record is not None
    if existing and (record.get('draft') is not False or record.get('immutable') is not True):
        raise ValueError('existing draft or mutable release requires operator inspection')
    if not existing:
        record = github_json(f'repos/{repository}/releases', method='POST', body={
            'tag_name': version, 'name': version, 'draft': True, 'make_latest': 'false',
            'body': 'Verified release archive. Supported versions are designated in retention.json.'})
        github(['release', 'upload', version, '--repo', 'github.com/' + repository,
                *sorted(path.name for path in directory.iterdir())], cwd=directory)
        record = archive_release(repository, version)
    if record is None or record.get('tag_name') != version or (not existing and record.get('draft') is not True):
        raise ValueError('archive release changed during promotion')
    with tempfile.TemporaryDirectory(prefix='debuglet-release-download-') as temporary:
        downloaded = Path(temporary)
        download_release(repository, record, downloaded, version)
        verify_release(downloaded, trust, signer, version, release['source_sha'], release['builder'])
        if any(digest(downloaded / p.name) != digest(p) for p in directory.iterdir()):
            raise ValueError('existing or uploaded bundle differs from the verified input')
    verified_id = record['id']
    verified_assets = {a['name']: (a['id'], a['size'], a['digest']) for a in record['assets']}
    if not existing:
        record = github_json(f"repos/{repository}/releases/{record['id']}", method='PATCH',
                             body={'draft': False, 'make_latest': 'false'})
    if (record.get('id') != verified_id or record.get('tag_name') != version or
        record.get('draft') is not False or record.get('immutable') is not True or
        {a['name']: (a['id'], a['size'], a['digest']) for a in record.get('assets', [])} != verified_assets):
        raise ValueError('published release immutability was not confirmed')
    return {'repository': repository, 'version': version, 'source_sha': release['source_sha'],
            'manifest_sha256': digest(directory / SUBJECT)['sha256'],
            'release_id': record['id'], 'published': True, 'verified': True, 'already_present': existing}


def retention_audit(repository, revision, trust, signer):
    metadata = private_archive(repository)
    if not SOURCE.fullmatch(revision):
        raise ValueError('policy revision must be a full commit SHA')
    branch_path = f"repos/{repository}/branches/{quote(metadata['default_branch'], safe='')}"
    branch = github_json(branch_path)
    if branch.get('protected') is not True or branch.get('commit', {}).get('sha') != revision:
        raise ValueError('policy must be the exact protected default-branch revision')
    contents = github_json(f'repos/{repository}/contents/retention.json?ref={revision}')
    if contents.get('encoding') != 'base64' or contents.get('type') != 'file':
        raise ValueError('retention policy is missing or not a regular file')
    policy = json.loads(base64.b64decode(contents['content']), object_pairs_hook=unique)
    if set(policy) != {'schema_version', 'current', 'rollback'} or policy['schema_version'] != 1:
        raise ValueError('unsupported retention policy')
    for entry in (policy['current'], policy['rollback']):
        if (set(entry) != {'version', 'source_sha', 'manifest_sha256'} or not VERSION.fullmatch(entry['version']) or
            not SOURCE.fullmatch(entry['source_sha']) or not re.fullmatch(r'[0-9a-f]{64}', entry['manifest_sha256'])):
            raise ValueError('invalid current or rollback release pin')
    if policy['current']['version'] == policy['rollback']['version']:
        raise ValueError('current and rollback releases must be distinct')
    report = {'repository': repository, 'private': True, 'policy_revision': revision, 'releases': {}, 'verified': True}
    for role, entry in ((key, policy[key]) for key in ('current', 'rollback')):
        result = dict(entry, verified=False, problems=[])
        try:
            record = archive_release(repository, entry['version'])
            if record is None or record.get('draft') is not False or record.get('immutable') is not True:
                raise ValueError('protected release is missing, unpublished or mutable')
            result['release_id'] = record['id']
            with tempfile.TemporaryDirectory(prefix='debuglet-retention-audit-') as temporary:
                directory = Path(temporary)
                download_release(repository, record, directory, entry['version'])
                if digest(directory / SUBJECT)['sha256'] != entry['manifest_sha256']:
                    raise ValueError('release manifest differs from protected policy')
                signed = verify_release(directory, trust, signer, entry['version'], entry['source_sha'])
                result.update(verified=True, builder=signed['builder'],
                              digests={p.name: digest(p) for p in sorted(directory.iterdir())})
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result['problems'].append(str(error))
            report['verified'] = False
        report['releases'][role] = result
    if github_json(branch_path).get('commit', {}).get('sha') != revision:
        raise ValueError('retention policy changed during audit')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('stage')
    p.add_argument('--packages', type=Path, required=True)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--version', required=True)
    p = commands.add_parser('gates')
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--jobs', type=Path, required=True)
    p.add_argument('--environment', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--out', type=Path, required=True)
    p = commands.add_parser('evidence')
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p = commands.add_parser('retention-audit')
    p.add_argument('--repository', required=True)
    p.add_argument('--policy-revision', required=True)
    p.add_argument('--trust', type=Path, required=True)
    p.add_argument('--signer', required=True)
    for action in ('prepare', 'verify', 'audit', 'promote'):
        p = commands.add_parser(action)
        p.add_argument('--directory', type=Path, required=True)
        p.add_argument('--version', required=True)
        p.add_argument('--source', required=action == 'prepare')
        p.add_argument('--builder', required=action == 'prepare')
        if action == 'promote':
            p.add_argument('--repository', required=True)
        if action != 'prepare':
            p.add_argument('--trust', type=Path, required=True)
            p.add_argument('--signer', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'stage':
            stage(args.packages, args.directory, args.version)
        elif args.command == 'gates':
            check_environment(read_json(args.environment))
            write_json(args.out, check_gates(read_json(args.run), read_json(args.jobs), args.version, args.source))
        elif args.command == 'evidence':
            collect_evidence(args.directory, read_json(args.artifacts))
        elif args.command == 'promote':
            print(json.dumps(promote(args.repository, args.directory, args.version, args.trust, args.signer, args.source, args.builder), sort_keys=True))
        elif args.command == 'retention-audit':
            report = retention_audit(args.repository, args.policy_revision, args.trust, args.signer)
            print(json.dumps(report, sort_keys=True))
            if not report['verified']:
                parser.exit(1)
        elif args.command == 'prepare':
            write_json(args.directory / SUBJECT, subject(args.directory, args.version, args.source, args.builder))
        else:
            release = verify_release(args.directory, args.trust, args.signer, args.version, args.source, args.builder)
            print(json.dumps({'version': release['version'], 'source_sha': release['source_sha'],
                              'builder': release['builder'], 'signer': args.signer,
                              'files': len(release['files']), 'verified': True,
                              'published': False}, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f'release: {error}\n')


if __name__ == '__main__':
    main()
