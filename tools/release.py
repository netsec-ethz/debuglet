#!/usr/bin/env python3
"""Prepare and verify immutable release subjects; signing uses OpenSSH."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPOSITORY = 'netsec-ethz/debuglet'
WORKFLOW = '.github/workflows/ci.yml'
NAMESPACE = 'debuglet-release'
SUBJECT = 'release.json'
METADATA = {'build-inputs.json', 'sbom.cdx.json', 'provenance.json', 'gates.json', 'LICENSE', 'NOTICE'}
LANES = {'fmt', 'vet', 'generate', 'test', 'race', 'kernel', 'build', 'package',
         'demo', 'compatibility', 'local', 'secrets', 'offline', 'vulnerabilities', 'required'}
VERSION = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?\Z')
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
    names = set()
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
    expected = package_names(version) | METADATA
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError('release subjects require the exact packages and complete metadata')
    validate_gates(read_json(directory / 'gates.json'), version, source, builder)
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
    if set(result['files']) != package_names(version) | METADATA:
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
    from release_inventory import verify
    verify(directory, version, release['source_sha'], release['builder'])
    return release


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
    for action in ('prepare', 'verify', 'audit'):
        p = commands.add_parser(action)
        p.add_argument('--directory', type=Path, required=True)
        p.add_argument('--version', required=True)
        p.add_argument('--source', required=action == 'prepare')
        p.add_argument('--builder', required=action == 'prepare')
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
