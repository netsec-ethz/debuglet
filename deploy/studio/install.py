#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Verify and install the separately signed, immutable Studio compiler bundle."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

NAMESPACE = 'debuglet-studio-release'
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
MANIFEST = 'studio-manifest.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def regular(path, limit):
    require(path.is_file() and not path.is_symlink(), 'expected regular file: ' + str(path))
    require(path.stat().st_size <= limit, 'file exceeds limit: ' + str(path))
    return path.read_bytes()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and str(path) == name and
            all(part not in ('.', '..') for part in path.parts) and
            not any(c in name for c in '\r\n\x00\\'), 'unsafe bundle path')
    return path


def verify_release(directory, source, trust=None, signer=None, expected_digest=None):
    require(re.fullmatch(r'[0-9a-f]{40}', source), 'expected an exact source commit')
    subject = regular(directory / 'studio-release.json', 65536)
    if expected_digest is None:
        require(trust is not None and signer, 'provide trusted signer or independently verified archive SHA256')
        regular(directory / 'studio-release.json.sig', 16384)
        regular(trust, 65536)
        subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(trust), '-I', signer,
                        '-n', NAMESPACE, '-s', str(directory / 'studio-release.json.sig')],
                       input=subject, check=True, timeout=30, stdout=subprocess.DEVNULL)
    else:
        require(trust is None and signer is None and re.fullmatch(r'[0-9a-f]{64}', expected_digest),
                'choose one explicit artifact trust path')
    release = json.loads(subject, object_pairs_hook=unique)
    require(set(release) == {'schema_version', 'source_sha', 'go_version', 'archive',
                             'archive_sha256', 'archive_bytes'}, 'unsupported Studio release record')
    require(release['schema_version'] == 1 and release['source_sha'] == source and
            release['go_version'] == 'go1.26.9', 'Studio release identity differs')
    require(release['archive'] == f'debuglet-studio-{source}-linux-amd64.tar.gz',
            'unexpected Studio archive name')
    archive = directory / release['archive']
    data = regular(archive, MAX_ARCHIVE)
    require(len(data) == release['archive_bytes'] and sha256(data) == release['archive_sha256'],
            'Studio archive checksum differs')
    require(expected_digest is None or sha256(data) == expected_digest, 'independently verified archive checksum differs')
    # Keep the exact authenticated bytes. Never reopen a potentially writable
    # staging path after verification or between archive inspection/extraction.
    return release, data


def open_archive(data):
    require(isinstance(data, bytes), 'archive must be an immutable verified snapshot')
    return tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')


def inspect_archive(archive, source):
    with open_archive(archive) as bundle:
        members = {}
        expanded = 0
        for member in bundle:
            name = member.name.rstrip('/') if member.isdir() else member.name
            safe_path(name)
            require(name not in members, 'duplicate archive member')
            require(member.isfile() or member.isdir(), 'bundle contains a non-regular member')
            require(member.mode in (0o644, 0o755) and member.uid == 0 and member.gid == 0,
                    'unexpected archive mode or owner')
            require(not member.isdir() or member.mode == 0o755, 'unexpected directory mode')
            expanded += member.size
            require(member.size <= 256 * 1024 * 1024 and expanded <= MAX_EXPANDED,
                    'expanded bundle exceeds limit')
            members[name] = member
        require(MANIFEST in members and members[MANIFEST].isfile() and
                members[MANIFEST].size <= 16 * 1024 * 1024, 'missing or oversized Studio manifest')
        manifest = json.loads(bundle.extractfile(members[MANIFEST]).read(), object_pairs_hook=unique)
        require(manifest.get('schema_version') == 1 and manifest.get('source_sha') == source and
                manifest.get('go_version') == 'go1.26.9', 'Studio manifest identity differs')
        files, directories = manifest['files'], manifest['directories']
        require(isinstance(files, dict) and isinstance(directories, list) and
                len(set(directories)) == len(directories), 'invalid Studio inventory')
        require(set(members) == set(files) | set(directories) | {MANIFEST}, 'Studio inventory differs')
        for name in directories:
            safe_path(name)
            require(members[name].isdir(), 'Studio directory differs')
        for name, expected in files.items():
            safe_path(name)
            require(set(expected) == {'sha256', 'bytes', 'mode'} and members[name].isfile(),
                    'invalid Studio file inventory')
            require(members[name].mode == expected['mode'] and members[name].size == expected['bytes'],
                    'Studio file metadata differs: ' + name)
            require(sha256(bundle.extractfile(members[name]).read()) == expected['sha256'],
                    'Studio file checksum differs: ' + name)
        require({'bin/dbl-studio', 'go/bin/go', 'sdk/go.mod'} <= set(files) and
                {'tmp', 'run/studio', 'proc', 'dev', 'modules'} <= set(directories),
                'Studio bundle lacks required runtime inputs')
    return manifest


def verify_tree(destination, manifest, archive):
    require(destination.is_dir() and not destination.is_symlink(), 'installation is not a real directory')
    require(destination.stat().st_uid == os.geteuid() and
            stat.S_IMODE(destination.stat().st_mode) == 0o755, 'installation root ownership or mode differs')
    expected_files = dict(manifest['files'])
    with open_archive(archive) as bundle:
        data = bundle.extractfile(MANIFEST).read()
    expected_files[MANIFEST] = {'sha256': sha256(data), 'bytes': len(data), 'mode': 0o644}
    found_files, found_dirs = set(), set()
    for path in destination.rglob('*'):
        name = path.relative_to(destination).as_posix()
        mode = path.lstat().st_mode
        require(path.lstat().st_uid == os.geteuid(), 'installed Studio ownership differs')
        require(not stat.S_ISLNK(mode), 'linked path in installed Studio bundle')
        if stat.S_ISDIR(mode):
            found_dirs.add(name)
            require(stat.S_IMODE(mode) == 0o755, 'installed directory mode differs')
        else:
            require(name in expected_files and stat.S_ISREG(mode), 'unexpected installed file')
            expected = expected_files[name]
            require(path.stat().st_size == expected['bytes'] and stat.S_IMODE(mode) == expected['mode'] and
                    sha256(path.read_bytes()) == expected['sha256'], 'installed Studio file differs: ' + name)
            found_files.add(name)
    require(found_files == set(expected_files) and found_dirs == set(manifest['directories']),
            'installed Studio inventory differs')


def install(archive, manifest, prefix):
    require(prefix.is_absolute(), 'Studio prefix must be absolute')
    for parent in [prefix, *prefix.parents]:
        require(not parent.is_symlink(), 'linked installation parent')
        require(not parent.exists() or parent.is_dir(), 'installation parent is not a directory')
        if parent.exists():
            info = parent.stat()
            require(info.st_uid in (0, os.geteuid()), 'installation parent has an untrusted owner')
            # Root-owned sticky ancestors such as /tmp protect this caller's
            # descendants from replacement. The installation prefix itself
            # must never be writable by another identity.
            sticky_ancestor = parent != prefix and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(not info.st_mode & 0o022 or sticky_ancestor, 'installation parent is writable by another identity')
    prefix.mkdir(parents=True, exist_ok=True, mode=0o755)
    require(prefix.stat().st_uid == os.geteuid(), 'installation prefix has an untrusted owner')
    destination = prefix / manifest['source_sha']
    if destination.exists() or destination.is_symlink():
        verify_tree(destination, manifest, archive)
        return False
    staging = Path(tempfile.mkdtemp(prefix='.studio-', dir=prefix))
    try:
        with open_archive(archive) as bundle:
            for member in bundle:
                target = staging / member.name
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    target.chmod(0o755)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('xb') as output, bundle.extractfile(member) as data:
                        shutil.copyfileobj(data, output)
                    target.chmod(member.mode)
        staging.chmod(0o755)
        verify_tree(staging, manifest, archive)
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['verify', 'install'])
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--trust', type=Path)
    parser.add_argument('--signer')
    parser.add_argument('--archive-sha256', help='independently verified candidate archive digest; excludes signature options')
    parser.add_argument('--prefix', type=Path)
    args = parser.parse_args()
    release, archive = verify_release(args.directory, args.source, args.trust, args.signer, args.archive_sha256)
    manifest = inspect_archive(archive, args.source)
    changed = False
    if args.action == 'install':
        require(args.prefix is not None, 'install requires --prefix')
        changed = install(archive, manifest, args.prefix)
    print(json.dumps({'source_sha': release['source_sha'], 'verified': True, 'changed': changed}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit('studio-install: ' + str(error))
