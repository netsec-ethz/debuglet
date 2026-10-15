#!/usr/bin/env python3
"""Build and verify the small Debuglet apt repository with standard Debian tools."""
import argparse
import gzip
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import io
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import urlopen

SUITE = Path('dists/stable')
INDEX = Path('main/binary-amd64/Packages')
POOL = Path('pool/main/d/debuglet')
MAX_INDEX = 16 * 1024 * 1024
MAX_PACKAGE = 512 * 1024 * 1024
PACKAGE = re.compile(r'debuglet(?:-payload-[0-9a-f]{24})?\Z')
FILENAME = re.compile(r'debuglet(?:-payload-[0-9a-f]{24})?_[0-9][0-9A-Za-z.+~:-]*_amd64\.deb\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(args, **kwargs):
    return subprocess.check_output(args, timeout=180, **kwargs)


def regular(path, maximum=MAX_PACKAGE):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            'missing, linked or oversized file: ' + str(path))
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fields(data):
    """Read the Deb822 records emitted by apt-ftparchive, rejecting ambiguity."""
    result = []
    for paragraph in data.decode('utf-8').strip().split('\n\n'):
        record, key = {}, None
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')):
                require(key is not None, 'orphan metadata continuation')
                record[key] += '\n' + line.strip()
            else:
                require(':' in line, 'invalid apt metadata field')
                key, value = line.split(':', 1)
                require(key not in record and re.fullmatch(r'[A-Za-z0-9-]+', key),
                        'duplicate or invalid apt metadata field')
                record[key] = value.strip()
        require(record, 'empty apt metadata')
        result.append(record)
    return result


def release_indexes(data):
    records = fields(data)
    require(len(records) == 1, 'expected one Release record')
    release = records[0]
    for key, value in {'Origin': 'Debuglet', 'Label': 'Debuglet', 'Suite': 'stable',
                       'Codename': 'stable', 'Architectures': 'amd64', 'Components': 'main'}.items():
        require(release.get(key) == value, 'unexpected Release ' + key)
    result = {}
    for line in release.get('SHA256', '').splitlines():
        if not line:
            continue
        parts = line.split()
        require(len(parts) == 3 and re.fullmatch(r'[0-9a-f]{64}', parts[0])
                and parts[1].isdigit(), 'invalid Release SHA256 entry')
        hashed, size, name = parts
        require(name not in result and name in (str(INDEX), str(INDEX) + '.gz')
                and 0 < int(size) <= MAX_INDEX, 'unexpected, duplicate or oversized apt index')
        result[name] = (hashed, int(size))
    require(set(result) == {str(INDEX), str(INDEX) + '.gz'}, 'incomplete apt indexes')
    return result


def package_entries(data):
    result, identities = {}, set()
    for record in fields(data):
        name, version, architecture = (record.get(key, '') for key in ('Package', 'Version', 'Architecture'))
        filename = record.get('Filename', '')
        require(PACKAGE.fullmatch(name) and architecture == 'amd64'
                and re.fullmatch(r'[0-9][0-9A-Za-z.+~:-]*', version), 'unexpected package identity')
        require(filename == str(POOL / f'{name}_{version}_amd64.deb')
                and FILENAME.fullmatch(Path(filename).name), 'unexpected package filename')
        require(filename not in result and (name, version, architecture) not in identities,
                'duplicate package identity')
        require(re.fullmatch(r'[0-9a-f]{64}', record.get('SHA256', ''))
                and record.get('Size', '').isdigit()
                and 0 < int(record['Size']) <= MAX_PACKAGE, 'invalid package digest or size')
        result[filename] = (record['SHA256'], int(record['Size']))
        identities.add((name, version, architecture))
    require(any(record['Package'] == 'debuglet' for record in fields(data)), 'missing debuglet selector')
    return result


def matches(path, expected, maximum):
    data = regular(path, maximum)
    require((digest(data), len(data)) == expected, 'SHA256/size mismatch: ' + str(path))
    return data


def keyring(key, fingerprint, directory):
    fingerprint = fingerprint.upper()
    require(re.fullmatch(r'[0-9A-F]{40}|[0-9A-F]{64}', fingerprint), 'invalid OpenPGP fingerprint')
    regular(key, 1024 * 1024)
    home = directory / 'gnupg'
    home.mkdir(mode=0o700)
    output = command(['gpg', '--batch', '--no-options', '--homedir', str(home), '--with-colons',
                      '--show-keys', '--fingerprint', str(key)]).decode()
    primary, pending = [], False
    for line in output.splitlines():
        parts = line.split(':')
        if parts[0] == 'pub':
            pending = True
        elif parts[0] == 'fpr' and pending:
            primary.append(parts[9])
            pending = False
    require(primary == [fingerprint], 'public key does not match the independently provisioned fingerprint')
    ring = directory / 'trusted.gpg'
    command(['gpg', '--batch', '--no-options', '--homedir', str(home), '--dearmor',
             '--output', str(ring), str(key)])
    return ring


def verified_release(directory, key, fingerprint):
    regular(directory / SUITE / 'InRelease', MAX_INDEX)
    with tempfile.TemporaryDirectory(prefix='debuglet-apt-verify-') as temporary:
        temporary = Path(temporary)
        ring = keyring(key, fingerprint, temporary)
        output = temporary / 'Release'
        command(['gpgv', '--homedir', str(temporary / 'gnupg'), '--keyring', str(ring),
                 '--output', str(output), str(directory / SUITE / 'InRelease')])
        data = regular(output, MAX_INDEX)
    release_indexes(data)
    return data


def verify(directory, key, fingerprint):
    release = verified_release(directory, key, fingerprint)
    require(regular(directory / SUITE / 'Release', MAX_INDEX) == release,
            'Release differs from verified InRelease')
    for name, expected in release_indexes(release).items():
        matches(directory / SUITE / name, expected, MAX_INDEX)
    packages = regular(directory / SUITE / INDEX, MAX_INDEX)
    with gzip.GzipFile(fileobj=io.BytesIO(regular(directory / SUITE / (str(INDEX) + '.gz'), MAX_INDEX))) as compressed:
        require(compressed.read(MAX_INDEX + 1) == packages, 'compressed index differs')
    entries = package_entries(packages)
    for name, expected in entries.items():
        matches(directory / name, expected, MAX_PACKAGE)
    actual = {p.relative_to(directory).as_posix() for p in (directory / 'pool').rglob('*') if p.is_file()}
    require(actual == set(entries), 'unsigned extra pool files')
    return {'packages': len(entries), 'release_sha256': digest(release), 'verified': True}


def fetch(url, directory, key, fingerprint, bootstrap=False, allow_local_http=False):
    parsed = urlsplit(url)
    allowed = parsed.scheme == 'https' or (allow_local_http and parsed.scheme == 'http'
                                          and parsed.hostname in ('localhost', '127.0.0.1', '::1'))
    require(allowed and parsed.netloc and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment, 'repository URL must be HTTPS without credentials')
    directory.mkdir()

    def download(name, limit):
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with urlopen(url.rstrip('/') + '/' + name, timeout=60) as response:
            final = urlsplit(response.url)
            require(final.scheme == 'https' or (allow_local_http and final.scheme == 'http'
                    and final.hostname in ('localhost', '127.0.0.1', '::1')), 'unsafe repository redirect')
            data = response.read(limit + 1)
            require(len(data) <= limit, 'repository file exceeds size limit')
            target.write_bytes(data)

    try:
        download(str(SUITE / 'InRelease'), MAX_INDEX)
    except HTTPError as error:
        if bootstrap and error.code == 404:
            return {'bootstrap': True, 'packages': 0}
        raise
    require(not bootstrap, 'bootstrap refused: a signed repository already exists')
    release = verified_release(directory, key, fingerprint)
    (directory / SUITE / 'Release').write_bytes(release)
    for name, expected in release_indexes(release).items():
        download(str(SUITE / name), MAX_INDEX)
        matches(directory / SUITE / name, expected, MAX_INDEX)
    for name, expected in package_entries(regular(directory / SUITE / INDEX, MAX_INDEX)).items():
        download(name, MAX_PACKAGE)
        matches(directory / name, expected, MAX_PACKAGE)
    return verify(directory, key, fingerprint)


def build(packages, directory, previous=None):
    """Create unsigned metadata; production callers first authenticate all inputs."""
    require(not directory.exists(), 'output already exists')
    sources = sorted(packages.glob('*.deb'))
    require(sources, 'no Debian packages')
    directory.mkdir()
    pool = directory / POOL
    pool.mkdir(parents=True)
    if previous is not None:
        # The production prepare command verifies previous before reaching here.
        entries = package_entries(regular(previous / SUITE / INDEX, MAX_INDEX))
        for name, expected in entries.items():
            matches(previous / name, expected, MAX_PACKAGE)
            shutil.copyfile(previous / name, directory / name)
    for source in sources:
        data = regular(source)
        output = command(['dpkg-deb', '--field', str(source), 'Package', 'Version', 'Architecture'])
        control = fields(output)[0]
        require(PACKAGE.fullmatch(control.get('Package', '')) and control.get('Architecture') == 'amd64'
                and re.fullmatch(r'[0-9][0-9A-Za-z.+~:-]*', control.get('Version', '')),
                'unexpected Debian control identity')
        if previous is not None and control['Package'] == 'debuglet':
            for retained in fields(regular(previous / SUITE / INDEX, MAX_INDEX)):
                if retained['Package'] == 'debuglet':
                    comparison = subprocess.run(['dpkg', '--compare-versions', control['Version'],
                                                 'ge', retained['Version']], check=False, timeout=10)
                    require(comparison.returncode == 0, 'refusing to publish an older selector version')
        destination = pool / '{Package}_{Version}_{Architecture}.deb'.format(**control)
        require(not destination.exists() or regular(destination) == data, 'refusing to replace a retained package')
        destination.write_bytes(data)
    index = directory / SUITE / INDEX
    index.parent.mkdir(parents=True)
    data = command(['apt-ftparchive', 'packages', 'pool'], cwd=directory)
    package_entries(data)
    index.write_bytes(data)
    (index.parent / 'Packages.gz').write_bytes(gzip.compress(data, mtime=0))
    # Keep the previous generation's content-addressed indexes for clients that
    # fetched its InRelease immediately before an atomic Pages deployment.
    by_hash = index.parent / 'by-hash/SHA256'
    by_hash.mkdir(parents=True)
    for root in (previous, directory):
        if root is not None:
            for name in (INDEX, Path(str(INDEX) + '.gz')):
                contents = regular(root / SUITE / name, MAX_INDEX)
                (by_hash / digest(contents)).write_bytes(contents)
    options = {'Origin': 'Debuglet', 'Label': 'Debuglet', 'Suite': 'stable', 'Codename': 'stable',
               'Architectures': 'amd64', 'Components': 'main', 'Acquire-By-Hash': 'yes',
               'Description': 'Debuglet for Ubuntu 24.04 amd64',
               'Valid-Until': format_datetime(datetime.now(timezone.utc) + timedelta(days=90), usegmt=True)}
    arguments = ['apt-ftparchive']
    for key, value in options.items():
        arguments += ['-o', f'APT::FTPArchive::Release::{key}={value}']
    release = command(arguments + ['release', str(SUITE)], cwd=directory)
    release_indexes(release)
    (directory / SUITE / 'Release').write_bytes(release)
    (directory / '.nojekyll').touch()
    return {'packages': len(package_entries(data)), 'release_sha256': digest(release), 'signed': False}


def prepare(release_directory, version, source, trust, signer, directory, key, fingerprint, previous=None):
    from release import verify_release
    release = verify_release(release_directory, trust, signer, version, source)
    if previous is not None:
        verify(previous, key, fingerprint)
    names = [name for name in release['files'] if name.endswith('.deb')]
    require(set(names) == {f'debuglet-{version}-linux-amd64.deb',
                           f'debuglet-payload-{version}-linux-amd64.deb'},
            'release must bind the selector and one immutable payload package')
    with tempfile.TemporaryDirectory(prefix='debuglet-apt-input-') as temporary:
        staging = Path(temporary)
        for name in names:
            shutil.copyfile(release_directory / name, staging / name)
        result = build(staging, directory, previous)
    with tempfile.TemporaryDirectory(prefix='debuglet-apt-key-') as temporary:
        keyring(key, fingerprint, Path(temporary))
    shutil.copyfile(key, directory / 'debuglet-archive-keyring.asc')
    return dict(result, version=version, source_sha=source)


def check_published_release(record, version):
    from release import VERSION
    require(VERSION.fullmatch(version), 'invalid release version')
    require(record.get('tag_name') == version and record.get('draft') is False
            and isinstance(record.get('published_at'), str) and record['published_at'],
            'release must be published for the exact protected version tag')


def download_published(version, directory):
    from release import REPOSITORY, VERSION, github_json, download_release
    require(VERSION.fullmatch(version), 'invalid release version')
    record = github_json(f'repos/{REPOSITORY}/releases/tags/{version}')
    check_published_release(record, version)
    directory.mkdir()
    download_release(REPOSITORY, record, directory, version)
    return {'downloaded': True, 'version': version, 'release_id': record['id']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for action in ('fetch', 'verify', 'prepare'):
        command_parser = commands.add_parser(action)
        command_parser.add_argument('--key', type=Path, required=True)
        command_parser.add_argument('--fingerprint', required=True)
        if action == 'verify':
            command_parser.add_argument('--directory', type=Path, required=True)
        else:
            command_parser.add_argument('--out', type=Path, required=True)
        if action == 'fetch':
            command_parser.add_argument('--url', required=True)
            command_parser.add_argument('--bootstrap', action='store_true')
            command_parser.add_argument('--allow-local-http', action='store_true')
        if action == 'prepare':
            command_parser.add_argument('--release-directory', type=Path, required=True)
            command_parser.add_argument('--version', required=True)
            command_parser.add_argument('--source', required=True)
            command_parser.add_argument('--trust', type=Path, required=True)
            command_parser.add_argument('--signer', required=True)
            command_parser.add_argument('--previous', type=Path)
    command_parser = commands.add_parser('build', help='local unsigned repository rehearsal')
    command_parser.add_argument('--packages', type=Path, required=True)
    command_parser.add_argument('--out', type=Path, required=True)
    command_parser.add_argument('--previous', type=Path)
    command_parser = commands.add_parser('download-release')
    command_parser.add_argument('--version', required=True)
    command_parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            result = build(args.packages.resolve(), args.out.resolve(), args.previous)
        elif args.command == 'verify':
            result = verify(args.directory, args.key, args.fingerprint)
        elif args.command == 'fetch':
            result = fetch(args.url, args.out, args.key, args.fingerprint, args.bootstrap, args.allow_local_http)
        elif args.command == 'prepare':
            result = prepare(args.release_directory, args.version, args.source, args.trust, args.signer,
                             args.out.resolve(), args.key, args.fingerprint, args.previous)
        else:
            result = download_published(args.version, args.out)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f'apt repository: {error}\n')


if __name__ == '__main__':
    main()
