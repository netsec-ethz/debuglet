#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Build a deterministic, offline Linux hosted compiler bundle.

Run in the pinned CI tools image with --network=none and a warmed Go module
cache. This command never downloads modules or toolchains and never signs a
release. The release subject is studio-release.json; its OpenSSH signature
namespace is debuglet-studio-release.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

GO_VERSION = 'go1.26.10'
MODULE = 'github.com/netsec-ethz/debuglet'
GUEST_PACKAGES = ['./pkg/workflow/guest', './pkg/debuglet']
RUNTIME_DIRECTORIES = {'tmp', 'run', 'run/studio', 'proc', 'sys', 'dev', 'modules'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def command(args, cwd, env=None, timeout=180):
    try:
        return subprocess.check_output(args, cwd=cwd, env=env, text=True,
                                       stderr=subprocess.PIPE, timeout=timeout).strip()
    except subprocess.CalledProcessError as error:
        raise ValueError('command failed: ' + args[0] + ': ' + error.stderr[-8192:].strip()) from error


def environment(**extra):
    # Do not import developer Go settings, alternate toolchains or compiler flags.
    result = {key: os.environ[key] for key in
              ('PATH', 'HOME', 'TMPDIR', 'GOCACHE', 'GOMODCACHE') if key in os.environ}
    result.update(GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', GOWORK='off',
                  GOENV='off', GOFLAGS='', GOEXPERIMENT='', CGO_ENABLED='0',
                  GOOS='linux', GOARCH='amd64', GOAMD64='v1', GOMAXPROCS='2')
    result.update(extra)
    return result


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'expected regular file: ' + str(path))
    with path.open('rb') as source:
        value = hashlib.file_digest(source, 'sha256').hexdigest()
    return {'sha256': value, 'bytes': path.stat().st_size}


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts and
            str(path) == name and all(ord(c) >= 32 and c != '\x7f' for c in name) and
            '\\' not in name, 'unsafe payload path: ' + repr(name))
    return name


def copy_regular(source, destination):
    require(source.is_file() and not source.is_symlink(), 'linked or nonregular input: ' + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def copy_tree(source, destination):
    require(source.is_dir() and not source.is_symlink(), 'expected real input directory: ' + str(source))
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        safe_name(relative.as_posix())
        require(not path.is_symlink(), 'linked input: ' + str(path))
        if path.is_dir():
            (destination / relative).mkdir(parents=True, exist_ok=True)
        else:
            copy_regular(path, destination / relative)


def json_stream(data):
    decoder = json.JSONDecoder()
    while data.strip():
        data = data.lstrip()
        value, end = decoder.raw_decode(data)
        yield value
        data = data[end:]


def clean_source(source):
    require(not command(['git', 'status', '--porcelain', '--untracked-files=normal'], source),
            'compiler packages require a clean committed checkout')
    sha = command(['git', 'rev-parse', 'HEAD'], source)
    require(re.fullmatch(r'[0-9a-f]{40}', sha), 'invalid source revision')
    return sha


def tracked_files(source):
    entries = command(['git', 'ls-files', '--stage', '-z'], source).split('\0')
    result = {}
    for entry in entries:
        if entry:
            metadata, name = entry.split('\t', 1)
            mode, _, stage = metadata.split()
            require(stage == '0', 'unmerged source file')
            result[safe_name(name)] = mode
    return result


def copy_sdk(source, stage, packages, tracked):
    # Include only the files selected by the fixed WASI guest import closure.
    # Generated custom blocks can additionally import this same pkg/debuglet.
    selected = {'go.mod', 'go.sum', 'LICENSE', 'NOTICE'}
    for package in packages:
        if package.get('Module', {}).get('Main'):
            directory = Path(package['Dir']).resolve()
            require(directory.is_relative_to(source), 'SDK package escaped the checkout')
            for field in ('GoFiles', 'CgoFiles', 'CFiles', 'CXXFiles', 'MFiles',
                          'HFiles', 'FFiles', 'SFiles', 'SwigFiles', 'SwigCXXFiles',
                          'SysoFiles', 'EmbedFiles'):
                for filename in package.get(field, []):
                    selected.add((directory / filename).relative_to(source).as_posix())
    for name in sorted(selected):
        require(tracked.get(name) in ('100644', '100755'), 'SDK input is not a tracked regular file: ' + name)
        copy_regular(source / name, stage / 'sdk' / name)


def copy_modules(stage, packages, cache):
    modules = {}
    for package in packages:
        module = package.get('Module')
        if not module or module.get('Main'):
            continue
        require(not module.get('Replace'), 'replacement dependencies are not supported in hosted packages')
        modules[module['Path']] = module
    inventory = {}
    for name, module in sorted(modules.items()):
        require(module.get('Version') and module.get('Sum'), 'guest dependency lacks a pinned version/checksum')
        directory = Path(module['Dir']).resolve()
        require(directory.is_relative_to(cache), 'guest dependency escaped the module cache')
        relative = directory.relative_to(cache)
        copy_tree(directory, stage / 'modules' / relative)
        # Go's readonly module graph also needs the cached .mod metadata.
        mod = Path(module['GoMod']).resolve()
        require(mod.is_relative_to(cache) and mod.suffix == '.mod', 'unexpected cached module metadata')
        for extension in ('.mod', '.info', '.ziphash'):
            metadata = mod.with_suffix(extension)
            require(metadata.is_file(), 'missing offline module metadata: ' + str(metadata))
            copy_regular(metadata, stage / 'modules' / metadata.relative_to(cache))
        inventory[name] = {'version': module['Version'], 'sum': module['Sum']}
    return inventory


def require_static(path):
    """Reject ELF interpreters: a minimal service root has no host loader/libc."""
    with path.open('rb') as source:
        header = source.read(64)
        if not header.startswith(b'\x7fELF'):
            return
        require(len(header) == 64 and header[4] in (1, 2) and header[5] in (1, 2),
                'unsupported ELF executable: ' + str(path))
        endian = '<' if header[5] == 1 else '>'
        if header[4] == 2:
            offset = struct.unpack_from(endian + 'Q', header, 32)[0]
            size, count = struct.unpack_from(endian + 'HH', header, 54)
        else:
            offset = struct.unpack_from(endian + 'I', header, 28)[0]
            size, count = struct.unpack_from(endian + 'HH', header, 42)
        require(size >= 4 and count < 1024, 'invalid ELF program table')
        for index in range(count):
            source.seek(offset + index * size)
            kind = source.read(4)
            require(len(kind) == 4, 'truncated ELF program table')
            require(struct.unpack(endian + 'I', kind)[0] != 3,
                    'dynamically linked executable cannot run in the compiler root: ' + str(path))


def manifest(stage, sha, inputs):
    files, directories = {}, []
    for path in sorted(stage.rglob('*')):
        name = safe_name(path.relative_to(stage).as_posix())
        require(not path.is_symlink(), 'linked payload entry')
        if path.is_dir():
            directories.append(name)
            path.chmod(0o755)
        else:
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            path.chmod(mode)
            if mode == 0o755:
                require_static(path)
            files[name] = dict(digest(path), mode=mode)
    result = {'schema_version': 1, 'source_sha': sha, 'go_version': GO_VERSION,
              'inputs': inputs, 'directories': directories, 'files': files}
    (stage / 'studio-manifest.json').write_bytes(encoded(result))
    return result


def archive(stage, destination):
    # Explicit headers avoid host ownership, permissions, mtimes and gzip names.
    with destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for path in sorted(stage.rglob('*')):
                    name = safe_name(path.relative_to(stage).as_posix())
                    require(not path.is_symlink(), 'linked payload entry')
                    entry = tarfile.TarInfo(name)
                    if path.is_dir():
                        entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                        tar.addfile(entry)
                    else:
                        require(path.is_file(), 'nonregular payload entry')
                        entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                        entry.size = path.stat().st_size
                        with path.open('rb') as data:
                            tar.addfile(entry, data)


def smoke(source, stage):
    # Compile both API outputs with only the packaged SDK/toolchain/module cache.
    # Neither generated guest is executed. A fresh build cache detects omissions.
    with tempfile.TemporaryDirectory(prefix='debuglet-studio-smoke-') as temporary:
        env = environment(PATH=str(stage / 'go/bin'), HOME=temporary, TMPDIR=temporary,
                          GOCACHE=temporary + '/cache', GOMODCACHE=str(stage / 'modules'))
        for operation, fixture in (
                ('build', 'examples/workflows/custom-transform.json'),
                ('build-experiment', 'examples/workflows/experiments/three-node.json')):
            command([str(stage / 'bin/dbl-studio'), operation, '--sdk', str(stage / 'sdk'),
                     '--input', str(source / fixture), '--output', temporary + '/bundle.json'],
                    source, env, timeout=180)


def build(source, output, go):
    source, output = source.resolve(), output.absolute()
    require(platform.system() == 'Linux' and platform.machine() in ('x86_64', 'amd64'),
            'compiler packages must be built on Linux amd64')
    sha = clean_source(source)
    require(not output.exists() and not output.is_symlink(), 'output directory must not exist')
    env = environment()
    info = json.loads(command([go, 'env', '-json', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH',
                               'GOROOT', 'GOMODCACHE'], source, env))
    require(info['GOVERSION'] == GO_VERSION and info['GOHOSTOS'] == 'linux' and
            info['GOHOSTARCH'] == 'amd64', 'requires pinned Go 1.26.10 for Linux amd64')
    package_data = command([go, 'list', '-mod=readonly', '-deps', '-json'] + GUEST_PACKAGES,
                           source, environment(GOOS='wasip1', GOARCH='wasm'))
    packages = list(json_stream(package_data))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='debuglet-studio-package-') as temporary:
        stage = Path(temporary) / 'payload'
        stage.mkdir()
        for directory in RUNTIME_DIRECTORIES | {'bin'}:
            (stage / directory).mkdir(parents=True, exist_ok=True)
        command([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=true', '-p=2',
                 '-ldflags=-s -w', '-o', str(stage / 'bin/dbl-studio'), './cmd/dbl-studio'],
                source, env, timeout=300)
        copy_sdk(source, stage, packages, tracked_files(source))
        modules = copy_modules(stage, packages, Path(info['GOMODCACHE']).resolve())
        copy_tree(Path(info['GOROOT']), stage / 'go')
        for name in ('LICENSE', 'NOTICE'):
            copy_regular(source / name, stage / name)
        smoke(source, stage)
        # Refuse a build whose source changed while the compiler was working.
        require(clean_source(source) == sha, 'source changed during packaging')
        inputs = {name: digest(source / name) for name in ('go.mod', 'go.sum', 'deploy/ci/images.env')}
        inputs['modules'] = modules
        manifest(stage, sha, inputs)
        with tempfile.TemporaryDirectory(prefix='.' + output.name + '-', dir=output.parent) as prepared:
            prepared = Path(prepared)
            name = f'debuglet-studio-{sha}-linux-amd64.tar.gz'
            archive(stage, prepared / name)
            hashed = digest(prepared / name)
            release = {'schema_version': 1, 'source_sha': sha, 'go_version': GO_VERSION,
                       'archive': name, 'archive_sha256': hashed['sha256'], 'archive_bytes': hashed['bytes']}
            (prepared / 'studio-release.json').write_bytes(encoded(release))
            # mkdir is exclusive; never replace an existing candidate directory.
            output.mkdir(mode=0o755)
            for path in prepared.iterdir():
                path.rename(output / path.name)
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='action', required=True)
    create = subcommands.add_parser('build')
    create.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2])
    create.add_argument('--output', type=Path, required=True)
    create.add_argument('--go', default='go')
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.source, args.output, args.go), sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'studio package: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
