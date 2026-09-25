#!/usr/bin/env python3
"""Witness an installed candidate in an existing isolated runtime image on Linux.

This is an operator acceptance tool, not part of the installed product. It never
fetches an image or contacts a testbed. Exit zero requires inspection BEFORE
container teardown as well as removal of the exact owned container afterwards.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
IMAGE = 'ubuntu@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54'
PAYLOAD = {
    'bin/dbl': 0o755, 'bin/debuglet-dispatcher': 0o755,
    'bin/debuglet-executor': 0o755, 'share/debuglet/demo.wasm': 0o644,
    'share/debuglet/hello.wasm': 0o644,
    'share/debuglet/manifest.json': 0o644, 'LICENSE': 0o644,
    'README-install.md': 0o644,
}
# The wrapper remains PID 1 after dbl exits. Process and state checks happen
# here, not after Docker has destroyed the namespace and hidden possible leaks.
WRAPPER = r'''
set -eu
export LC_ALL=C
for tool in go gcc clang docker; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'unexpected runtime tool: %s\n' "$tool" >&2
    exit 1
  fi
done
[ "$(id -u)" = 65532 ]
mkdir -m 0700 /tmp/work /tmp/state
cd /tmp/work
/usr/bin/env -i PATH= LANG=C LC_ALL=C TZ=UTC /opt/debuglet/bin/dbl --timeout 5s --output json version > /tmp/version.json
printf 'BINARY_VERSION=' >&2
cat /tmp/version.json >&2
set +e
/usr/bin/env -i PATH= TMPDIR=/tmp/state LANG=C LC_ALL=C TZ=UTC \
  /opt/debuglet/bin/dbl --timeout 60s --output json demo > /tmp/receipt.json 2>/tmp/diagnostics.txt
code=$?
set -e
cat /tmp/receipt.json
cat /tmp/diagnostics.txt >&2
printf 'DBL_EXIT=%s\n' "$code" >&2
clean=1
for process in /proc/[0-9]*; do
  pid=${process#/proc/}
  [ "$pid" = "$$" ] && continue
  printf 'remaining process: %s\n' "$pid" >&2
  clean=0
done
for entry in /tmp/* /tmp/.[!.]* /tmp/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "$entry" in /tmp/work|/tmp/state|/tmp/receipt.json|/tmp/diagnostics.txt|/tmp/version.json) continue ;; esac
  printf 'unexpected temporary entry: %s\n' "$entry" >&2
  clean=0
done
for entry in /tmp/state/* /tmp/state/.[!.]* /tmp/state/..?* /tmp/work/* /tmp/work/.[!.]* /tmp/work/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  printf 'remaining demo state: %s\n' "$entry" >&2
  clean=0
done
[ "$clean" = 1 ] || exit 1
printf 'CLEANUP_OBSERVED_BEFORE_CONTAINER_EXIT=1\n' >&2
[ "$code" = 0 ]
'''


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def terminate_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=5)


def command(args, *, timeout=30, cwd=None):
    environment = dict(os.environ)
    environment.pop('DOCKER_HOST', None)
    environment.pop('DOCKER_CONTEXT', None)
    process = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        terminate_group(process)
        raise
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        terminate_group(process)
        raise RuntimeError('command left subprocesses in its owned process group')
    if process.returncode:
        raise RuntimeError(f'{args[0]} exited {process.returncode}: '
                           f'{stderr.decode(errors="replace")[:8192]}')
    return stdout


def verify_payload(root, sha):
    paths = {p.relative_to(root).as_posix(): p for p in root.rglob('*')}
    if set(paths) != set(PAYLOAD) | {'bin', 'share', 'share/debuglet'}:
        raise ValueError('unexpected staged payload paths')
    for name, path in paths.items():
        if path.is_symlink():
            raise ValueError('staged payload contains a symlink')
        if name in PAYLOAD and (not path.is_file() or path.stat().st_mode & 0o7777 != PAYLOAD[name]):
            raise ValueError('staged payload mode/type mismatch')
    manifest_path = root / 'share/debuglet/manifest.json'
    if manifest_path.stat().st_size > 65536:
        raise ValueError('manifest is too large')
    manifest = decode(manifest_path.read_bytes())
    if (manifest['source_sha'] != sha or manifest['dirty'] is not False or
            manifest['goos'] != 'linux' or manifest['goarch'] != 'amd64'):
        raise ValueError('installed identity differs from committed source')
    if set(manifest['files']) != set(PAYLOAD) - {'share/debuglet/manifest.json'}:
        raise ValueError('manifest file set mismatch')
    for name, record in manifest['files'].items():
        if digest(root / name) != record['sha256'] or (root / name).stat().st_size != record['bytes']:
            raise ValueError('staged payload digest/size mismatch')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError(f'acceptance interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if sys.platform != 'linux':
        raise ValueError('run this host acceptance tool on Linux')
    os.environ.pop('DOCKER_HOST', None)
    os.environ.pop('DOCKER_CONTEXT', None)
    repo = Path(__file__).resolve().parents[1]
    if command(['git', 'status', '--porcelain'], cwd=repo).strip():
        raise ValueError('acceptance requires a clean committed checkout')
    sha = command(['git', 'rev-parse', 'HEAD'], cwd=repo).decode().strip()
    package = args.packages.resolve(strict=True)
    archives = list(package.glob('debuglet-v*-linux-amd64.tar.gz'))
    if len(archives) != 1:
        raise ValueError('expected exactly one archive')
    archive = archives[0]
    version = archive.name.removeprefix('debuglet-').removesuffix('-linux-amd64.tar.gz')
    evidence = args.evidence.resolve()
    evidence.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = 'debuglet-offline-' + uuid.uuid4().hex[:12]
    report = dict(source_sha=sha, version=version, image=IMAGE,
                  archive_sha256=digest(archive), installer_sha256=digest(package / 'install.sh'),
                  container_name=name, external_environment='unconfirmed', outcome='failed')
    started = time.monotonic()
    created = False
    stage = Path(tempfile.mkdtemp(prefix='debuglet-offline-'))
    try:
        command(DOCKER + ['image', 'inspect', IMAGE])  # Existing image only.
        (evidence / 'checksums.log').write_bytes(command(['sha256sum', '--check', 'SHA256SUMS'], cwd=package))
        prefix = stage / 'install with spaces'
        install = ['sh', str(package / 'install.sh'), '--archive', str(archive),
                   '--checksums', str(package / 'SHA256SUMS'), '--version', version, '--prefix', str(prefix)]
        (evidence / 'install-command.json').write_text(json.dumps(install))
        (evidence / 'install.log').write_bytes(command(install, timeout=60))
        installed = prefix / 'lib/debuglet' / version
        original = verify_payload(installed, sha)
        payload = stage / 'payload'
        shutil.copytree(installed, payload)
        os.chmod(payload, 0o755)
        if verify_payload(payload, sha) != original:
            raise ValueError('staging changed the installed manifest')
        report['manifest_sha256'] = digest(payload / 'share/debuglet/manifest.json')
        (evidence / 'manifest.json').write_text(json.dumps(original, indent=2) + '\n')
        create = DOCKER + ['create', '--name', name, '--pull=never', '--network', 'none',
                  '--user', '65532:65532', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                  '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
                  '--memory', '1g', '--cpus', '2', '--pids-limit', '128',
                  '--mount', f'type=bind,source={payload},target=/opt/debuglet,readonly',
                  '--workdir', '/tmp', IMAGE, '/bin/sh', '-c', WRAPPER]
        (evidence / 'container-command.json').write_text(json.dumps(create, indent=2) + '\n')
        # Claim this unique name before create: even a client timeout after
        # successful daemon creation must lead to cleanup of this owned name.
        created = True
        container_id = command(create).decode().strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container_id):
            raise ValueError('invalid created container ID')
        report['container_id'] = container_id
        with (evidence / 'stdout.json').open('wb') as stdout, (evidence / 'stderr.log').open('wb') as stderr:
            result = subprocess.run(DOCKER + ['start', '--attach', container_id],
                                    stdout=stdout, stderr=stderr, timeout=90, check=False)
        inspect = decode(command(DOCKER + ['inspect', container_id]))[0]
        report['state'] = inspect['State']
        report['docker_client_exit'] = result.returncode
        if inspect['State']['Running'] or inspect['State']['ExitCode'] != 0 or result.returncode != 0:
            raise RuntimeError('offline container or demo failed; inspect retained diagnostics')
        if (evidence / 'stdout.json').stat().st_size > 65536 or (evidence / 'stderr.log').stat().st_size > 3*1024*1024:
            raise ValueError('offline output exceeds its evidence bounds')
        if b'CLEANUP_OBSERVED_BEFORE_CONTAINER_EXIT=1\n' not in (evidence / 'stderr.log').read_bytes():
            raise ValueError('missing cleanup observation before container exit')
        version_lines = [line.removeprefix('BINARY_VERSION=') for line in
                         (evidence / 'stderr.log').read_text().splitlines()
                         if line.startswith('BINARY_VERSION=')]
        if len(version_lines) != 1:
            raise ValueError('missing or ambiguous offline binary identity')
        binary = decode(version_lines[0])
        if (binary.get('module') != 'github.com/netsec-ethz/debuglet' or
                binary.get('version') != version or binary.get('revision') != sha or
                binary.get('modified') is not False):
            raise ValueError('offline binary identity does not match candidate')
        report['binary_version'] = binary
        receipt = decode((evidence / 'stdout.json').read_bytes())
        if (set(receipt) != {'version', 'executor_id', 'run_id', 'response', 'state', 'cleanup'} or
                receipt['version'] != version or receipt['state'] != 'RunStateExited' or
                receipt['cleanup'] != 'complete' or not re.fullmatch(r'DEBUGLET/1 [0-9a-f]{32}', receipt['response'])):
            raise ValueError('invalid offline demo receipt')
        for key in ['executor_id', 'run_id']:
            uuid.UUID(receipt[key])
        report['receipt'] = receipt
        report['cleanup_observed_before_container_exit'] = True
        report['outcome'] = 'passed'
    except Exception as exc:
        report['error'] = str(exc)
    finally:
        if created:
            try:
                removed = subprocess.run(DOCKER + ['rm', '--force', name], stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, timeout=30, check=False)
                report['container_removal_exit'] = removed.returncode
                if removed.returncode:
                    report['outcome'] = 'failed'
                    report['removal_error'] = removed.stderr.decode(errors='replace')[:8192]
            except Exception as exc:
                report['outcome'] = 'failed'
                report['removal_error'] = str(exc)
        if not created or report.get('container_removal_exit') == 0:
            try:
                shutil.rmtree(stage)
            except Exception as exc:
                report['outcome'] = 'failed'
                report['stage_removal_error'] = str(exc)
                report['retained_stage'] = str(stage)
        else:
            report['retained_stage'] = str(stage)
        report['wall_seconds'] = round(time.monotonic() - started, 3)
        (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['outcome'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
