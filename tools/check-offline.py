#!/usr/bin/env python3
"""Execute a verified installed candidate in an existing, offline runtime image."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

SCRIPT = r'''
set -eu
for compiler in go gcc clang cc; do
    if command -v "$compiler" >/dev/null 2>&1; then
        echo 'offline runtime contains a compiler' >&2; exit 1
    fi
done
/payload/bin/dbl --timeout 90s --output json demo > /tmp/result.json
# Observe ownership before the container boundary can hide leaks.
for process in /proc/[0-9]*; do
    case "${process##*/}" in 1|$$) continue ;; esac
    [ ! -d "$process" ] || { echo 'demo left an owned process' >&2; exit 1; }
done
for state in /tmp/debuglet-demo-*; do
    [ ! -e "$state" ] || { echo 'demo left owned state' >&2; exit 1; }
done
cat /tmp/result.json
'''


def validate_result(text, version):
    result = json.loads(text)
    if (not isinstance(result, dict) or result.get('version') != version or
            result.get('state') != 'RunStateExited' or result.get('cleanup') != 'complete' or
            not result.get('executor_id') or not result.get('run_id') or
            not result.get('response', '').startswith('DEBUGLET/1 ')):
        raise ValueError('offline demo returned an incomplete or mismatched result')
    return result


def witness(image, root, archive, source, evidence):
    image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image],
                                       text=True, timeout=20).strip()
    manifest_bytes = (root / 'share/debuglet/manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get('source_sha') != source or manifest.get('dirty') is not False:
        raise ValueError('installed manifest does not match the clean candidate revision')
    name = 'debuglet-offline-' + uuid.uuid4().hex
    with archive.open('rb') as payload:
        archive_hash = hashlib.file_digest(payload, 'sha256').hexdigest()
    record = {'source_sha': source, 'image': image, 'image_id': image_id,
              'archive_sha256': archive_hash,
              'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'container': name}
    evidence.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(['docker', 'run', '--init', '--pull=never', '--name', name,
                                 '--network', 'none', '--cap-drop', 'ALL', '--read-only',
                                 '--cpus', '2', '--memory', '1g', '--pids-limit', '256',
                                 '--tmpfs', '/tmp:rw,exec,size=256m',
                                 '--mount', f'type=bind,source={root},target=/payload,readonly',
                                 '--env', 'HOME=/tmp', image, 'sh', '-c', SCRIPT],
                                text=True, capture_output=True, timeout=120)
        (evidence / 'stdout.json').write_text(result.stdout)
        (evidence / 'stderr.log').write_text(result.stderr)
        record['exit_status'] = result.returncode
        if result.returncode != 0:
            raise ValueError('offline demo or pre-teardown ownership check failed')
        record['result'] = validate_result(result.stdout, manifest['version'])
        record['ownership_checked_before_teardown'] = True
    finally:
        subprocess.run(['docker', 'rm', '--force', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        remaining = name in subprocess.check_output(
            ['docker', 'container', 'ls', '--all', '--format', '{{.Names}}'],
            text=True, timeout=20).splitlines()
        record['container_removed'] = not remaining
        (evidence / 'witness.json').write_text(json.dumps(record, indent=2) + '\n')
        if remaining:
            raise ValueError('offline witness container was not removed')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--installed-root', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    witness(args.image, args.installed_root.resolve(strict=True), args.archive,
            args.source_sha, args.evidence)
    print('Installed candidate passed without network or compiler access; owned container removed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'Offline verification failed: {error}', file=sys.stderr)
        sys.exit(1)
