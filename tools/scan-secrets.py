#!/usr/bin/env python3
"""Run Gitleaks without exposing match values in logs or retained reports."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

# Gitleaks fingerprints: `file:rule:line`, or `commit:file:rule:line` for one commit.
# Each entry names one finding exactly; wildcards and directories cannot match.
EXCEPTION = re.compile(r'(?:[0-9a-f]{40}:)?[^\s:*?\[\]]+[^\s:*?\[\]/]:[a-z0-9][a-z0-9-]*:[1-9][0-9]*')
FIXED = ('-c', '-b', '-i', '--config', '--baseline-path', '--gitleaks-ignore-path')


def exceptions(path):
    """Validate the reviewed exception list; any malformed entry fails the scan."""
    entries = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not EXCEPTION.fullmatch(line):
            raise ValueError(f'{path.name}:{number}: exception is not an exact finding fingerprint')
        entries.append(line)
    return entries


def guard(arguments, exception_path):
    """Refuse configuration Gitleaks would otherwise load from outside the reviewed list."""
    for name in ('GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML'):
        if os.environ.get(name):
            raise ValueError(f'{name} would replace the default scanner rules')
    if any(a.split('=', 1)[0] in FIXED for a in arguments):
        raise ValueError('scanner rules and exceptions are fixed by this wrapper')
    if len(arguments) < 2 or arguments[0] not in ('dir', 'git') or arguments[-1].startswith('-'):
        raise ValueError('secret scan mode or source is missing')
    source = Path(arguments[-1])
    if (source / '.gitleaks.toml').exists():
        raise ValueError('scan source provides its own scanner configuration')
    ignore = source / '.gitleaksignore'
    if ignore.exists() and ignore.read_bytes() != exception_path.read_bytes():
        raise ValueError('scan source provides an unreviewed exception list')


def scan(binary, arguments, report, exception_path):
    exceptions(exception_path)
    guard(arguments, exception_path)
    with tempfile.TemporaryDirectory() as temporary:
        raw = Path(temporary) / 'findings.json'
        result = subprocess.run([binary, *arguments[:-1], '--redact=100', '--no-banner',
                                 '--no-color', '--log-level=error', '--exit-code=10',
                                 '--gitleaks-ignore-path', str(exception_path),
                                 '--report-format=json', '--report-path', str(raw),
                                 arguments[-1]],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        if result.returncode not in (0, 10):
            raise ValueError(f'secret scanner execution failed (status {result.returncode})')
        findings = json.loads(raw.read_text())
        if not isinstance(findings, list):
            raise ValueError('secret scanner returned an invalid report')
        safe = []
        for finding in findings:
            if not isinstance(finding, dict) or not all(key in finding for key in ('RuleID', 'File', 'StartLine')):
                raise ValueError('secret scanner returned an incomplete finding')
            safe.append({key: finding[key] for key in ('RuleID', 'File', 'StartLine')})
        if bool(safe) != (result.returncode == 10):
            raise ValueError('secret scanner result disagrees with its report')
        report.write_text(json.dumps(safe, indent=2) + '\n')
        for finding in safe:
            print(f"{finding['File']}:{finding['StartLine']}: {finding['RuleID']} (redacted)")
        return bool(safe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scanner', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--exceptions', type=Path, required=True,
                        help='reviewed .gitleaksignore of exact finding fingerprints')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    return int(scan(args.scanner, arguments, args.report, args.exceptions.resolve(strict=True)))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Secret scan failed: {error}', file=sys.stderr)
        sys.exit(2)
