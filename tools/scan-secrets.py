#!/usr/bin/env python3
"""Run Gitleaks without exposing match values in logs or retained reports."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def scan(binary, arguments, report):
    with tempfile.TemporaryDirectory() as temporary:
        raw = Path(temporary) / 'findings.json'
        result = subprocess.run([binary, *arguments, '--redact=100', '--no-banner',
                                 '--no-color', '--log-level=error', '--exit-code=10',
                                 '--report-format=json', '--report-path', str(raw)],
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
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    return int(scan(args.scanner, arguments, args.report))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Secret scan failed: {error}', file=sys.stderr)
        sys.exit(2)
