#!/usr/bin/env python3
"""Check the race lane's Go JSON results for actual, race-free test evidence.

Go reports a package without tests, and a package whose tests all skipped, as a
success. This gate requires every requested package root to report at least one
passing test, rejects failures and build errors, and rejects race reports even
when a test still returned success. It only reads results; it runs nothing.
"""
import argparse
import json
from pathlib import Path
import sys

RACE_MARKERS = ('WARNING: DATA RACE', 'race detected during execution of test',
                'found unexpected data race')


def module_path(repository):
    for line in (repository / 'go.mod').read_text(encoding='utf-8').splitlines():
        if line.startswith('module '):
            return line.split(None, 1)[1].strip()
    raise ValueError('go.mod does not declare a module path')


def import_path(module, root):
    """Map an explicit native package root such as ./internal/x to its import path."""
    if not root.startswith('./') or root.endswith('...') or root.strip('./') == '':
        raise ValueError(f'expected an explicit package root like ./internal/x, got {root}')
    return module + root[1:]


def read_events(path):
    events = []
    with open(path, encoding='utf-8') as results:
        for number, line in enumerate(results, start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f'{path}:{number}: unreadable Go JSON result: {exc}') from exc
    return events


def report(events, required):
    problems = []
    packages = {name: {'result': None, 'elapsed': 0.0, 'pass': 0, 'skip': 0, 'fail': 0}
                for name in required}
    unexpected = set()
    skipped = []
    races = []
    for event in events:
        action = event.get('Action')
        if action in ('build-fail', 'build-output') and event.get('ImportPath'):
            if action == 'build-fail':
                problems.append(f'build failed: {event["ImportPath"]}')
            continue
        name = event.get('Package')
        if name is None:
            continue
        if name not in packages:
            if action in ('pass', 'fail', 'skip'):
                unexpected.add(name)
            continue
        summary = packages[name]
        test = event.get('Test')
        if action == 'output':
            text = event.get('Output', '')
            if any(marker in text for marker in RACE_MARKERS):
                races.append(f'{name} {test or ""}'.strip())
            continue
        if test:
            if action == 'pass':
                summary['pass'] += 1
            elif action == 'skip':
                summary['skip'] += 1
                skipped.append(f'{name} {test}')
            elif action == 'fail':
                summary['fail'] += 1
                problems.append(f'failed test: {name} {test}')
        elif action in ('pass', 'fail', 'skip'):
            summary['result'] = action
            summary['elapsed'] = event.get('Elapsed') or 0.0

    for name in required:
        summary = packages[name]
        if summary['result'] is None:
            problems.append(f'no result for required package {name}')
        elif summary['result'] != 'pass':
            problems.append(f'package {summary["result"]}: {name}')
        if not summary['pass']:
            problems.append(f'no passing test in required package {name}; '
                            'a package without executed tests is not race evidence')
    for name in sorted(unexpected):
        problems.append(f'unrequested package in race results: {name}')
    for name in sorted(set(races)):
        problems.append(f'data race reported by {name}')
    return packages, skipped, problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--budget-seconds', type=float, default=None)
    parser.add_argument('packages', nargs='+', metavar='PACKAGE_ROOT')
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    module = module_path(repository)
    required = [import_path(module, root) for root in args.packages]
    if len(set(required)) != len(required):
        raise ValueError('duplicate package root requested')
    packages, skipped, problems = report(read_events(args.evidence), required)

    total = sum(summary['elapsed'] for summary in packages.values())
    for name in required:
        summary = packages[name]
        print(f'{summary["elapsed"]:8.2f}s {summary["result"] or "missing":7} '
              f'pass={summary["pass"]:<4} skip={summary["skip"]:<4} {name}')
    for entry in skipped:
        print(f'Skipped test (not counted as evidence): {entry}', file=sys.stderr)
    print(f'Race lane test time: {total:.1f}s across {len(required)} packages.')
    if args.budget_seconds and total > args.budget_seconds:
        print(f'Race lane exceeded its {args.budget_seconds:.0f}s budget; '
              'trim the package list or split the lane.', file=sys.stderr)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print('Race lane evidence is incomplete.', file=sys.stderr)
        return 1
    print('Every requested package passed actual tests under the race detector.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
