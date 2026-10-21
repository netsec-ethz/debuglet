#!/usr/bin/env python3
"""Split Go statement coverage by source ownership and list package timings.

Input is the ordinary test lane's own profile and JSON event stream. Generated
bindings are kept in a separate report; neither profile includes coverage of
independently built subprocesses or WASM guests.
"""
import csv
import json
from pathlib import Path
import re


def write_reports(root, output):
    module = next(line.split()[1] for line in (root / 'go.mod').read_text().splitlines()
                  if line.startswith('module '))
    profile = (output / 'all.out').read_text().splitlines(keepends=True)
    generated = {}
    source_lines, generated_lines = [profile[0]], [profile[0]]
    for line in profile[1:]:
        filename = line.split(':', 1)[0]
        if filename not in generated:
            if not filename.startswith(module + '/'):
                raise ValueError(f'coverage file is outside this module: {filename}')
            text = (root / filename[len(module) + 1:]).read_text()
            generated[filename] = bool(re.search(r'^// Code generated .* DO NOT EDIT\.$', text, re.M))
        (generated_lines if generated[filename] else source_lines).append(line)
    (output / 'source.out').write_text(''.join(source_lines))
    (output / 'generated.out').write_text(''.join(generated_lines))

    packages = []
    for line in (output.parent / 'tests.json').read_text().splitlines():
        event = json.loads(line)
        if not event.get('Test') and event.get('Action') in ('pass', 'fail', 'skip'):
            packages.append((event.get('Elapsed', 0), event['Package'], event['Action']))
    with (output / 'package-times.csv').open('w', newline='') as report:
        writer = csv.writer(report)
        writer.writerow(('package', 'status', 'elapsed_seconds'))
        for elapsed, name, status in sorted(packages, reverse=True):
            writer.writerow((name, status, elapsed))


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    write_reports(root, root / '.cache/ci/coverage')
