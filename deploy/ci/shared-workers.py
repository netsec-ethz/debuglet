#!/usr/bin/env python3
"""Run only the shared-worker witnesses inside this transient delegated unit."""

import json
import os
from pathlib import Path
import subprocess
import sys


def run(unit):
    evidence = Path('.cache/ci/ci-image-evidence/shared-workers').resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    paths = [line[3:] for line in membership if line.startswith('0::/')]
    if len(paths) != 1 or Path(paths[0]).name != unit:
        raise RuntimeError('test driver must run in its own delegated systemd unit')
    root = Path('/sys/fs/cgroup') / paths[0].lstrip('/')
    (evidence / 'cgroup-path.txt').write_text(str(root) + '\n')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    if int(status['CapEff'].strip(), 16) != 0 or status['NoNewPrivs'].strip() != '1':
        raise RuntimeError('test driver must have no effective capabilities and no privilege escalation')
    if (root / 'cgroup.procs').read_text().split() != [str(os.getpid())]:
        raise RuntimeError('delegation contains a process other than this test driver')
    limits = {name: (root / name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
    quota, period = limits['cpu.max'].split()
    if (not 0 < int(limits['memory.max']) <= 5 * (1 << 30)
            or limits['memory.swap.max'] != '0' or not 0 < int(quota) <= 3 * int(period)
            or not 0 < int(limits['pids.max']) <= 512):
        raise RuntimeError('test delegation is missing its finite resource limits')
    # cgroup-v2 controllers require an empty internal node. Move only this
    # unit's driver into a leaf; the test supervisors create sibling groups.
    driver = root / 'driver'
    driver.mkdir()
    (driver / 'cgroup.procs').write_text(str(os.getpid()))
    (root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    env = {'PATH': '/usr/bin:/bin', 'GOMAXPROCS': '3', 'DEBUGLET_TEST_CGROUP_ROOT': str(root)}
    checkout = Path.cwd()
    binaries = checkout / '.cache/ci/shared-workers'
    tests = {
        'debuglet': [
            'TestSharedWorkerLimitsAndDisposal', 'TestSharedCompilerAdmissionAndJoin',
            'TestSharedWorkerCancellationAndSibling', 'TestSharedCompilerDeadlineDisposesWorker',
            'TestSharedWorkerKernelMemoryBudget', 'TestWorkerRejectsUnavailableImports',
            'TestSharedWorkerRejectsInvalidMemoryRanges',
        ],
        'executor': [
            'TestSharedSocketQuotaKeepsRealGuestAndControlResponsive',
            'TestSharedGuestReceivesCopiedBytesAndEOF',
            'TestSharedCompilerBudgetKeepsGuestAndControlResponsive',
            'TestSharedMemoryBudgetKeepsGuestAndControlResponsive',
        ],
    }
    all_events = []
    for name, required in tests.items():
        relative = 'internal/executor' + ('/debuglet' if name == 'debuglet' else '')
        package = 'github.com/netsec-ethz/debuglet/' + relative
        result_path = evidence / (name + '.json')
        with result_path.open('w', encoding='utf-8') as output:
            result = subprocess.run(
                [str(binaries / 'test2json'), '-t', '-p', package, str(binaries / (name + '.test')),
                 '-test.v=test2json', '-test.count=1', '-test.timeout=90s',
                 '-test.run=^(TestShared|TestWorkerRejectsUnavailableImports$)'],
                cwd=checkout / relative, env=env, stdout=output, stderr=subprocess.STDOUT,
                timeout=100, check=False)
        events = [json.loads(line) for line in result_path.read_text().splitlines() if line.strip()]
        all_events.extend(events)
        passed = {event.get('Test') for event in events if event.get('Action') == 'pass'}
        skipped = [event.get('Test') for event in events if event.get('Action') == 'skip']
        missing = set(required) - passed
        if result.returncode or skipped or missing:
            raise RuntimeError(f'{name}: status={result.returncode}, skipped={skipped}, missing={sorted(missing)}')
        print(f'{name}: all {len(required)} shared-worker witnesses passed without skips.', flush=True)
    remaining = sorted(path.name for path in root.iterdir() if path.is_dir() and path != driver)
    driver_pids = (driver / 'cgroup.procs').read_text().split()
    if remaining or driver_pids != [str(os.getpid())]:
        raise RuntimeError(f'workers did not join: cgroups={remaining}, driver_pids={driver_pids}')
    with Path('.cache/ci/kernel-tests.json').open('a', encoding='utf-8') as output:
        for event in all_events:
            output.write(json.dumps(event) + '\n')
    (evidence / 'summary.json').write_text(json.dumps({
        'unit': unit, 'limits': limits, 'passed': sum(map(len, tests.values())),
        'effective_capabilities': 0, 'no_new_privileges': True,
        'skipped': 0, 'remaining_worker_cgroups': remaining, 'driver_pids': driver_pids,
    }, indent=2) + '\n')


if __name__ == '__main__':
    run(sys.argv[1])
