"""Serial-promotion checks with real Ansible/signatures and fixture services.

Run inside the pinned provisioner, without network access or managed hosts:
    python3 -m unittest deploy.test.test_rollout -v
The service manager, package payload and measurement client are local fixtures;
this suite does not establish deployment or real-release acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

import yaml
from tools import test_release_retention as retention_tests
from tools.test_release_inventory import VERSION, SOURCE

ROOT = Path(__file__).resolve().parents[2]
SYSTEMCTL = r'''#!PYTHON
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
name = next((x for x in args if x.startswith('fixture-')), 'fixture-canary')
root = Path(os.environ['ROLLOUT_FIXTURE'])
state = root / (name + '.active')
active = not state.exists() or state.read_text() == 'yes'
if '--version' in args:
    print('systemd 252'); sys.exit(0)
if 'stop' in args or 'start' in args:
    action = 'stop' if 'stop' in args else 'start'
    state.write_text('yes' if action == 'start' else 'no')
    with (root / 'trace').open('a') as f: f.write(action + ' ' + name + '\n')
    sys.exit(0)
if 'is-active' in args:
    print('active' if active else 'inactive'); sys.exit(0 if active else 3)
if 'is-enabled' in args:
    print('enabled'); sys.exit(0)
print('LoadState=loaded\nUnitFileState=enabled\nNeedDaemonReload=no\nResult=success\nExecMainStatus=0')
print('ActiveState=' + ('active' if active else 'inactive'))
print('SubState=' + ('running' if active else 'dead'))
'''
INSTALLER = r'''#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) prefix=$2; shift 2;;
    --version) version=$2; shift 2;;
    --stage-only) shift;;
    *) shift 2;;
  esac
done
printf '%s\n' "$prefix" >> "$ROLLOUT_FIXTURE/installers"
[ ! -f "$prefix/lib/debuglet/$version/bad-tree" ] || exit 18
mkdir -p "$prefix/lib/debuglet/$version/bin" "$prefix/lib/debuglet/$version/share/debuglet" "$prefix/bin"
printf '{}\n' > "$prefix/lib/debuglet/$version/share/debuglet/manifest.json"
printf '#!/bin/sh\n[ ! -f "%s/incompatible" ]\n' "$ROLLOUT_FIXTURE" > "$prefix/lib/debuglet/$version/bin/debuglet-executor"
chmod 755 "$prefix/lib/debuglet/$version/bin/debuglet-executor"
cp "$prefix/lib/debuglet/$version/bin/debuglet-executor" "$prefix/lib/debuglet/$version/bin/debuglet-dispatcher"
'''
CLIENT = r'''#!PYTHON
import json, os, sys
from pathlib import Path
root = Path(os.environ['ROLLOUT_FIXTURE'])
args = sys.argv[1:]
if args[-1] == 'nodes':
    print(json.dumps([{'id': n, 'ready': True, 'version': os.environ['ROLLOUT_VERSION']} for n in ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')]))
else:
    node = args[args.index('--executor') + 1]
    with (root / 'trace').open('a') as f: f.write('measure ' + node + '\n')
    if (root / 'fail-measurement').exists(): sys.exit(3)
    print(json.dumps({'id': '33333333-3333-4333-8333-333333333333', 'executor_id': node, 'state': 'RunStateExited'}))
'''


class RolloutTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which('ansible-playbook'), 'run in the pinned provisioner')
        self.fixture = retention_tests.RetentionTests('test_evidence_is_signed_and_survives_source_artifact_removal')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.work = self.fixture.archive / 'rollout'
        self.work.mkdir()
        self.playbooks = self.work / 'ansible'
        shutil.copytree(ROOT / 'deploy/ansible', self.playbooks)
        # Only local service behavior is substituted. The complete preflight,
        # real payload role, release audit, SSH signatures and backup tasks run.
        shutil.copytree(ROOT / 'tools', self.work.parent / 'tools', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT / 'deploy/provisioner.env', self.work / 'provisioner.env')
        # payload's audit path is relative to playbook_dir/../../tools.
        for name, code in [('systemctl', SYSTEMCTL), ('client', CLIENT)]:
            p = self.work / name
            p.write_text(code.replace('PYTHON', sys.executable, 1)); p.chmod(0o755)
        Path('/run/systemd/system').mkdir(parents=True, exist_ok=True)
        (self.fixture.directory / 'install.sh').write_text(INSTALLER)
        sums = self.fixture.directory / 'SHA256SUMS'
        lines = sums.read_text().splitlines()
        lines[1] = hashlib.sha256(INSTALLER.encode()).hexdigest() + '  install.sh'
        sums.write_text('\n'.join(lines) + '\n')
        self.fixture.inventory.generate()
        self.fixture.signed()
        (self.work / 'known_hosts').write_text('fixture ssh-ed25519 AAAAFIXTURE\n')
        (self.work / 'client.json').write_text('{}')
        hosts = {}
        for name, ident in [('canary', '11111111-1111-4111-8111-111111111111'),
                            ('second', '22222222-2222-4222-8222-222222222222')]:
            host = self.work / name
            (host / 'state/executor-dev').mkdir(parents=True)
            (host / 'config/executor-dev').mkdir(parents=True)
            (host / 'state/executor-dev/executor.db').write_text('unchanged fixture state')
            (host / 'config/executor-dev/executor.toml').write_text('[identity]\nversion = "previous"\n')
            (host / 'config/deployment-dev.json').write_text(json.dumps({'application': {'version': 'previous'}}))
            hosts[name] = {'executor_id': ident, 'executor_service': 'fixture-' + name,
                           'payload_prefix': str(host / 'prefix'), 'config_dir': str(host / 'config'),
                           'state_dir': str(host / 'state'), 'log_dir': str(host / 'log'),
                           'payload_staging_dir': str(host / 'staging'), 'systemd_unit_dir': str(host / 'units')}
        (self.work / 'inventory.yml').write_text(yaml.safe_dump({'all': {'children': {'executors': {'hosts': hosts}}}}, sort_keys=False))
        settings = {'ansible_connection': 'local', 'ansible_become': False,
                    'ansible_python_interpreter': sys.executable, 'debuglet_env': 'dev',
                    'known_hosts_file': str(self.work / 'known_hosts'), 'dispatcher_addr': '127.0.0.1', 'executor_disable_tls': True, 'dispatcher_disable_tls': True,
                    'executor_user': 'root', 'executor_group': 'root', 'debuglet_group': 'root', 'executor_interface': 'lo',
                    'executor_enable_bpf': False,
                    'dist_dir': str(self.fixture.directory), 'deploy_version': VERSION, 'release_source_sha': SOURCE,
                    'release_trust_file': str(self.fixture.trust), 'release_signer': 'fixture',
                    'rollout_confirm': 'dev:' + VERSION + ':' + SOURCE, 'rollout_canary': 'canary',
                    'rollout_operator': 'fixture operator', 'rollout_cli': str(self.work / 'client'),
                    'rollout_client_config': str(self.work / 'client.json')}
        (self.work / 'settings.yml').write_text(yaml.safe_dump(settings))
        self.env = dict(os.environ, PATH=str(self.work) + os.pathsep + os.environ['PATH'],
                        ROLLOUT_FIXTURE=str(self.work), ROLLOUT_VERSION=VERSION, ANSIBLE_NOCOLOR='1')

    def run_rollout(self):
        p = subprocess.run(['ansible-playbook', '-i', str(self.work / 'inventory.yml'),
                            '-e', '@' + str(self.work / 'settings.yml'), 'rollout-executors.yml'],
                           cwd=self.playbooks, env=self.env, text=True, capture_output=True, timeout=180)
        return p, (self.work / 'trace').read_text().splitlines() if (self.work / 'trace').exists() else []

    def test_serial_success_records_verified_backups_and_measurements(self):
        p, trace = self.run_rollout()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(trace, ['stop fixture-canary', 'start fixture-canary',
                                'measure 11111111-1111-4111-8111-111111111111',
                                'stop fixture-second', 'start fixture-second',
                                'measure 22222222-2222-4222-8222-222222222222'])
        for host in ('canary', 'second'):
            record = next((self.work / host / 'state').glob('rollout-backup-*/rollout.json'))
            row = json.loads(record.read_text())
            self.assertEqual(row['status'], 'verified')
            self.assertTrue(row['drain_joined'])
            for name, digest in row['backup_sha256'].items():
                self.assertEqual(hashlib.sha256((record.parent / (name + '.tar')).read_bytes()).hexdigest(), digest)

    def test_failed_canary_measurement_never_touches_second_host(self):
        (self.work / 'fail-measurement').touch()
        p, trace = self.run_rollout()
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('measure 11111111-1111-4111-8111-111111111111', trace, p.stdout + p.stderr)
        self.assertFalse((self.work / 'second/prefix').exists())
        self.assertEqual(json.loads((self.work / 'second/config/deployment-dev.json').read_text())['application']['version'], 'previous')

    def test_incompatible_schema_is_refused_before_stopping_current_service(self):
        (self.work / 'incompatible').touch()
        p, trace = self.run_rollout()
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('Refuse a release incompatible with the current schema', p.stdout)
        self.assertEqual(trace, [])
        self.assertFalse((self.work / 'second/prefix').exists())

    def test_existing_candidate_is_reverified_before_execution(self):
        candidate = self.work / 'canary/prefix/lib/debuglet' / VERSION
        (candidate / 'share/debuglet').mkdir(parents=True)
        (candidate / 'share/debuglet/manifest.json').write_text('{}')
        (candidate / 'bad-tree').touch()
        p, trace = self.run_rollout()
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual((self.work / 'installers').read_text().splitlines(), [str(self.work / 'canary/prefix')])
        self.assertEqual(trace, [])
        self.assertFalse((self.work / 'second/prefix').exists())

    def test_missing_required_capabilities_stop_before_drain(self):
        settings = self.work / 'settings.yml'
        value = yaml.safe_load(settings.read_text()); value['executor_enable_bpf'] = True
        settings.write_text(yaml.safe_dump(value))
        for name, code in [('getcap', '#!/bin/sh\nexit 0\n'), ('setcap', '#!/bin/sh\nexit 1\n')]:
            path = self.work / name; path.write_text(code); path.chmod(0o755)
        p, trace = self.run_rollout()
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Preserve the executor's required kernel capabilities", p.stdout)
        self.assertEqual(trace, [])
        self.assertFalse((self.work / 'second/prefix').exists())


if __name__ == '__main__':
    unittest.main()
