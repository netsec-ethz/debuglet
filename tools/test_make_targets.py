"""Exercise Make recipes with stub compilers and deployment commands."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[1]
LANGUAGES = {'rust': ('Cargo.toml', 'CARGO'), 'go': ('main.go', 'GO'),
             'c': ('main.c', 'CLANG'), 'js': ('main.js', 'JAVY')}


class MakeTargetsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='debuglet-make-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'deploy/ansible').mkdir(parents=True)
        (self.root / 'deploy/scripts').mkdir()
        for name in ('Makefile', 'deploy/scripts/executor-ids.py'):
            shutil.copyfile(REPOSITORY / name, self.root / name)
        self.controller = self.script(
            'deploy/debuglet-deploy', 'printf "%s\\n" "$@" > deploy-called')
        self.inventory = self.script('inventory', 'printf "%s\\n" "$@" > ../../inventory-args; cat "$(dirname "$0")/inventory.json"')
        self.playbook = self.script('playbook', 'printf "%s\\n" "$@" > ../../playbook-called')

    def script(self, name, body):
        path = self.root / name
        path.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
        path.chmod(0o755)
        return str(path)

    def make(self, target, **variables):
        return subprocess.run(['make', '--no-print-directory', '-s', target,
                               *(f'{key}={value}' for key, value in variables.items())],
                              cwd=self.root, text=True, capture_output=True, timeout=10)

    def sample(self, language):
        directory = self.root / language
        directory.mkdir()
        (directory / LANGUAGES[language][0]).touch()
        (directory / 'debuglet.wasm').write_text('old')
        return directory

    def test_wasm_compiler_failures(self):
        compiler = self.script('compiler', 'echo compiler-failed >&2; exit 7')
        for language, (_, variable) in LANGUAGES.items():
            with self.subTest(language=language):
                sample = self.sample(language)
                result = self.make('wasm', SAMPLE_DIR=sample, **{variable: compiler})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('compiler-failed', result.stderr)
                self.assertNotIn('wrote ', result.stdout)
                self.assertEqual((sample / 'debuglet.wasm').read_text(), 'old')

    def test_wasm_success(self):
        compiler = self.script('compiler', '''
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then printf new > "$2"; exit 0; fi
    shift
done
mkdir -p target/wasm32-wasip1/release
printf new > target/wasm32-wasip1/release/debuglet.wasm''')
        for language, (_, variable) in LANGUAGES.items():
            with self.subTest(language=language):
                sample = self.sample(language)
                result = self.make('wasm', SAMPLE_DIR=sample, RUST_TARGET='wasm32-wasip1',
                                   **{variable: compiler})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'wrote {sample}/debuglet.wasm', result.stdout)
                self.assertEqual((sample / 'debuglet.wasm').read_text(), 'new')

    def test_rust_copy_failure(self):
        sample = self.sample('rust')
        result = self.make('wasm', SAMPLE_DIR=sample, CARGO=self.script('cargo', 'exit 0'))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('wrote ', result.stdout)
        self.assertEqual((sample / 'debuglet.wasm').read_text(), 'old')

    def test_inventory_direct_nested_and_shared_hosts(self):
        inventory = json.dumps({
            'executors': {'hosts': ['direct'], 'children': ['first', 'second']},
            'first': {'hosts': ['direct', 'nested'], 'children': ['leaf']},
            'second': {'children': ['leaf']},
            'leaf': {'hosts': ['fallback']},
            'dispatcher': {'hosts': ['dispatcher']},
            '_meta': {'hostvars': {'direct': {'executor_id': 'id-1'},
                                   'nested': {'executor_id': 'id-2'},
                                   'dispatcher': {'dispatcher_addr': 'dispatcher.example.com',
                                                  'dispatcher_tls_sans': ['DNS:proxy.internal']}}},
        })
        result = subprocess.run(
            ['python3', 'deploy/scripts/executor-ids.py'], cwd=self.root,
            input=inventory, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'id-1 id-2 fallback\n')
        for option, expected in (('--dispatcher-addr', 'dispatcher.example.com\n'),
                                 ('--dispatcher-tls-sans', 'DNS:proxy.internal\n')):
            selected = subprocess.run(
                ['python3', 'deploy/scripts/executor-ids.py', option], cwd=self.root,
                input=inventory, text=True, capture_output=True, timeout=10)
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(selected.stdout, expected)

    def test_invalid_inventory(self):
        for inventory in ('not JSON', '{}', '{"executors":{"children":["missing"]}}',
                          '{"executors":{"hosts":"not a list"}}'):
            with self.subTest(inventory=inventory):
                result = subprocess.run(
                    ['python3', 'deploy/scripts/executor-ids.py'], cwd=self.root,
                    input=inventory, text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot extract executor IDs', result.stderr)

    def test_deployment_controller_receives_selected_environment_and_action(self):
        result = self.make('deploy-certs', DEPLOY_ENV='dev')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'deploy-called').read_text().splitlines(),
                         ['dev', 'certs'])

    def test_deployment_commands_use_selected_environment(self):
        for target, action in (('deploy', 'all'), ('deploy-dispatcher', 'dispatcher'),
                               ('deploy-executors', 'executors')):
            with self.subTest(target=target, action=action):
                result = subprocess.run(
                    ['make', '--no-print-directory', '-s', '-o', 'deploy-build',
                     '-o', 'deploy-seed-db', target, 'DEPLOY_ENV=dev'],
                    cwd=self.root, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'deploy-called').read_text().splitlines(),
                                 ['dev', action])

    def test_playbook_maintenance_commands_use_selected_environment(self):
        for target in ('bootstrap-sudo', 'deploy-update-addr', 'deploy-update-config'):
            with self.subTest(target=target):
                result = self.make(target, INVENTORY='hosts.dev.yml', DEPLOY_ENV='dev',
                                   ANSIBLE_PLAYBOOK=self.playbook)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'playbook-called').read_text().splitlines()[:4],
                                 ['-i', 'hosts.dev.yml', '-e', '@vars/dev.yml'])

    def test_database_upgrade_uses_selected_environment(self):
        for environment, inventory, known_hosts in (('dev', 'hosts.dev.yml', 'known_hosts.dev'),
                                                    ('prod', 'hosts.yml', 'known_hosts')):
            with self.subTest(environment=environment):
                result = self.make('deploy-upgrade-db', DEPLOY_ENV=environment,
                                   ANSIBLE_PLAYBOOK=self.playbook)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'playbook-called').read_text().splitlines()[:7],
                                 ['-i', inventory, '-e', f'@vars/{environment}.yml', '-e',
                                  f'known_hosts_file={{{{ playbook_dir }}}}/{known_hosts}',
                                  'upgrade-database.yml'])

    def test_database_upgrade_requires_an_environment(self):
        result = self.make('deploy-upgrade-db', ANSIBLE_PLAYBOOK=self.playbook)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('DEPLOY_ENV must be dev or prod', result.stderr)
        self.assertFalse((self.root / 'playbook-called').exists())


if __name__ == '__main__':
    unittest.main()
