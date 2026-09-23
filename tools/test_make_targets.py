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
        self.script('deploy/scripts/generate-certs.sh', 'printf "%s\\n" "$@" > cert-ids')
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

    def certificates(self, inventory, **variables):
        (self.root / 'inventory.json').write_text(inventory)
        return self.make('deploy-certs', DISPATCHER_SANS='DNS:dispatcher.example.com',
                         ANSIBLE_INVENTORY=self.inventory, ANSIBLE_PLAYBOOK=self.playbook,
                         **variables)

    def assert_no_deployment(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'cert-ids').exists())
        self.assertFalse((self.root / 'playbook-called').exists())

    def test_inventory_direct_nested_and_shared_hosts(self):
        result = self.certificates(json.dumps({
            'executors': {'hosts': ['direct'], 'children': ['first', 'second']},
            'first': {'hosts': ['direct', 'nested'], 'children': ['leaf']},
            'second': {'children': ['leaf']},
            'leaf': {'hosts': ['fallback']},
            'dispatcher': {'hosts': ['unrelated']},
            '_meta': {'hostvars': {'direct': {'executor_id': 'id-1'},
                                   'nested': {'executor_id': 'id-2'}}},
        }))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'cert-ids').read_text(), 'id-1\nid-2\nfallback\n')
        self.assertTrue((self.root / 'playbook-called').exists())

    def test_inventory_failure_even_with_valid_stdout(self):
        self.inventory = self.script('inventory', 'echo \'{"executors": {}}\'; exit 7')
        result = self.certificates('')
        self.assert_no_deployment(result)
        self.assertIn('Could not read Ansible inventory', result.stderr)

    def test_invalid_inventory(self):
        for inventory in ('not JSON', '{}', '{"executors":{"children":["missing"]}}',
                          '{"executors":{"hosts":"not a list"}}'):
            with self.subTest(inventory=inventory):
                result = self.certificates(inventory)
                self.assert_no_deployment(result)
                self.assertIn('Cannot extract executor IDs', result.stderr)

    def test_explicit_ids_bypass_inventory(self):
        self.inventory = str(self.root / 'missing-command')
        result = self.certificates('', EXECUTOR_IDS='explicit-1 explicit-2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'cert-ids').read_text(), 'explicit-1\nexplicit-2\n')
        self.assertTrue((self.root / 'playbook-called').exists())

    def test_certificate_inventory_and_install_use_selected_environment(self):
        result = self.certificates('{"executors":{"hosts":["selected"]}}',
                                   INVENTORY='hosts.dev.yml', DEPLOY_ENV='dev')
        self.assertEqual(result.returncode, 0, result.stderr)
        for output in ('inventory-args', 'playbook-called'):
            self.assertEqual((self.root / output).read_text().splitlines()[:4],
                             ['-i', 'hosts.dev.yml', '-e', '@vars/dev.yml'])

    def test_deployment_commands_use_selected_environment(self):
        for target in ('deploy', 'deploy-dispatcher', 'deploy-executors',
                       'bootstrap-sudo', 'deploy-update-addr', 'deploy-update-config'):
            with self.subTest(target=target):
                result = subprocess.run(
                    ['make', '--no-print-directory', '-s', '-o', 'deploy-build',
                     '-o', 'deploy-seed-db', target, 'INVENTORY=hosts.dev.yml',
                     'DEPLOY_ENV=dev', f'ANSIBLE_PLAYBOOK={self.playbook}'],
                    cwd=self.root, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.root / 'playbook-called').read_text().splitlines()[:4],
                                 ['-i', 'hosts.dev.yml', '-e', '@vars/dev.yml'])


if __name__ == '__main__':
    unittest.main()
