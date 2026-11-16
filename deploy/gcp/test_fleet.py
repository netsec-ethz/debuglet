# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Offline cloud lifecycle regressions. No credentials or cloud calls are used."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fleet', Path(__file__).with_name('fleet.py'))
fleet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleet)


class Cloud:
    def __init__(self):
        self.rows = {'disks': {}, 'instances': {}}
        self.calls = []
        self.next_id = 100
        self.fail_create = False
        self.fail_list = False
        self.fail_delete = False

    def run(self, command, **kwargs):
        self.calls.append(command)
        assert command[:2] == ['gcloud', 'compute']
        assert '--project=test-project' in command
        assert kwargs['capture_output'] and kwargs['timeout'] == 300
        kind, action = command[2:4]
        def flag(prefix):
            return next(x[len(prefix):] for x in command if x.startswith(prefix))
        zone = flag('--zones=' if action == 'list' else '--zone=')
        if action == 'list':
            if self.fail_list:
                return SimpleNamespace(returncode=1, stdout='', stderr='permission denied')
            name = flag('--filter=name=')
            row = self.rows[kind].get((zone, name))
            result = [copy.deepcopy(row)] if row else []
        elif action == 'create':
            name = command[4]
            assert (zone, name) not in self.rows[kind]
            self.next_id += 1
            row = {'name': name, 'id': str(self.next_id),
                   'labels': dict(item.split('=', 1) for item in flag('--labels=').split(','))}
            if kind == 'instances':
                row['disks'] = [{'boot': True, 'source': f'projects/test-project/zones/{zone}/disks/{name}'}]
                row['networkInterfaces'] = [{'accessConfigs': [{'natIP': '192.0.2.10'}]}]
                assert '--disk=name=' + name + ',boot=yes,auto-delete=no' in command
                assert '--no-service-account' in command and '--no-scopes' in command
                assert '--stack-type=IPV4_ONLY' in command
            else:
                assert '--image-project=ubuntu-os-cloud' in command
                assert '--image=test-image' in command
            self.rows[kind][zone, name] = row
            if self.fail_create:
                self.fail_create = False
                raise subprocess.TimeoutExpired(command, 300)
            result = [row]
        elif action == 'delete':
            name = command[4]
            if kind == 'instances':
                assert '--keep-disks=all' in command
            del self.rows[kind][zone, name]
            if self.fail_delete:
                self.fail_delete = False
                raise subprocess.TimeoutExpired(command, 300)
            result = None
        else:
            raise AssertionError(action)
        return SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr='')


class FleetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state.json'
        self.config = {'project': 'test-project', 'fleet': 'research-01', 'operator': 'Test operator',
                       'approved_monthly_budget_usd': 50, 'image': 'projects/ubuntu-os-cloud/global/images/test-image',
                       'machine_type': 'e2-small', 'disk_gb': 20, 'ssh_user': 'research',
                       'nodes': [{'name': 'eu', 'zone': 'europe-west4-a',
                                  'subnet': 'projects/test-project/regions/europe-west4/subnetworks/research'}]}
        self.config_path = self.root / 'config.json'
        self.config_path.write_text(json.dumps(self.config))
        self.cloud = Cloud()
        self.mock = patch.object(fleet.subprocess, 'run', self.cloud.run)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def call(self, action, confirm=True):
        args = ['fleet', action, '--state', str(self.state)]
        if action == 'plan':
            args += ['--config', str(self.config_path)]
        elif confirm:
            args += ['--confirm', 'test-project/research-01']
        with patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO()) as output:
            fleet.main()
        return json.loads(output.getvalue())

    def test_offline_plan_is_stable_and_changed_plan_is_refused(self):
        first = self.call('plan')
        original = self.state.read_bytes()
        self.assertEqual(self.call('plan'), first)
        self.assertEqual(self.state.read_bytes(), original)
        self.assertEqual(self.cloud.calls, [])
        self.assertFalse(first['budget_enforced'])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.config['nodes'][0]['zone'] = 'europe-west4-b'
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(fleet.FleetError, 'another plan'):
            self.call('plan')

    def test_apply_is_idempotent_and_destroy_removes_only_recorded_fleet(self):
        self.call('plan')
        inventory = self.call('apply')
        hosts = inventory['all']['children']['executors']['hosts']
        self.assertEqual(hosts['dbg-research-01-eu']['ansible_host'], '192.0.2.10')
        identity = hosts['dbg-research-01-eu']['executor_id']
        self.assertEqual(self.call('apply'), inventory)
        self.assertEqual(len([c for c in self.cloud.calls if c[3] == 'create']), 2)
        self.cloud.rows['instances']['europe-west4-a', 'unrelated'] = {'id': '999'}
        self.assertTrue(self.call('destroy')['destroyed'])
        self.assertEqual(self.cloud.rows['disks'], {})
        self.assertEqual(list(self.cloud.rows['instances']), [('europe-west4-a', 'unrelated')])
        self.assertTrue(self.call('destroy')['destroyed'])
        self.assertEqual(fleet.load(self.state)['nodes'][0]['executor_id'], identity)
        with self.assertRaisesRegex(fleet.FleetError, 'destroyed'):
            self.call('apply')

    def test_creation_timeout_recovers_ownership_without_duplicate_allocation(self):
        self.call('plan')
        self.cloud.fail_create = True
        with self.assertRaises(subprocess.TimeoutExpired):
            self.call('apply')
        self.assertEqual(len(self.cloud.rows['disks']), 1)
        self.call('apply')
        self.assertEqual(len([c for c in self.cloud.calls if c[3] == 'create']), 2)

    def test_wrong_owner_and_replacement_ids_never_get_deleted(self):
        self.call('plan')
        self.call('apply')
        row = next(iter(self.cloud.rows['instances'].values()))
        row['id'] = '123456'
        with self.assertRaisesRegex(fleet.FleetError, 'ID changed'):
            self.call('destroy')
        self.assertFalse(any(c[3] == 'delete' for c in self.cloud.calls))
        row['id'] = fleet.load(self.state)['nodes'][0]['instances_id']
        row['labels']['debuglet-owner'] = 'other-owner'
        with self.assertRaisesRegex(fleet.FleetError, 'different ownership'):
            self.call('apply')
        with self.assertRaisesRegex(fleet.FleetError, 'different ownership'):
            self.call('destroy')
        self.assertFalse(any(c[3] == 'delete' for c in self.cloud.calls))

    def test_partial_creation_can_be_destroyed_without_creating_a_vm(self):
        self.call('plan')
        self.cloud.fail_create = True
        with self.assertRaises(subprocess.TimeoutExpired):
            self.call('apply')
        self.assertTrue(self.call('destroy')['destroyed'])
        self.assertFalse(self.cloud.rows['disks'])
        self.assertFalse(self.cloud.rows['instances'])
        self.assertEqual(len([c for c in self.cloud.calls if c[3] == 'create']), 1)

    def test_existing_name_with_another_owner_is_not_adopted(self):
        self.call('plan')
        self.cloud.rows['disks']['europe-west4-a', 'dbg-research-01-eu'] = {
            'name': 'dbg-research-01-eu', 'id': '999', 'labels': {'debuglet-owner': 'not-this-fleet'}}
        with self.assertRaisesRegex(fleet.FleetError, 'different ownership'):
            self.call('apply')
        with self.assertRaisesRegex(fleet.FleetError, 'different ownership'):
            self.call('destroy')
        self.assertFalse(any(c[3] in ('create', 'delete') for c in self.cloud.calls))

    def test_partial_deletion_can_be_retried(self):
        self.call('plan')
        self.call('apply')
        self.cloud.fail_delete = True
        with self.assertRaises(subprocess.TimeoutExpired):
            self.call('destroy')
        self.assertFalse(fleet.load(self.state).get('destroyed'))
        self.assertTrue(self.call('destroy')['destroyed'])
        self.assertFalse(self.cloud.rows['disks'])
        self.assertFalse(self.cloud.rows['instances'])

    def test_permission_errors_are_not_absence_and_confirmation_is_required(self):
        self.call('plan')
        with self.assertRaisesRegex(fleet.FleetError, 'confirm'):
            self.call('apply', confirm=False)
        self.assertEqual(self.cloud.calls, [])
        self.cloud.fail_list = True
        with self.assertRaisesRegex(fleet.FleetError, 'gcloud disks list failed'):
            self.call('apply')
        self.assertFalse(any(c[3] == 'create' for c in self.cloud.calls))

    def test_invalid_or_missing_budget_and_wrong_region_fail_before_cloud_access(self):
        for key, value in [('approved_monthly_budget_usd', None), ('approved_monthly_budget_usd', 0),
                           ('machine_type', 'a3-highgpu-8g')]:
            invalid = copy.deepcopy(self.config)
            invalid[key] = value
            with self.assertRaises(fleet.FleetError):
                fleet.validate(invalid)
        self.config['nodes'][0]['subnet'] = 'projects/test-project/regions/us-central1/subnetworks/research'
        with self.assertRaisesRegex(fleet.FleetError, 'subnet'):
            fleet.validate(self.config)
        self.assertEqual(self.cloud.calls, [])


if __name__ == '__main__':
    unittest.main()
