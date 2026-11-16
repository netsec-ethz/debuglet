#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Prepare or provision a fixed executor fleet. `plan` never calls Google Cloud."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


class FleetError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise FleetError(message)


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def validate(config):
    require(set(config) == {'project', 'fleet', 'operator', 'approved_monthly_budget_usd',
                            'image', 'machine_type', 'disk_gb', 'ssh_user', 'nodes'},
            'configuration fields must match fleet.example.json')
    patterns = {'project': r'[a-z][a-z0-9-]{4,28}[a-z0-9]',
                'fleet': r'[a-z][a-z0-9-]{0,30}[a-z0-9]',
                'machine_type': r'e2-(micro|small|medium|standard-[248])',
                'ssh_user': r'[a-z_][a-z0-9_-]{0,31}',
                'image': r'projects/[a-z0-9-]+/global/images/[a-z0-9-]+'}
    for key, pattern in patterns.items():
        require(isinstance(config[key], str) and re.fullmatch(pattern, config[key]),
                'invalid or missing ' + key)
    require(isinstance(config['operator'], str) and 0 < len(config['operator'].strip()) <= 200 and
            not config['operator'].startswith('CHOOSE_'),
            'set the responsible operator')
    budget = config['approved_monthly_budget_usd']
    require(type(budget) in (int, float) and 0 < budget < 100000,
            'set a positive approved_monthly_budget_usd; this is a record, not a spending limiter')
    require(type(config['disk_gb']) is int and 10 <= config['disk_gb'] <= 100,
            'disk_gb must be an integer between 10 and 100')
    nodes = config['nodes']
    require(isinstance(nodes, list) and 0 < len(nodes) <= 20, 'list between 1 and 20 fixed nodes')
    names = set()
    for node in nodes:
        require(isinstance(node, dict) and set(node) == {'name', 'zone', 'subnet'},
                'each node needs name, zone and subnet')
        require(isinstance(node['name'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,19}', node['name']),
                'invalid node name')
        require(node['name'] not in names, 'duplicate node name')
        names.add(node['name'])
        require(isinstance(node['zone'], str) and re.fullmatch(r'[a-z]+-[a-z]+[0-9]+-[a-z]', node['zone']),
                'invalid zone')
        region = node['zone'].rsplit('-', 1)[0]
        require(isinstance(node['subnet'], str) and re.fullmatch(
            r'projects/' + config['project'] + '/regions/' + region + r'/subnetworks/[a-z][a-z0-9-]+', node['subnet']),
            'subnet must name an existing subnet in the configured project and node region')
    return config


def save(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def command(config, *args):
    return ['gcloud', 'compute', *args, '--project=' + config['project'], '--quiet', '--format=json']


def cloud(config, *args):
    result = subprocess.run(command(config, *args), capture_output=True, text=True, timeout=300)
    require(result.returncode == 0,
            'gcloud ' + ' '.join(args[:2]) + ' failed; inspect cloud status before retrying (state retained)')
    return json.loads(result.stdout or 'null')


def lookup(config, kind, node):
    rows = cloud(config, kind, 'list', '--zones=' + node['zone'], '--filter=name=' + node['resource'])
    require(isinstance(rows, list), 'invalid cloud inventory response')
    rows = [row for row in rows if row.get('name') == node['resource']]
    require(len(rows) <= 1, 'ambiguous cloud identity')
    return rows[0] if rows else None


def owned(state, node, kind, resource):
    require(resource.get('labels', {}).get('debuglet-owner') == state['owner'],
            'refusing resource with different ownership: ' + node['resource'])
    ident = str(resource.get('id', ''))
    require(ident.isdigit(), 'missing provider resource ID')
    expected = node.get(kind + '_id')
    require(expected is None or expected == ident,
            'provider ID changed; refusing replacement: ' + node['resource'])
    return ident


def create_args(state, node, kind):
    config = state['config']
    labels = '--labels=debuglet-fleet=' + config['fleet'] + ',debuglet-owner=' + state['owner']
    common = [node['resource'], '--zone=' + node['zone'], labels]
    if kind == 'disks':
        image = config['image'].split('/')
        return ['disks', 'create', *common, '--image-project=' + image[1], '--image=' + image[-1],
                '--size=' + str(config['disk_gb']) + 'GB', '--type=pd-balanced']
    return ['instances', 'create', *common, '--machine-type=' + config['machine_type'],
            '--disk=name=' + node['resource'] + ',boot=yes,auto-delete=no',
            '--subnet=' + node['subnet'], '--stack-type=IPV4_ONLY', '--tags=debuglet-' + config['fleet'],
            '--no-service-account', '--no-scopes',
            '--metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE',
            '--maintenance-policy=MIGRATE', '--restart-on-failure']


def reconcile(state, path):
    config = state['config']
    for node in state['nodes']:
        for kind in ('disks', 'instances'):
            resource = lookup(config, kind, node)
            if resource is None:
                require(node.get(kind + '_id') is None,
                        'recorded resource disappeared; restore or destroy this fleet before recreating it')
                cloud(config, *create_args(state, node, kind))
                resource = lookup(config, kind, node)
                require(resource is not None, 'creation not confirmed; retry with the same state file')
            node[kind + '_id'] = owned(state, node, kind, resource)
            if kind == 'instances':
                disks = resource.get('disks', [])
                require(len(disks) == 1 and disks[0].get('boot') and
                        disks[0].get('source', '').endswith('/disks/' + node['resource']),
                        'unexpected attached disks; inspect before continuing')
                interfaces = resource.get('networkInterfaces', [])
                require(len(interfaces) == 1, 'expected one network interface')
                access = interfaces[0].get('accessConfigs', [])
                require(len(access) == 1 and access[0].get('natIP'), 'expected a public IPv4 address')
                node['address'] = access[0]['natIP']
            save(path, state)
    return {'all': {'children': {'executors': {'hosts': {
        node['resource']: {'ansible_host': node['address'], 'ansible_user': config['ssh_user'],
                           'executor_id': node['executor_id'], 'executor_public_host': node['address']}
        for node in state['nodes']}}}}}


def destroy(state, path):
    config = state['config']
    # Check every identity before making any deletion. Never delete by label alone.
    for node in state['nodes']:
        for kind in ('instances', 'disks'):
            resource = lookup(config, kind, node)
            if resource:
                # A create may have succeeded before its response timed out.
                # Recover its exact ID using this plan's private ownership token.
                node[kind + '_id'] = owned(state, node, kind, resource)
    save(path, state)
    for node in state['nodes']:
        for kind in ('instances', 'disks'):
            resource = lookup(config, kind, node)
            if resource:
                owned(state, node, kind, resource)
                args = [kind, 'delete', node['resource'], '--zone=' + node['zone']]
                if kind == 'instances':
                    args.append('--keep-disks=all')
                cloud(config, *args)
            require(lookup(config, kind, node) is None, 'deletion not confirmed; state retained')
    state['destroyed'] = True
    save(path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'apply', 'destroy'])
    parser.add_argument('--state', required=True, type=Path, help='private persistent JSON state outside Git')
    parser.add_argument('--config', type=Path, help='required only to prepare the offline plan')
    parser.add_argument('--confirm', help='project/fleet; apply costs money, destroy deletes VM disks')
    args = parser.parse_args()
    os.umask(0o077)
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not args.state.is_symlink(), 'state must not be a symlink')
    with open(str(args.state) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'plan':
            require(args.config is not None, 'plan requires --config')
            config = validate(load(args.config))
            if args.state.exists():
                state = load(args.state)
                require(state['config'] == config, 'state already binds another plan; do not edit a live plan')
            else:
                state = {'schema_version': 1, 'config': config, 'owner': uuid.uuid4().hex, 'nodes': [
                    dict(node, resource='dbg-' + config['fleet'] + '-' + node['name'], executor_id=str(uuid.uuid4()))
                    for node in config['nodes']]}
                save(args.state, state)
            require(not state.get('destroyed'), 'fleet was destroyed; use a new fleet name and state file')
            print(json.dumps({'offline': True, 'project': config['project'], 'operator': config['operator'],
                              'approved_monthly_budget_usd': config['approved_monthly_budget_usd'],
                              'budget_enforced': False, 'commands': [command(config, *create_args(state, node, kind))
                              for node in state['nodes'] for kind in ('disks', 'instances')]}, indent=2))
            return
        require(args.config is None, 'apply/destroy use the plan already recorded in --state')
        state = load(args.state)
        require(state.get('schema_version') == 1, 'unsupported state version')
        config = validate(state['config'])
        require(isinstance(state.get('owner'), str) and re.fullmatch(r'[0-9a-f]{32}', state['owner']),
                'invalid state ownership token')
        require(len(state['nodes']) == len(config['nodes']), 'state node count differs from plan')
        for node, planned in zip(state['nodes'], config['nodes']):
            require(all(node.get(key) == value for key, value in planned.items()) and
                    node.get('resource') == 'dbg-' + config['fleet'] + '-' + planned['name'],
                    'state node differs from recorded plan')
            require(str(uuid.UUID(node['executor_id'])) == node['executor_id'], 'invalid executor identity')
        require(args.confirm == config['project'] + '/' + config['fleet'], 'confirm must match project/fleet')
        if args.action == 'apply':
            require(not state.get('destroyed'), 'destroyed fleet cannot be recreated')
            print(json.dumps(reconcile(state, args.state), indent=2))
        else:
            destroy(state, args.state)
            print(json.dumps({'destroyed': True, 'nodes': len(state['nodes'])}))


if __name__ == '__main__':
    try:
        main()
    except (FleetError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        sys.exit('fleet: ' + str(error))
