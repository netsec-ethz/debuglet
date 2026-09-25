#!/usr/bin/env python3
"""Read deployment values from ansible-inventory --list JSON on stdin."""
import argparse
import json
import sys


def executor_ids(inventory):
    hosts, visited = {}, set()
    pending = ['executors']
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        group = inventory[name]
        for field in ('hosts', 'children'):
            entries = group.get(field, [])
            if not isinstance(entries, list) or not all(isinstance(n, str) for n in entries):
                raise ValueError(f'{name}.{field} must be a list of names')
        hosts.update(dict.fromkeys(group.get('hosts', [])))
        pending.extend(reversed(group.get('children', [])))
    hostvars = inventory.get('_meta', {}).get('hostvars', {})
    return [hostvars.get(host, {}).get('executor_id', host) for host in hosts]


def dispatcher_addr(inventory):
    hostvars = inventory.get('_meta', {}).get('hostvars', {})
    dispatchers = inventory.get('dispatcher', {}).get('hosts', [])
    if not dispatchers:
        raise ValueError('dispatcher group has no hosts')
    value = hostvars.get(dispatchers[0], {}).get('dispatcher_addr')
    if not isinstance(value, str) or not value:
        raise ValueError('dispatcher_addr is not set in inventory')
    return value


def dispatcher_tls_sans(inventory):
    hostvars = inventory.get('_meta', {}).get('hostvars', {})
    dispatchers = inventory.get('dispatcher', {}).get('hosts', [])
    if not dispatchers:
        raise ValueError('dispatcher group has no hosts')
    value = hostvars.get(dispatchers[0], {}).get('dispatcher_tls_sans', [])
    if not isinstance(value, list) or not all(isinstance(san, str) and san for san in value):
        raise ValueError('dispatcher_tls_sans must be a list of non-empty strings')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dispatcher-addr', action='store_true')
    parser.add_argument('--dispatcher-tls-sans', action='store_true')
    args = parser.parse_args()
    try:
        inventory = json.load(sys.stdin)
        if args.dispatcher_addr:
            print(dispatcher_addr(inventory))
        elif args.dispatcher_tls_sans:
            print(' '.join(dispatcher_tls_sans(inventory)))
        else:
            print(' '.join(executor_ids(inventory)))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        sys.exit(f'Cannot extract executor IDs from Ansible inventory: {error}')
