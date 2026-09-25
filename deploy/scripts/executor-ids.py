#!/usr/bin/env python3
"""Print executor IDs from ansible-inventory --list JSON on stdin."""
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


if __name__ == '__main__':
    try:
        print(' '.join(executor_ids(json.load(sys.stdin))))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        sys.exit(f'Cannot extract executor IDs from Ansible inventory: {error}')
