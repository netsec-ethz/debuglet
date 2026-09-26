#!/usr/bin/env bash
# Check that one unreachable executor does not end the deployment of the rest.
#
# deploy-executors.yml deploys one host at a time (serial: 1) and keeps an
# unreachable host in the play (ignore_unreachable). Its inspections then
# register no result, and a check that runs on the controller would fail the
# host on the missing result, which under serial: 1 ends the play for every
# later host. This runs the executor role's own inspection tasks
# (roles/executor/tasks/inspect.yml) against an unreachable host followed by a
# reachable one: this machine over the local connection, inspecting a
# temporary directory. Nothing is deployed and no managed host is contacted.
#
# Checked:
#   1. the unreachable host is ended cleanly, reported as not deployed and not
#      failed,
#   2. the reachable host after it runs to the end, through a controller-side
#      check that reads the inspections as the role's checks do,
#   3. without the guard the same play ends at the unreachable host, so the
#      checks above are actually testing it.
#
# Usage: deploy/test/unreachable-host.sh

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
inspect=$root/deploy/ansible/roles/executor/tasks/inspect.yml
failures=0

for tool in ansible-playbook python3; do
	command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-unreachable.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT INT TERM

check() {
	local name=$1 outcome=$2
	if [ "$outcome" = pass ]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name" >&2
		failures=$((failures + 1))
	fi
}

# The unreachable host is an SSH connection to a loopback port nothing
# listens on, which is refused at once. The port is one the kernel just handed
# out and took back, so no service can be listening on it.
closed_port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
cat >"$work/inventory.yml" <<EOF
all:
  hosts:
    unreachable:
      ansible_host: 127.0.0.1
      ansible_port: $closed_port
      ansible_ssh_common_args: "-o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    reachable:
      ansible_connection: local
      ansible_python_interpreter: "{{ ansible_playbook_python }}"
EOF

# Everything after the guard's comment is the guard.
sed '/^# A host that stops answering mid-play/,$d' "$inspect" >"$work/inspect-unguarded.yml"

play() {
	local tasks=$1 name=$2
	cat >"$work/play-$name.yml" <<EOF
- hosts: unreachable:reachable
  serial: 1
  ignore_unreachable: true
  gather_facts: false
  vars:
    executor_state_dir: $work/state
    executor_config_dir: $work/config
    executor_legacy_config_dir: $work/legacy-config
    executor_legacy_state_dir: $work/legacy-state
    systemd_unit_dir: $work/units
    executor_legacy_service: debuglet-executor
  tasks:
    - ansible.builtin.import_tasks: $tasks
    - name: Read the inspections as the role's checks do
      ansible.builtin.assert:
        that:
          - not executor_legacy_unit.stat.exists or not executor_db.stat.exists
          - executor_previous_databases.results | map(attribute='stat') | list | length == 3
        quiet: true
    - name: Report the end of the play
      ansible.builtin.debug:
        msg: "reached the end on {{ inventory_hostname }}"
EOF
	ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i "$work/inventory.yml" "$work/play-$name.yml" \
		</dev/null >"$work/$name.log" 2>&1 || true
}

recap() {
	sed -n '/PLAY RECAP/,$p' "$1" | grep -E "^$2 +:" || true
}

play "$inspect" guarded
if grep -q 'unreachable did not answer its inspection and is not deployed' "$work/guarded.log" &&
	recap "$work/guarded.log" unreachable | grep -q 'failed=0' &&
	! grep -q 'reached the end on unreachable' "$work/guarded.log"; then
	check 'the unreachable host is ended cleanly and reported as not deployed' pass
else
	check 'the unreachable host is ended cleanly and reported as not deployed' fail
	tail -30 "$work/guarded.log" >&2
fi
if grep -q 'reached the end on reachable' "$work/guarded.log" &&
	recap "$work/guarded.log" reachable | grep -q 'failed=0'; then
	check 'the reachable host after it is deployed to the end' pass
else
	check 'the reachable host after it is deployed to the end' fail
	tail -30 "$work/guarded.log" >&2
fi

play "$work/inspect-unguarded.yml" unguarded
if ! grep -q 'reached the end on reachable' "$work/unguarded.log" &&
	recap "$work/unguarded.log" unreachable | grep -q 'failed=1'; then
	check 'without the guard the unreachable host ends the play' pass
else
	check 'without the guard the unreachable host ends the play' fail
	tail -30 "$work/unguarded.log" >&2
fi

if [ "$failures" -ne 0 ]; then
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi
