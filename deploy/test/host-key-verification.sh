#!/usr/bin/env bash
# Check that a deployment connection accepts only a pinned SSH host identity.
#
# This starts a throwaway SSH server on a loopback port with a host key
# generated for this run, then connects to it with the same options the
# deployment configuration pins. The test host exists only for the duration of
# the run: it is not in any inventory, it is never deployed to, and the real
# managed hosts are not contacted.
#
# Checked:
#   1. an unknown host key is refused before authentication,
#   2. the correct pinned key reaches authentication,
#   3. a changed key on a pinned host is refused,
#   4. replacing that entry with the key read from the host's own public key
#      file — the documented rotation path — is accepted again,
#   5. permissive checking would have accepted the unknown key, so the checks
#      above are actually testing the pinning,
#   6. no deployment configuration, make target or pipeline job disables host
#      verification or trusts a scanned key.
#
# Usage: deploy/test/host-key-verification.sh [PORT]

set -euo pipefail

port=${1:-42222}
host=127.0.0.1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
sshd=${DEBUGLET_TEST_SSHD:-/usr/sbin/sshd}
failures=0

for tool in ssh ssh-keygen; do
	command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }
done
[ -x "$sshd" ] || { echo "missing sshd at $sshd; set DEBUGLET_TEST_SSHD" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-host-key.XXXXXXXX")
server_pid=

cleanup() {
	[ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
	rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

check() {
	local name=$1 outcome=$2
	if [ "$outcome" = pass ]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name" >&2
		failures=$((failures + 1))
	fi
}

# connect runs one ssh attempt with the pinned options and prints its
# diagnostics. Authentication is expected to fail: this test is about which
# host the client is willing to talk to, not about logging in.
connect() {
	local known_hosts=$1 strict=${2:-yes}
	ssh -F /dev/null \
		-o "StrictHostKeyChecking=$strict" \
		-o "UserKnownHostsFile=$known_hosts" \
		-o GlobalKnownHostsFile=/dev/null \
		-o HashKnownHosts=no \
		-o HostKeyAlgorithms=ssh-ed25519 \
		-o PreferredAuthentications=none \
		-o BatchMode=yes \
		-o ConnectTimeout=10 \
		-p "$port" "$host" true 2>&1 || true
}

# The pinned identity is read from the server's own public key file, the way a
# real host key is provisioned. Nothing here scans the network for a key.
entry() {
	printf '[%s]:%s %s\n' "$host" "$port" "$(cut -d' ' -f1,2 <"$1")"
}

ssh-keygen -q -t ed25519 -N '' -C debuglet-test-host -f "$work/host_key"
ssh-keygen -q -t ed25519 -N '' -C debuglet-test-other -f "$work/other_key"

"$sshd" -D -p "$port" -h "$work/host_key" \
	-o ListenAddress="$host" \
	-o PidFile=none \
	-o UsePAM=no \
	-o PermitRootLogin=no \
	-o AuthorizedKeysFile=/dev/null \
	-E "$work/sshd.log" &
server_pid=$!

for _ in $(seq 1 50); do
	if grep -q 'Server listening' "$work/sshd.log" 2>/dev/null; then
		break
	fi
	sleep 0.2
done
if ! grep -q 'Server listening' "$work/sshd.log" 2>/dev/null; then
	echo "the test SSH server did not start; see $work/sshd.log" >&2
	cat "$work/sshd.log" >&2 || true
	exit 2
fi

: >"$work/known_hosts.unknown"
entry "$work/host_key.pub" >"$work/known_hosts.pinned"
entry "$work/other_key.pub" >"$work/known_hosts.changed"

output=$(connect "$work/known_hosts.unknown")
case $output in
	*'Host key verification failed'*) check 'unknown host key is refused' pass ;;
	*) check 'unknown host key is refused' fail; printf '%s\n' "$output" >&2 ;;
esac
if [ -s "$work/known_hosts.unknown" ]; then
	check 'a refused key is not recorded' fail
else
	check 'a refused key is not recorded' pass
fi

output=$(connect "$work/known_hosts.pinned")
case $output in
	*'Host key verification failed'*|*'IDENTIFICATION HAS CHANGED'*)
		check 'pinned host key reaches authentication' fail
		printf '%s\n' "$output" >&2 ;;
	*'Permission denied'*) check 'pinned host key reaches authentication' pass ;;
	*) check 'pinned host key reaches authentication' fail; printf '%s\n' "$output" >&2 ;;
esac

output=$(connect "$work/known_hosts.changed")
case $output in
	*'IDENTIFICATION HAS CHANGED'*|*'Host key verification failed'*)
		check 'changed host key is refused' pass ;;
	*) check 'changed host key is refused' fail; printf '%s\n' "$output" >&2 ;;
esac

# The rotation path: replace only that host's entry with the key taken from
# the host itself, then connect again.
entry "$work/host_key.pub" >"$work/known_hosts.rotated"
output=$(connect "$work/known_hosts.rotated")
case $output in
	*'Permission denied'*) check 'rotated entry restores the host' pass ;;
	*) check 'rotated entry restores the host' fail; printf '%s\n' "$output" >&2 ;;
esac

# Negative control: the option the deployment configuration no longer uses
# accepts the same unknown host without asking.
: >"$work/known_hosts.permissive"
output=$(connect "$work/known_hosts.permissive" no)
case $output in
	*'Permission denied'*) check 'permissive checking would have trusted it' pass ;;
	*) check 'permissive checking would have trusted it' fail; printf '%s\n' "$output" >&2 ;;
esac

# Everything that starts a deployment: the configuration, the make targets
# that invoke it, and the pipeline. This directory is excluded because the
# check above deliberately exercises the permissive option, prose is excluded
# because documenting an option is not using it, and comment lines are dropped
# for the same reason.
weak_pattern='StrictHostKeyChecking=(no|accept-new)'
weak_pattern="$weak_pattern"'|host_key_checking[[:space:]]*=[[:space:]]*([Ff]alse|no)'
weak_pattern="$weak_pattern"'|ANSIBLE_HOST_KEY_CHECKING[[:space:]]*[:=][[:space:]]*.?([Ff]alse|no|0)'
weak_pattern="$weak_pattern"'|ssh-keyscan'
weak=$( { grep -RInE "$weak_pattern" "$root/deploy" \
		--exclude-dir=test --exclude='*.md' 2>/dev/null || true
	grep -InE "$weak_pattern" "$root/Makefile" "$root"/.github/workflows/*.yml 2>/dev/null || true
} | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' || true)
if [ -n "$weak" ]; then
	check 'no deployment command weakens host verification' fail
	printf '%s\n' "$weak" >&2
else
	check 'no deployment command weakens host verification' pass
fi

for required in 'StrictHostKeyChecking=yes' 'GlobalKnownHostsFile=/dev/null'; do
	if grep -qF "$required" "$root/deploy/ansible/ansible.cfg"; then
		check "ansible.cfg pins $required" pass
	else
		check "ansible.cfg pins $required" fail
	fi
done
if grep -qF 'UserKnownHostsFile={{ known_hosts_file }}' \
	"$root/deploy/ansible/group_vars/all.yml"; then
	check 'the known-hosts file is pinned for managed hosts' pass
else
	check 'the known-hosts file is pinned for managed hosts' fail
fi

if command -v ansible-playbook >/dev/null; then
	if (cd "$root/deploy/ansible" && ansible-playbook -i localhost, \
		--syntax-check preflight-host-keys.yml >/dev/null 2>&1); then
		check 'the preflight playbook parses' pass
	else
		check 'the preflight playbook parses' fail
	fi
else
	printf 'skip the preflight playbook parses: ansible-playbook is not installed\n'
fi

if [ "$failures" -ne 0 ]; then
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi
printf 'all host identity checks passed\n'
