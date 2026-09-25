#!/usr/bin/env bash
# Check the deployment playbooks against a local fixture host.
#
# Everything here runs on this machine against a throwaway directory tree: the
# fixture host is this machine reached over the local connection, its "managed
# host" is a temporary root, and no inventory, no known-hosts file and no
# managed machine is involved. Nothing is deployed anywhere.
#
# Checked:
#   1. every playbook parses,
#   2. the preflight refuses a missing dispatcher address, a missing API
#      origin and a non-UUID executor identity, and accepts a complete set,
#   3. the playbooks apply in the documented order — deploy-certs.yml, then
#      site.yml — and the roles create the directory skeleton, install the
#      verified release package with its own installer, install the seed
#      databases and render both daemon configurations and both systemd units,
#   4. the rendered configurations name the configured listener addresses and
#      ports, carry explicit wallet-free payment settings, and put each
#      database in the writable state directory rather than in the read-only
#      configuration directory,
#   5. the state directories the databases live in are writable and the
#      configuration files are not world-readable,
#   6. the daemons the package installed accept both rendered configurations
#      through their own validator,
#   7. the deployment record names both the application and the provisioner,
#   8. applying the same variables again changes nothing (check mode reports
#      no change).
#
# It needs a built release package in deploy/dist (./deploy/scripts/build-linux.sh)
# and the pinned provisioner, so run it through deploy/test/provisioner-check.sh.
#
# Usage: deploy/test/ansible-render.sh

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
playbooks=$root/deploy/ansible
failures=0

command -v ansible-playbook >/dev/null || {
	echo "missing ansible-playbook; run this through deploy/test/provisioner-check.sh" >&2
	exit 2
}
command -v openssl >/dev/null || {
	echo "missing openssl; run this through deploy/test/provisioner-check.sh" >&2
	exit 2
}
[ -f "$root/deploy/dist/release.json" ] || {
	echo "missing deploy/dist/release.json; build the release package with ./deploy/scripts/build-linux.sh" >&2
	exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-ansible-render.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
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

expect() {
	local name=$1 file=$2 pattern=$3
	if grep -qF -- "$pattern" "$file"; then
		check "$name" pass
	else
		check "$name" fail
		printf '     %s does not contain %s\n' "$file" "$pattern" >&2
	fi
}

refute() {
	local name=$1 file=$2 pattern=$3
	if grep -qF -- "$pattern" "$file"; then
		check "$name" fail
		printf '     %s unexpectedly contains %s\n' "$file" "$pattern" >&2
	else
		check "$name" pass
	fi
}

# The fixture host is this machine over the local connection, and everything a
# role would write to a managed host goes under this root instead.
host=$work/host
dist=$work/dist
certs=$work/certs
# A managed host already has the directory systemd reads units from; the
# fixture provides it the same way, so the roles install into it rather than
# create it.
mkdir -p "$host" "$dist" "$host/etc/systemd/system"
# The real release package, plus stand-ins for the schema-only databases
# `make deploy-seed-db` writes. The package is installed by its own installer,
# which verifies it; the two database files are only copied into place.
cp "$root/deploy/dist/release.json" "$root/deploy/dist/SHA256SUMS" \
	"$root/deploy/dist/install.sh" "$dist/"
release_version=$(tr -d ' \n' <"$dist/release.json" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
release_archive=$(tr -d ' \n' <"$dist/release.json" | grep -o '"archive":"[^"]*"' | cut -d'"' -f4)
cp "$root/deploy/dist/$release_archive" "$dist/"
for artifact in dispatcher-seed.db executor-seed.db; do
	printf 'fixture %s\n' "$artifact" >"$dist/$artifact"
done

# The preflight requires pinned host identities before anything connects. The
# fixture host is reached over the local connection and never over SSH, but
# the file still has to be there, so the fixture provisions its own.
printf '%s\n' 'dispatcher.fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIXT' \
	'executor.fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTUREFIXTUREFIXTUREFIXTUREFIXTUREFIXT' \
	>"$work/known_hosts"

# The inventory carries the host layout only. Everything a role would write to
# a managed host is redirected with extra variables, which outrank both the
# inventory and the playbooks' own group_vars, so this run cannot touch a real
# installation path.
cat >"$work/inventory.yml" <<EOF
all:
  children:
    dispatcher:
      hosts:
        dispatcher.fixture.invalid: {}
    executors:
      hosts:
        executor.fixture.invalid:
          executor_id: 5fe02882-0410-416c-9935-235090bcba0d
EOF

cat >"$work/fixture.yml" <<EOF
ansible_connection: local
ansible_become: false
ansible_python_interpreter: "{{ ansible_playbook_python }}"
known_hosts_file: $work/known_hosts
dispatcher_addr: dispatcher.fixture.invalid
dispatcher_base_url: api.fixture.invalid
dispatcher_grpc_port: 19001
dispatcher_http_port: 19000
deploy_version: fixture-1.2.3
payload_prefix: "$host/opt/debuglet/{{ debuglet_env }}"
payload_staging_dir: "$host/var/tmp/debuglet-payload-{{ debuglet_env }}"
config_dir: $host/etc/debuglet
state_dir: $host/var/lib/debuglet
log_dir: $host/var/log/debuglet
systemd_unit_dir: $host/etc/systemd/system
dist_dir: $dist
certs_dir: $certs
debuglet_user: "$(id -un)"
debuglet_group: "$(id -gn)"
executor_user: "$(id -un)"
executor_group: "$(id -gn)"
executor_enable_bpf: false
debuglet_manage_account: false
debuglet_manage_services: false
EOF

# The fixture leaves the two host-only steps off — creating the system account
# and driving systemd — and installs no file capabilities, so the same roles
# apply to a temporary directory tree.
run() {
	local log=$1
	shift
	(cd "$playbooks" && ANSIBLE_CONFIG=ansible.cfg ansible-playbook \
		-i "$work/inventory.yml" -e @vars/prod.yml -e "@$work/fixture.yml" "$@") >"$log" 2>&1
}

# ------------------------------------------------------------ certificates ---
# The executor verifies the dispatcher against the name it dialled, so the
# generator is given that name and the certificate has to carry it.
fixture_sans='DNS:dispatcher.fixture.invalid,IP:127.0.0.1'
fixture_executor=5fe02882-0410-416c-9935-235090bcba0d
fixture_dev_executor=1144ad6e-2c14-4e5c-ab72-c05a8e8770f2
if CERTS_DIR=$certs DISPATCHER_SANS=$fixture_sans \
	"$root/deploy/scripts/generate-certs.sh" "$fixture_executor" "$fixture_dev_executor" >"$work/certs.log" 2>&1; then
	check 'the certificate generator issues a CA, a server and a client certificate' pass
else
	check 'the certificate generator issues a CA, a server and a client certificate' fail
	tail -20 "$work/certs.log" >&2
fi

if CERTS_DIR=$certs DISPATCHER_SANS= "$root/deploy/scripts/generate-certs.sh" \
	>"$work/nosan.log" 2>&1; then
	check 'the generator refuses to issue without a name list' fail
else
	check 'the generator refuses to issue without a name list' pass
fi

server_text=$(openssl x509 -in "$certs/dispatcher/server.crt" -noout -text 2>/dev/null || true)
client_text=$(openssl x509 -in "$certs/executors/$fixture_executor/client.crt" -noout -text 2>/dev/null || true)
contains() {
	local name=$1 haystack=$2 needle=$3
	case $haystack in
		*"$needle"*) check "$name" pass ;;
		*) check "$name" fail; printf '     missing: %s\n' "$needle" >&2 ;;
	esac
}
contains 'the dispatcher certificate names the dialled host' "$server_text" 'DNS:dispatcher.fixture.invalid'
contains 'the dispatcher certificate names the dialled address' "$server_text" 'IP Address:127.0.0.1'
contains 'the dispatcher certificate is a server certificate' "$server_text" 'TLS Web Server Authentication'
contains 'the dispatcher certificate is a leaf' "$server_text" 'CA:FALSE'
contains 'the executor certificate is a client certificate' "$client_text" 'TLS Web Client Authentication'
contains 'the executor certificate is a leaf' "$client_text" 'CA:FALSE'
contains 'the executor certificate carries its UUID identity' "$client_text" "$fixture_executor"
for leaf in "$certs/dispatcher/server.crt" "$certs/executors/$fixture_executor/client.crt"; do
	if openssl verify -CAfile "$certs/ca.crt" "$leaf" >/dev/null 2>&1; then
		check "the deployment CA signed ${leaf##*/}" pass
	else
		check "the deployment CA signed ${leaf##*/}" fail
	fi
done

# ---------------------------------------------------------------- parsing ---
for playbook in "$playbooks"/*.yml; do
	name=$(basename "$playbook")
	# Dependency manifests and ignored operator inventories live next to the
	# playbooks but are not playbooks. Real inventories may also contain
	# private values that deliberately differ from the fixtures used here.
	case $name in requirements.yml|hosts.yml|hosts.*.yml) continue ;; esac
	if (cd "$playbooks" && ANSIBLE_CONFIG=ansible.cfg ansible-playbook \
		-i "$work/inventory.yml" -e @vars/prod.yml -e "@$work/fixture.yml" \
		--syntax-check "$name" >"$work/syntax.log" 2>&1); then
		check "$name parses" pass
	else
		check "$name parses" fail
		tail -5 "$work/syntax.log" >&2
	fi
done

# -------------------------------------------------------------- preflight ---
if run "$work/preflight.log" preflight-variables.yml; then
	check 'the preflight accepts a complete variable set' pass
else
	check 'the preflight accepts a complete variable set' fail
	tail -20 "$work/preflight.log" >&2
fi

refuses() {
	local name=$1 expected=$2
	shift 2
	if run "$work/refuse.log" preflight-variables.yml "$@"; then
		check "$name" fail
		tail -10 "$work/refuse.log" >&2
	elif grep -q "$expected" "$work/refuse.log"; then
		check "$name" pass
	else
		check "$name" fail
		printf '     the failure did not name %s\n' "$expected" >&2
		tail -20 "$work/refuse.log" >&2
	fi
}

refuses 'an unknown environment is refused' 'debuglet_env must be prod or dev' -e debuglet_env=other
refuses 'a missing dispatcher address is refused' 'dispatcher_addr is required' \
	-e 'dispatcher_addr='
refuses 'a dispatcher address with a port is refused' 'bare host name' \
	-e 'dispatcher_addr=dispatcher.fixture.invalid:9001'
refuses 'a missing API origin is refused' 'dispatcher_base_url is required' \
	-e 'dispatcher_base_url='
refuses 'a wildcard credentialed origin is refused' 'wildcard is refused' \
	-e '{"dispatcher_cors_allowed_origins": ["*"]}'
refuses 'a non-UUID executor identity is refused' 'must be a lowercase UUID' \
	-e 'executor_id=executor-1'
refuses 'colliding listener ports are refused' 'must differ' \
	-e 'dispatcher_grpc_port=19000'
refuses 'a database directory inside the configuration is refused' 'neither' \
	-e "state_dir=$host/etc/debuglet/state"
refuses 'a cleartext channel to a remote dispatcher is refused' 'literal loopback address' \
	-e executor_disable_tls=true
refuses 'verifying a dispatcher that serves no TLS is refused' 'verify a certificate nothing presents' \
	-e dispatcher_disable_tls=true
refuses 'requiring client certificates without TLS is refused' 'cleartext listener has no client certificate' \
	-e dispatcher_disable_tls=true -e dispatcher_require_client_cert=true

# Material the daemons refuse: a leaf that does not chain to the configured
# root, and a root that has expired. Both are checked before a host is
# touched, so both are refused here.
foreign=$work/foreign
mkdir -p "$foreign"
cp -r "$certs/dispatcher" "$certs/executors" "$foreign/"
CERTS_DIR=$work/foreign-ca DISPATCHER_SANS='DNS:other.fixture.invalid' \
	"$root/deploy/scripts/generate-certs.sh" >/dev/null 2>&1
cp "$work/foreign-ca/ca.crt" "$foreign/ca.crt"
refuses 'a leaf that does not chain to the authority is refused' 'verification failed' \
	-e "certs_dir=$foreign"

expired=$work/expired
mkdir -p "$expired"
cp -r "$certs/dispatcher" "$certs/executors" "$expired/"
if openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
	-keyout "$expired/ca.key" -out "$expired/ca.crt" -subj '/CN=Debuglet-CA-expired/O=Debuglet' \
	-not_before 20200101000000Z -not_after 20200102000000Z >/dev/null 2>&1; then
	refuses 'an expired authority is refused' 'checkend' -e "certs_dir=$expired"
else
	printf 'skip an expired authority is refused: this openssl cannot backdate a certificate\n'
fi

# The one shape a cleartext control channel is supported in.
if run "$work/loopback.log" preflight-variables.yml \
	-e executor_disable_tls=true -e dispatcher_disable_tls=true \
	-e dispatcher_addr=127.0.0.1; then
	check 'a cleartext channel to a loopback dispatcher is accepted' pass
else
	check 'a cleartext channel to a loopback dispatcher is accepted' fail
	tail -20 "$work/loopback.log" >&2
fi

# ----------------------------------------------------------------- render ---
# The documented order, on a host neither playbook has touched: certificates
# are issued and installed first, and only then does the deployment that
# renders paths to them run.
if run "$work/certs-apply.log" deploy-certs.yml; then
	check 'the certificate playbook installs the material' pass
else
	check 'the certificate playbook installs the material' fail
	tail -30 "$work/certs-apply.log" >&2
fi
for file in "$host/etc/debuglet/dispatcher/server.crt" "$host/etc/debuglet/dispatcher/server.key" \
	"$host/etc/debuglet/dispatcher/ca.crt" "$host/etc/debuglet/executor-prod/ca.crt" \
	"$host/etc/debuglet/executor-prod/client.crt" "$host/etc/debuglet/executor-prod/client.key"; do
	if [ -f "$file" ]; then
		check "the certificate playbook installs ${file#"$host"}" pass
	else
		check "the certificate playbook installs ${file#"$host"}" fail
	fi
done

if run "$work/apply.log" site.yml; then
	check 'the roles apply against the fixture host' pass
else
	check 'the roles apply against the fixture host' fail
	tail -30 "$work/apply.log" >&2
	printf '%s check(s) failed\n' "$((failures + 1))" >&2
	exit 1
fi

dispatcher_toml=$host/etc/debuglet/dispatcher/dispatcher.toml
executor_toml=$host/etc/debuglet/executor-prod/executor.toml
for file in "$dispatcher_toml" "$executor_toml" \
	"$host/etc/systemd/system/debuglet-dispatcher.service" \
	"$host/etc/systemd/system/debuglet-executor-prod.service" \
	"$host/var/lib/debuglet/dispatcher/dispatcher.db" \
	"$host/var/lib/debuglet/executor-prod/executor.db" \
	"$host/opt/debuglet/prod/bin/dbl" \
	"$host/opt/debuglet/prod/bin/debuglet-dispatcher" \
	"$host/opt/debuglet/prod/bin/debuglet-executor" \
	"$host/etc/debuglet/deployment-prod.json"; do
	if [ -f "$file" ]; then
		check "the roles install ${file#"$host"}" pass
	else
		check "the roles install ${file#"$host"}" fail
	fi
done

# Listener addresses: the dispatcher binds the configured ports and every
# executor dials exactly those, on the configured dispatcher address.
expect 'the dispatcher binds the configured HTTP port' "$dispatcher_toml" 'http_port = 19000'
expect 'the dispatcher binds the configured gRPC port' "$dispatcher_toml" 'grpc_port = 19001'
expect 'the dispatcher records the deployed version' "$dispatcher_toml" 'version = "fixture-1.2.3"'
expect 'the executor dials the configured control address' "$executor_toml" \
	'addr = "dispatcher.fixture.invalid:19001"'
expect 'the executor dials the configured yamux address' "$executor_toml" \
	'yamux_addr = "dispatcher.fixture.invalid:19000"'
expect 'the credentialed origin follows the API domain' "$dispatcher_toml" \
	'["https://api.fixture.invalid"]'
expect 'the executor carries its UUID identity' "$executor_toml" \
	'executor_id = "5fe02882-0410-416c-9935-235090bcba0d"'

# Transport security: the dispatcher serves its own listeners and the executor
# verifies them, so the rendered files name the material on both sides.
expect 'the dispatcher serves TLS on its own listeners' "$dispatcher_toml" 'disable = false'
expect 'the dispatcher names its certificate' "$dispatcher_toml" \
	"cert_file = \"$host/etc/debuglet/dispatcher/server.crt\""
expect 'the executor verifies with the deployment CA' "$executor_toml" \
	"ca_cert = \"$host/etc/debuglet/executor-prod/ca.crt\""
expect 'the executor presents its client certificate' "$executor_toml" \
	"client_cert = \"$host/etc/debuglet/executor-prod/client.crt\""
# Both keys are rendered only when they are set, so a deployment that needs
# neither carries neither.
refute 'no client-certificate requirement is rendered by default' "$dispatcher_toml" 'require_client_cert ='
refute 'no verification name is rendered by default' "$executor_toml" 'server_name ='

# …and are rendered when they are, which is what an operator who needs them
# writes in the inventory.
cat >"$work/tls-render.yml" <<'EOF'
- name: Render the configurations with the transport keys set
  hosts: all
  connection: local
  gather_facts: false
  become: false
  # This playbook is outside deploy/ansible, so the defaults the roles render
  # with are named rather than picked up from the directory.
  vars_files:
    - "{{ tls_template_dir }}/group_vars/all.yml"
    - "{{ tls_template_dir }}/group_vars/dispatcher.yml"
    - "{{ tls_template_dir }}/group_vars/executors.yml"
  tasks:
    - name: Render the dispatcher configuration
      ansible.builtin.template:
        src: "{{ tls_template_dir }}/roles/dispatcher/templates/dispatcher.toml.j2"
        dest: "{{ tls_render_dir }}/dispatcher.toml"
        mode: "0600"
      when: inventory_hostname in (groups['dispatcher'] | default([]))

    - name: Render the executor configuration
      ansible.builtin.template:
        src: "{{ tls_template_dir }}/roles/executor/templates/executor.toml.j2"
        dest: "{{ tls_render_dir }}/executor.toml"
        mode: "0600"
      when: inventory_hostname in (groups['executors'] | default([]))
EOF
mkdir -p "$work/tls"
if run "$work/tls-render.log" "$work/tls-render.yml" \
	-e "tls_template_dir=$playbooks" -e "tls_render_dir=$work/tls" \
	-e executor_tls_server_name=dispatcher.fixture.invalid \
	-e dispatcher_require_client_cert=true; then
	check 'the transport keys render when they are set' pass
	expect 'the dispatcher requires a client certificate when asked' \
		"$work/tls/dispatcher.toml" 'require_client_cert = true'
	expect 'the dispatcher names the authority it checks clients against' \
		"$work/tls/dispatcher.toml" "ca_file = \"$host/etc/debuglet/dispatcher/ca.crt\""
	expect 'the executor verifies the configured name' \
		"$work/tls/executor.toml" 'server_name = "dispatcher.fixture.invalid"'
	# Both keys are declared by the daemons this package installs, so a
	# rendered file that carries them has to reach the database rather than
	# be refused by name.
	for pair in "dispatcher:tls.require_client_cert" "executor:tls.server_name"; do
		role=${pair%%:*} key=${pair#*:}
		binary=$host/opt/debuglet/prod/bin/debuglet-$role
		database=$host/var/lib/debuglet/$role/$role.db
		[ "$role" != executor ] || database=$host/var/lib/debuglet/executor-prod/executor.db
		output=$(timeout 10 "$binary" --config "$work/tls/$role.toml" 2>&1 || true)
		case $output in
			*"$database"*)
				check "the installed $role accepts $key and reaches its database" pass ;;
			*)
				check "the installed $role accepts $key and reaches its database" fail
				printf '%s\n' "$output" | head -5 >&2 ;;
		esac
	done
else
	check 'the transport keys render when they are set' fail
	tail -20 "$work/tls-render.log" >&2
fi

# Wallet-free by default, explicitly rather than by omission.
expect 'the dispatcher disables chain payments explicitly' "$dispatcher_toml" 'disabled = true'
expect 'the executor prices in TEST units' "$executor_toml" 'currency = "TEST"'
expect 'the executor names no wallet' "$executor_toml" 'sui_wallet = ""'

# Writable database locations: inside the state directory the role creates for
# the service account, never inside the read-only configuration directory.
expect 'the dispatcher database is in the state directory' "$dispatcher_toml" \
	"path = \"$host/var/lib/debuglet/dispatcher/dispatcher.db\""
expect 'the executor database is in the state directory' "$executor_toml" \
	"path = \"$host/var/lib/debuglet/executor-prod/executor.db\""
refute 'no dispatcher database under the configuration directory' "$dispatcher_toml" \
	"path = \"$host/etc/debuglet"
refute 'no executor database under the configuration directory' "$executor_toml" \
	"path = \"$host/etc/debuglet"
for role in dispatcher executor; do
	directory=$host/var/lib/debuglet/$role
	[ "$role" != executor ] || directory=$host/var/lib/debuglet/executor-prod
	if [ -d "$directory" ] && [ -w "$directory" ] &&
		probe=$(mktemp "$directory/.writable.XXXXXX" 2>/dev/null); then
		rm -f -- "$probe"
		check "the $role database directory is writable" pass
	else
		check "the $role database directory is writable" fail
	fi
done

# The rendered configuration carries the TESLA seed, so it must not be
# readable by anyone but the service account and root.
for file in "$dispatcher_toml" "$executor_toml"; do
	mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
	case $mode in
		*[1-7]) check "${file#"$host"} is not world-readable" fail ;;
		*) check "${file#"$host"} is not world-readable" pass ;;
	esac
done

# ------------------------------------------------- the daemons' own checks ---
# The daemons validate their whole configuration file before they open a
# database or bind a listener, and name the key that is wrong. Running the
# ones the package installed against the rendered files is the same check a
# managed host would apply.
# The daemon checks its whole configuration file, then the certificate files
# it names, and only then opens the database. Starting it against a rendered
# file and watching it reach the database is what says the file was accepted:
# the fixture's database is a stand-in, so the daemon reports that and stops.
# It is bounded anyway, so a daemon that does start does not hang the run.
validator() {
	local role=$1 config=$2 database=$3
	local binary=$host/opt/debuglet/prod/bin/debuglet-$role
	if [ ! -x "$binary" ]; then
		check "the $role reaches its database with the rendered configuration" fail
		return
	fi
	local output
	output=$(timeout 10 "$binary" --config "$config" 2>&1 || true)
	case $output in
		*"$database"*)
			check "the $role reaches its database with the rendered configuration" pass ;;
		*)
			check "the $role reaches its database with the rendered configuration" fail
			printf '%s\n' "$output" | head -5 >&2 ;;
	esac
}
validator dispatcher "$dispatcher_toml" "$host/var/lib/debuglet/dispatcher/dispatcher.db"
validator executor "$executor_toml" "$host/var/lib/debuglet/executor-prod/executor.db"

# --------------------------------------------------------------- the record ---
# One deployment record names what is installed and what installed it.
record=$host/etc/debuglet/deployment-prod.json
for field in '"version"' '"source_sha"' '"archive_sha256"' '"ansible_core_version"' \
	'"requirements_sha256"' '"collections_sha256"'; do
	expect "the deployment record names $field" "$record" "$field"
done
expect 'the deployment record names the installed release' "$record" "$release_version"

# ------------------------------------------------------------ idempotence ---
# Unchanged variables must not change the host again. Check mode reports what
# a second run would do without doing it.
if run "$work/recheck.log" site.yml --check --diff; then
	# Every host has to be clean, not just one of them, and both fixture hosts
	# have to appear: a recap that lost a host would otherwise pass.
	recap=$(sed -n '/PLAY RECAP/,$p' "$work/recheck.log" | grep -cE ': +ok=' || true)
	clean=$(sed -n '/PLAY RECAP/,$p' "$work/recheck.log" |
		grep -cE ': +ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' || true)
	if [ "$recap" -eq 2 ] && [ "$clean" -eq "$recap" ]; then
		check 'a repeated run reports no change on every host' pass
	else
		check 'a repeated run reports no change on every host' fail
		printf '     %s of %s host(s) unchanged, expected 2\n' "$clean" "$recap" >&2
		sed -n '/PLAY RECAP/,$p' "$work/recheck.log" >&2
	fi
else
	check 'a repeated run reports no change on every host' fail
	tail -30 "$work/recheck.log" >&2
fi

# -------------------------------------------------- shared executor host ---
# Snapshot prod, including links, before applying dev to the same temporary
# host. The two environments must not share their active executable either.
prod_snapshot() {
	find "$host/etc/debuglet/executor-prod" "$host/var/lib/debuglet/executor-prod" \
		"$host/opt/debuglet/prod" -type f -exec sha256sum {} + | sort
	find "$host/opt/debuglet/prod" -type l -printf '%p -> %l\n' | sort
	sha256sum "$host/etc/debuglet/deployment-prod.json" \
		"$host/etc/systemd/system/debuglet-executor-prod.service"
}
prod_snapshot >"$work/prod-before"
if run "$work/dev-certs.log" deploy-certs.yml --limit executors \
	-e @vars/dev.yml -e "executor_id=$fixture_dev_executor" &&
	run "$work/dev-apply.log" deploy-executors.yml --limit executors \
	-e @vars/dev.yml -e "executor_id=$fixture_dev_executor"; then
	check 'a dev executor installs alongside prod on the same host' pass
else
	check 'a dev executor installs alongside prod on the same host' fail
	tail -25 "$work/dev-certs.log" "$work/dev-apply.log" >&2
fi
for file in "$host/etc/debuglet/executor-dev/executor.toml" \
	"$host/etc/debuglet/executor-dev/client.key" \
	"$host/var/lib/debuglet/executor-dev/executor.db" \
	"$host/etc/debuglet/deployment-dev.json" \
	"$host/etc/systemd/system/debuglet-executor-dev.service" \
	"$host/opt/debuglet/dev/bin/debuglet-executor"; do
	[ -f "$file" ] && check "dev owns ${file#"$host"}" pass || check "dev owns ${file#"$host"}" fail
done
expect 'the dev unit selects the dev executable' \
	"$host/etc/systemd/system/debuglet-executor-dev.service" \
	"ExecStart=$host/opt/debuglet/dev/bin/debuglet-executor"
expect 'the dev unit selects the dev config' \
	"$host/etc/systemd/system/debuglet-executor-dev.service" \
	"-config $host/etc/debuglet/executor-dev/executor.toml"
expect 'the dev executor has its own identity' \
	"$host/etc/debuglet/executor-dev/executor.toml" "executor_id = \"$fixture_dev_executor\""
expect 'the dev executor has its own writable state' \
	"$host/etc/debuglet/executor-dev/executor.toml" \
	"path = \"$host/var/lib/debuglet/executor-dev/executor.db\""

# Exercise repair of the dev activation link and zero-byte DB recovery. Prod
# has nonempty state and must remain byte-for-byte unchanged across both runs.
rm -f "$host/opt/debuglet/dev/bin/debuglet-executor"
: >"$host/var/lib/debuglet/executor-dev/executor.db"
if run "$work/dev-repair.log" deploy-executors.yml --limit executors \
	-e @vars/dev.yml -e "executor_id=$fixture_dev_executor" &&
	[ -x "$host/opt/debuglet/dev/bin/debuglet-executor" ] &&
	cmp -s "$dist/executor-seed.db" "$host/var/lib/debuglet/executor-dev/executor.db"; then
	check 'dev repairs its own activation link and empty database' pass
else
	check 'dev repairs its own activation link and empty database' fail
	tail -25 "$work/dev-repair.log" >&2
fi
prod_snapshot >"$work/prod-after"
if cmp -s "$work/prod-before" "$work/prod-after"; then
	check 'dev leaves prod binaries, activation links, config, credentials, state, unit and record unchanged' pass
else
	check 'dev leaves prod binaries, activation links, config, credentials, state, unit and record unchanged' fail
	diff -u "$work/prod-before" "$work/prod-after" >&2 || true
fi

# Render each environment's defaults without overriding the service accounts.
# Render the restart list too, without invoking a host service manager.
cat >"$work/identities.yml" <<'EOF'
- name: Render executor service identities
  hosts: executors
  connection: local
  gather_facts: false
  become: false
  vars_files:
    - "{{ template_dir }}/group_vars/all.yml"
    - "{{ template_dir }}/group_vars/executors.yml"
    - "{{ template_dir }}/roles/payload/defaults/main.yml"
  tasks:
    - ansible.builtin.template:
        src: "{{ template_dir }}/roles/executor/templates/executor.service.j2"
        dest: "{{ output_dir }}/{{ debuglet_env }}.service"
        mode: "0600"
    - ansible.builtin.copy:
        content: "{{ debuglet_services | to_json }}"
        dest: "{{ output_dir }}/{{ debuglet_env }}.restarts"
        mode: "0600"
EOF
for env in prod dev; do
	if (cd "$playbooks" && ANSIBLE_CONFIG=ansible.cfg ansible-playbook \
		-i "$work/inventory.yml" -e "@vars/$env.yml" \
		-e "template_dir=$playbooks" -e "output_dir=$work" \
		"$work/identities.yml") >"$work/identities-$env.log" 2>&1; then
		expect "$env service uses its own user" "$work/$env.service" "User=debuglet-$env"
		expect "$env service uses its own group" "$work/$env.service" "Group=debuglet-$env"
		expect "$env service uses its own log identity" "$work/$env.service" "SyslogIdentifier=debuglet-executor-$env"
		expect "$env payload restarts only its executor unit" "$work/$env.restarts" "[\"debuglet-executor-$env\"]"
	else
		check "$env service identities render" fail
		tail -20 "$work/identities-$env.log" >&2
	fi
done

# A legacy unsuffixed unit may belong to the other environment. Even when
# dev already has state, retiring that unit requires an explicit selection.
printf 'legacy unit\n' >"$host/etc/systemd/system/debuglet-executor.service"
if run "$work/legacy-unit.log" deploy-executors.yml --limit executors \
	-e @vars/dev.yml -e "executor_id=$fixture_dev_executor"; then
	check 'an unsuffixed unit requires explicit retirement' fail
elif grep -q 'may belong to another' "$work/legacy-unit.log"; then
	check 'an unsuffixed unit requires explicit retirement' pass
else
	check 'an unsuffixed unit requires explicit retirement' fail
	tail -25 "$work/legacy-unit.log" >&2
fi

# A nonempty legacy DB is preserved and blocks fresh seeding. Keep the legacy
# unit in place: deciding how to upgrade live state is an operator action.
mkdir -p "$host/etc/debuglet/executor"
printf 'legacy recorded state\n' >"$host/etc/debuglet/executor/executor.db"
printf 'legacy unit\n' >"$host/etc/systemd/system/debuglet-executor.service"
rm -f "$host/var/lib/debuglet/executor-dev/executor.db"
if run "$work/legacy.log" deploy-executors.yml --limit executors \
	-e @vars/dev.yml -e "executor_id=$fixture_dev_executor"; then
	check 'legacy state blocks a fresh seed until schema compatibility is established' fail
elif grep -q 'This alpha does not upgrade old database schemas' "$work/legacy.log" &&
	[ ! -f "$host/var/lib/debuglet/executor-dev/executor.db" ]; then
	check 'legacy state blocks a fresh seed until schema compatibility is established' pass
else
	check 'legacy state blocks a fresh seed until schema compatibility is established' fail
	tail -25 "$work/legacy.log" >&2
fi
expect 'legacy nonempty database is preserved' "$host/etc/debuglet/executor/executor.db" 'legacy recorded state'
expect 'legacy unit file is preserved' "$host/etc/systemd/system/debuglet-executor.service" 'legacy unit'

# The official dispatcher also stored its database under config_dir. Do not
# strand accounts and runs by replacing that installation with a fresh seed.
printf 'legacy dispatcher accounts and runs\n' >"$host/etc/debuglet/dispatcher/dispatcher.db"
rm -f "$host/var/lib/debuglet/dispatcher/dispatcher.db"
if run "$work/legacy-dispatcher.log" deploy-dispatcher.yml --limit dispatcher; then
	check 'legacy dispatcher state blocks a fresh seed' fail
elif grep -q 'This alpha does not upgrade old database schemas' "$work/legacy-dispatcher.log" &&
	[ ! -f "$host/var/lib/debuglet/dispatcher/dispatcher.db" ]; then
	check 'legacy dispatcher state blocks a fresh seed' pass
else
	check 'legacy dispatcher state blocks a fresh seed' fail
	tail -25 "$work/legacy-dispatcher.log" >&2
fi
expect 'legacy dispatcher database is preserved' \
	"$host/etc/debuglet/dispatcher/dispatcher.db" 'legacy dispatcher accounts and runs'

if [ "$failures" -ne 0 ]; then
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi
printf 'all deployment render checks passed\n'
