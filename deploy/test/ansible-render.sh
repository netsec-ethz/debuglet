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
#      no change),
#   9. a configuration-only update renders the version installed on each host
#      and refuses another one,
#  10. the RIS ASN database refresh: the timer and its unit are installed and
#      name the database the dispatcher configuration reads, a configuration
#      update refuses to name a database no deployment has built, and
#      disabling it removes the units and the configuration entry.
#  11. executor labels, the advertised address, the IPv4 reflector and the
#      executor's capability set render where the daemons read them.
#  12. with client certificates required, the deployment binds every inventory
#      executor to the certificate it installs before the dispatcher runs with
#      the requirement, re-binds a reissued certificate and refuses one from
#      another authority; the preflight refuses enforcement for an executor
#      with neither a certificate to bind nor an enrollment token.
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

# OAuth stays enabled in the rendered production profile. These credentials
# belong only to this offline fixture; no provider is contacted.
printf '%s\n' 'GITHUB_OAUTH_CLIENT_ID=fixture-client' \
	'GITHUB_OAUTH_CLIENT_SECRET=fixture-secret' >"$work/github-oauth.env"
chmod 0600 "$work/github-oauth.env"
# CILogon is enabled in the production profile too, from its own file.
printf '%s\n' 'CILOGON_CLIENT_ID=cilogon:/client_id/fixture' \
	'CILOGON_CLIENT_SECRET=fixture-secret' >"$work/cilogon_oidc.env"
chmod 0600 "$work/cilogon_oidc.env"
# A CILogon file that lacks the secret, for the preflight refusal below.
grep -v '^CILOGON_CLIENT_SECRET' "$work/cilogon_oidc.env" >"$work/cilogon-incomplete.env"
chmod 0600 "$work/cilogon-incomplete.env"
cat >"$work/cilogon.yml" <<EOF
dispatcher_cilogon_oidc_enabled: true
dispatcher_cilogon_oidc_env_file: $work/cilogon_oidc.env
dispatcher_authentication_public_url: https://api.fixture.invalid/api
dispatcher_authentication_device_verification_url: https://api.fixture.invalid/console/device
EOF
# Malformed credential files: each required name must be assigned exactly once
# and non-empty.
printf '%s\n' 'CILOGON_CLIENT_ID=cilogon:/client_id/fixture' \
	'CILOGON_CLIENT_ID=cilogon:/client_id/fixture' >"$work/cilogon-duplicate-id.env"
printf '%s\n' 'CILOGON_CLIENT_SECRET=' | cat "$work/cilogon_oidc.env" - >"$work/cilogon-empty-secret.env"
grep -v '^GITHUB_OAUTH_CLIENT_SECRET' "$work/github-oauth.env" >"$work/github-no-secret.env"
grep '^GITHUB_OAUTH_CLIENT_ID' "$work/github-oauth.env" | cat - "$work/github-oauth.env" >"$work/github-duplicate-id.env"
printf '%s\n' 'CILOGON_CLIENT_ID=cilogon:/client_id/fixture' \
	'CILOGON_CLIENT_SECRET=""' >"$work/cilogon-quoted-empty-secret.env"
printf '%s\n' 'GITHUB_OAUTH_CLIENT_ID=fixture-client' \
	"GITHUB_OAUTH_CLIENT_SECRET=''" >"$work/github-quoted-empty-secret.env"
printf '%s\n' 'CILOGON_CLIENT_ID=   ' \
	'CILOGON_CLIENT_SECRET=fixture-secret' >"$work/cilogon-blank-id.env"
printf '%s\n' ' CILOGON_CLIENT_SECRET=' | cat "$work/cilogon_oidc.env" - >"$work/cilogon-padded-secret.env"
printf '%s\n' 'CILOGON_CLIENT_SECRET =' | cat "$work/cilogon_oidc.env" - >"$work/cilogon-spaced-secret.env"
chmod 0600 "$work"/cilogon-*.env "$work"/github-*.env

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
          executor_public_host: 192.0.2.10
          executor_display_name: Fixture lab
          executor_display_city: Zürich
          executor_display_country: CH
          executor_display_network: SWITCH (AS559)
EOF

cat >"$work/fixture.yml" <<EOF
ansible_connection: local
ansible_become: false
ansible_python_interpreter: "{{ ansible_playbook_python }}"
known_hosts_file: $work/known_hosts
dispatcher_addr: dispatcher.fixture.invalid
dispatcher_base_url: api.fixture.invalid
dispatcher_github_oauth_env_file: $work/github-oauth.env
dispatcher_cilogon_oidc_env_file: $work/cilogon_oidc.env
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

# A separate intermediate is provisioned only for this fixture. Production
# playbooks never generate an enrollment issuer or copy the deployment root key.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$work/enrollment.key" -out "$work/enrollment.csr" \
	-subj '/CN=Fixture Executor Issuer' >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' \
	'keyUsage=critical,keyCertSign,cRLSign' 'extendedKeyUsage=clientAuth' \
	>"$work/enrollment.ext"
openssl x509 -req -in "$work/enrollment.csr" -CA "$certs/ca.crt" \
	-CAkey "$certs/ca.key" -CAcreateserial -days 2 -sha256 \
	-extfile "$work/enrollment.ext" -out "$work/enrollment.crt" >/dev/null 2>&1
chmod 0600 "$work/enrollment.key"
cat >"$work/onboarding.yml" <<EOF
dispatcher_require_client_cert: true
dispatcher_executor_onboarding_enabled: true
dispatcher_executor_onboarding_ca_cert: $work/enrollment.crt
dispatcher_executor_onboarding_ca_key: $work/enrollment.key
dispatcher_executor_onboarding_dispatcher_url: https://api.fixture.invalid/api
dispatcher_executor_onboarding_grpc_address: dispatcher.fixture.invalid:19001
dispatcher_executor_onboarding_yamux_address: dispatcher.fixture.invalid:19000
EOF

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
refuses 'a lower-case executor country is refused' 'ISO 3166-1 alpha-2' \
	-e executor_display_country=ch
refuses 'an executor label with trailing space is refused' 'without leading or trailing space' \
	-e '{"executor_display_city": "Zurich "}'
refuses 'an executor label over 64 characters is refused' 'at most 64 characters' \
	-e "executor_display_name=$(printf 'x%.0s' $(seq 65))"
refuses 'a public address with a port is refused' 'bare public' \
	-e executor_public_host=192.0.2.10:9000
refuses 'a named IPv4 reflector is refused' 'literal IPv4' \
	-e executor_connectivity_ipv4_reflector=dispatcher.fixture.invalid:19001
refuses 'colliding listener ports are refused' 'must differ' \
	-e 'dispatcher_grpc_port=19000'
refuses 'a database directory inside the configuration is refused' 'neither' \
	-e "state_dir=$host/etc/debuglet/state"
refuses 'a cleartext channel to a remote dispatcher is refused' 'literal loopback address' \
	-e executor_disable_tls=true
refuses 'CILogon without its credentials is refused' 'cilogon_oidc.env.example' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-incomplete.env"
refuses 'CILogon with a duplicate client ID and no secret is refused' 'CILOGON_CLIENT_ID exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-duplicate-id.env"
refuses 'CILogon with a trailing empty secret is refused' 'CILOGON_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-empty-secret.env"
refuses 'CILogon with an empty quoted secret is refused' 'CILOGON_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-quoted-empty-secret.env"
refuses 'CILogon with a whitespace-only client ID is refused' 'CILOGON_CLIENT_ID exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-blank-id.env"
refuses 'CILogon with a padded empty secret after a good one is refused' 'CILOGON_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-padded-secret.env"
refuses 'CILogon with a spaced empty secret after a good one is refused' 'CILOGON_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_cilogon_oidc_env_file=$work/cilogon-spaced-secret.env"
refute 'a refused credential file does not show its values' "$work/refuse.log" 'fixture-secret'
refuses 'GitHub OAuth without its secret is refused' 'GITHUB_OAUTH_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_github_oauth_env_file=$work/github-no-secret.env"
refuses 'GitHub OAuth with a duplicate client ID is refused' 'GITHUB_OAUTH_CLIENT_ID exactly once and non-empty' \
	-e "dispatcher_github_oauth_env_file=$work/github-duplicate-id.env"
refuses 'GitHub OAuth with an empty quoted secret is refused' 'GITHUB_OAUTH_CLIENT_SECRET exactly once and non-empty' \
	-e "dispatcher_github_oauth_env_file=$work/github-quoted-empty-secret.env"
refuses 'verifying a dispatcher that serves no TLS is refused' 'verify a certificate nothing presents' \
	-e dispatcher_disable_tls=true
refuses 'requiring client certificates without TLS is refused' 'cleartext listener has no client certificate' \
	-e dispatcher_disable_tls=true -e dispatcher_require_client_cert=true
refuses 'a RIS peer threshold below one is refused' 'dispatcher_ris_asn_min_peers must be a positive integer' \
	-e dispatcher_ris_asn_min_peers=0
refuses 'a RIS ASN database outside the dispatcher state is refused' 'the only directory the refresh' \
	-e "dispatcher_ris_asn_database=$host/etc/debuglet/ris-asn.mmdb"

refuses 'CILogon requires its own private credential file' 'cilogon_oidc.env.example' \
	-e "@$work/cilogon.yml" -e "dispatcher_cilogon_oidc_env_file=$work/missing.env"
chmod 0644 "$work/cilogon_oidc.env"
refuses 'CILogon refuses readable-by-others credentials' 'chmod 600' -e "@$work/cilogon.yml"
chmod 0600 "$work/cilogon_oidc.env"
refuses 'CILogon refuses an unrelated issuer' 'approved CILogon' \
	-e "@$work/cilogon.yml" -e dispatcher_cilogon_oidc_issuer=https://other.fixture.invalid
refuses 'browser credential URLs must be configured together' 'Set both dispatcher_authentication' \
	-e dispatcher_authentication_public_url=https://api.fixture.invalid/api

refuses 'onboarding requires client certificates' 'dispatcher_require_client_cert=true' \
	-e "@$work/onboarding.yml" -e dispatcher_require_client_cert=false
refuses 'onboarding requires a clean HTTPS API URL' 'an HTTPS URL' \
	-e "@$work/onboarding.yml" -e dispatcher_executor_onboarding_dispatcher_url=https://api.fixture.invalid/api?token=x
refuses 'onboarding refuses an API URL with port zero' 'an HTTPS URL' \
	-e "@$work/onboarding.yml" -e dispatcher_executor_onboarding_dispatcher_url=https://api.fixture.invalid:0/api
refuses 'onboarding requires explicit control endpoints' 'native TLS host:port' \
	-e "@$work/onboarding.yml" -e dispatcher_executor_onboarding_grpc_address=
refuses 'onboarding refuses a control hostname absent from the certificate' 'hostname mismatch' \
	-e "@$work/onboarding.yml" -e dispatcher_executor_onboarding_yamux_address=other.fixture.invalid:19000
refuses 'onboarding requires a preprovisioned issuer' 'preprovisioned dedicated' \
	-e "@$work/onboarding.yml" -e "dispatcher_executor_onboarding_ca_cert=$work/absent.crt"
chmod 0644 "$work/enrollment.key"
refuses 'onboarding requires an owner-only issuer key' 'owner-only' -e "@$work/onboarding.yml"
chmod 0600 "$work/enrollment.key"
refuses 'onboarding refuses the deployment root key' 'never the deployment root CA key' \
	-e "@$work/onboarding.yml" -e "dispatcher_executor_onboarding_ca_cert=$certs/ca.crt" \
	-e "dispatcher_executor_onboarding_ca_key=$certs/ca.key"
refuses 'onboarding refuses a mismatched issuer key' 'does not match its certificate' \
	-e "@$work/onboarding.yml" -e "dispatcher_executor_onboarding_ca_key=$certs/dispatcher/server.key"
if run "$work/onboarding-preflight.log" preflight-variables.yml -e "@$work/onboarding.yml"; then
	check 'onboarding accepts a dedicated trusted issuer and public endpoints' pass
else
	check 'onboarding accepts a dedicated trusted issuer and public endpoints' fail
	tail -20 "$work/onboarding-preflight.log" >&2
fi

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
refuses 'onboarding refuses an untrusted issuer' 'verification failed' \
	-e "@$work/onboarding.yml" -e "dispatcher_tls_ca_source=$foreign/ca.crt"
# The custom bundle must survive deployment verbatim, including overlapping
# trust for old clients. Only public certificates are installed as trust.
cat "$certs/ca.crt" "$foreign/ca.crt" >"$work/client-trust.crt"
printf '%s\n' "dispatcher_tls_ca_source: $work/client-trust.crt" >>"$work/onboarding.yml"

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
	"$host/etc/systemd/system/debuglet-ris-asn.service" \
	"$host/etc/systemd/system/debuglet-ris-asn.timer" \
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
cilogon_enabled() {
	grep -A1 -xF '[cilogon_oidc]' "$dispatcher_toml" | sed -n 2p
}
if [ "$(cilogon_enabled)" = 'enabled = true' ]; then
	check 'the production profile renders CILogon enabled' pass
else
	check 'the production profile renders CILogon enabled' fail
fi
refute 'browser CLI approval is absent by default' "$dispatcher_toml" '[authentication]'
# The production profile looks executor ASNs up in the RIS database, which the
# refresh unit writes to exactly the path the configuration names. The fixture
# drives no systemd, so no build runs and nothing is downloaded.
ris_database=$host/var/lib/debuglet/dispatcher/ris-asn.mmdb
ris_service=$host/etc/systemd/system/debuglet-ris-asn.service
ris_timer=$host/etc/systemd/system/debuglet-ris-asn.timer
expect 'the production profile reads the RIS ASN database' "$dispatcher_toml" \
	"asn_database = \"$ris_database\""
refute 'no city database is configured' "$dispatcher_toml" 'city_database'
expect 'the refresh builds the database the dispatcher reads' "$ris_service" \
	"-build-asn-database $ris_database"
expect 'the refresh runs the installed dispatcher' "$ris_service" \
	"ExecStart=$host/opt/debuglet/prod/bin/debuglet-dispatcher"
expect 'the refresh applies the RIS visibility threshold' "$ris_service" '-ris-min-peers 10'
expect 'the refresh runs as the service account' "$ris_service" "User=$(id -un)"
expect 'the refresh writes only the dispatcher state directory' "$ris_service" \
	"ReadWritePaths=$host/var/lib/debuglet/dispatcher"
expect 'the refresh is a one-shot job' "$ris_service" 'Type=oneshot'
expect 'the refresh runs daily' "$ris_timer" 'OnCalendar=*-*-* 04:30:00 UTC'
expect 'a missed refresh runs at the next boot' "$ris_timer" 'Persistent=true'
if [ ! -e "$ris_database" ]; then
	check 'the fixture deployment downloads no RIS data' pass
else
	check 'the fixture deployment downloads no RIS data' fail
fi
expect 'the executor dials the configured control address' "$executor_toml" \
	'addr = "dispatcher.fixture.invalid:19001"'
expect 'the executor dials the configured yamux address' "$executor_toml" \
	'yamux_addr = "dispatcher.fixture.invalid:19000"'
expect 'the credentialed origin follows the API domain' "$dispatcher_toml" \
	'["https://api.fixture.invalid"]'
expect 'the production profile enables CILogon sign-in' "$dispatcher_toml" \
	'callback_url = "https://api.fixture.invalid/api/auth/cilogon/callback"'
expect 'the dispatcher unit loads the CILogon credentials' \
	"$host/etc/systemd/system/debuglet-dispatcher.service" \
	"EnvironmentFile=$host/etc/debuglet/dispatcher/cilogon-oidc.env"
expect 'the executor carries its UUID identity' "$executor_toml" \
	'executor_id = "5fe02882-0410-416c-9935-235090bcba0d"'

# Vantage-point metadata: the executor advertises its public address, and the
# dispatcher labels it under its identity with exactly the inventory's values.
expect 'the executor advertises its public address' "$executor_toml" 'public_host = "192.0.2.10"'
expect 'the dispatcher labels the executor under its identity' "$dispatcher_toml" \
	'[executors."5fe02882-0410-416c-9935-235090bcba0d"]'
expect 'the dispatcher renders the executor display name' "$dispatcher_toml" 'display_name = "Fixture lab"'
expect 'the dispatcher renders the executor city' "$dispatcher_toml" 'city = "Z\u00fcrich"'
expect 'the dispatcher renders the executor country' "$dispatcher_toml" 'country = "CH"'
expect 'the dispatcher renders the executor network' "$dispatcher_toml" 'network = "SWITCH (AS559)"'
# A dispatcher reached by name has no literal to reflect against.
refute 'no reflector is rendered for a named dispatcher' "$executor_toml" '[connectivity]'

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
refute 'self-service enrollment remains disabled by default' "$dispatcher_toml" '[executor_onboarding]'
if [ ! -e "$host/etc/debuglet/dispatcher/enrollment-ca.key" ]; then
	check 'the default deployment installs no enrollment issuer key' pass
else
	check 'the default deployment installs no enrollment issuer key' fail
fi

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

# A dispatcher reached at an IPv4 literal is the executor's IPv4 reflector,
# on the gRPC port it already dials; nothing else is opened for it.
mkdir -p "$work/reflector"
if run "$work/reflector-render.log" "$work/tls-render.yml" --limit executors \
	-e "tls_template_dir=$playbooks" -e "tls_render_dir=$work/reflector" \
	-e dispatcher_addr=127.0.0.1; then
	check 'the IPv4 reflector renders for a literal dispatcher address' pass
	expect 'the reflector is the dialled gRPC endpoint' "$work/reflector/executor.toml" \
		'ipv4_reflector = "127.0.0.1:19001"'
	output=$(timeout 10 "$host/opt/debuglet/prod/bin/debuglet-executor" \
		--config "$work/reflector/executor.toml" 2>&1 || true)
	case $output in
		*"$host/var/lib/debuglet/executor-prod/executor.db"*)
			check 'the installed executor accepts the reflector and reaches its database' pass ;;
		*)
			check 'the installed executor accepts the reflector and reaches its database' fail
			printf '%s\n' "$output" | head -5 >&2 ;;
	esac
else
	check 'the IPv4 reflector renders for a literal dispatcher address' fail
	tail -20 "$work/reflector-render.log" >&2
fi

# Opt-in certificate installation preserves the explicit client trust source,
# protects the dedicated signing key and renders exactly the daemon's fields.
if run "$work/onboarding-certs.log" deploy-certs.yml --limit dispatcher -e "@$work/onboarding.yml" &&
	run "$work/onboarding-render.log" "$work/tls-render.yml" --limit dispatcher \
		-e "tls_template_dir=$playbooks" -e "tls_render_dir=$work/tls" -e "@$work/onboarding.yml"; then
	check 'self-service enrollment material installs and configuration renders' pass
	if cmp -s "$work/client-trust.crt" "$host/etc/debuglet/dispatcher/ca.crt" &&
		cmp -s "$work/enrollment.key" "$host/etc/debuglet/dispatcher/enrollment-ca.key" &&
		[ "$(stat -c %a "$host/etc/debuglet/dispatcher/enrollment-ca.key")" = 600 ] &&
		[ "$(stat -c %u "$host/etc/debuglet/dispatcher/enrollment-ca.key")" = "$(id -u)" ]; then
		check 'custom client trust is preserved and the issuer key is private to the service owner' pass
	else
		check 'custom client trust is preserved and the issuer key is private to the service owner' fail
	fi
	for expected in '[executor_onboarding]' 'enabled = true' \
		"ca_cert = \"$host/etc/debuglet/dispatcher/enrollment-ca.crt\"" \
		"ca_key = \"$host/etc/debuglet/dispatcher/enrollment-ca.key\"" \
		'dispatcher_url = "https://api.fixture.invalid/api"' \
		'grpc_address = "dispatcher.fixture.invalid:19001"' \
		'yamux_address = "dispatcher.fixture.invalid:19000"'; do
		expect "onboarding configuration includes $expected" "$work/tls/dispatcher.toml" "$expected"
	done
	output=$(timeout 10 "$host/opt/debuglet/prod/bin/debuglet-dispatcher" \
		--config "$work/tls/dispatcher.toml" 2>&1 || true)
	case $output in
		*"$host/var/lib/debuglet/dispatcher/dispatcher.db"*)
			check 'the dispatcher accepts the enabled onboarding configuration and issuer' pass ;;
		*) check 'the dispatcher accepts the enabled onboarding configuration and issuer' fail
			printf '%s\n' "$output" | head -5 >&2 ;;
	esac
else
	check 'self-service enrollment material installs and configuration renders' fail
	for log in "$work/onboarding-certs.log" "$work/onboarding-render.log"; do
		[ ! -f "$log" ] || tail -n 20 "$log" >&2
	done
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

# ---------------------------------------------------------- config update ---
# A configuration-only update renders the release each host has installed,
# which it reads from the host's deployment record, and refuses a version that
# names another release. The fixture's deploy_version names none, so the
# accepted run passes the installed one explicitly, as an operator may.
# The dispatcher refuses to start with a configured database that does not
# exist, and only a deployment builds the first one.
if run "$work/update-config-ris.log" update-config.yml -e "deploy_version=$release_version"; then
	check 'a configuration update refuses to name a RIS database no deployment built' fail
elif grep -qF 'Run deploy-dispatcher.yml (or site.yml) once' "$work/update-config-ris.log"; then
	check 'a configuration update refuses to name a RIS database no deployment built' pass
else
	check 'a configuration update refuses to name a RIS database no deployment built' fail
	tail -10 "$work/update-config-ris.log" >&2
fi
# A stand-in for the database a managed host's first build writes.
printf 'fixture RIS ASN database\n' >"$ris_database"
if run "$work/update-config.log" update-config.yml -e "deploy_version=$release_version"; then
	check 'a configuration update applies against the fixture host' pass
else
	check 'a configuration update applies against the fixture host' fail
	tail -30 "$work/update-config.log" >&2
fi
expect 'a configuration update renders the installed dispatcher version' "$dispatcher_toml" \
	"version = \"$release_version\""
expect 'a configuration update renders the installed executor version' "$executor_toml" \
	"version = \"$release_version\""
if run "$work/update-config-conflict.log" update-config.yml; then
	check 'a configuration update refuses a version other than the installed one' fail
elif grep -qF "but this host runs $release_version" "$work/update-config-conflict.log"; then
	check 'a configuration update refuses a version other than the installed one' pass
else
	check 'a configuration update refuses a version other than the installed one' fail
	tail -10 "$work/update-config-conflict.log" >&2
fi

# CILogon activation, secret rotation and disablement also use config updates.
if run "$work/cilogon-enable.log" update-config.yml --limit dispatcher \
	-e "deploy_version=$release_version" -e "@$work/cilogon.yml"; then
	check 'CILogon activates through the configuration update' pass
else
	check 'CILogon activates through the configuration update' fail
	tail -20 "$work/cilogon-enable.log" >&2
fi
expect 'the CILogon issuer is rendered' "$dispatcher_toml" 'issuer = "https://cilogon.org"'
expect 'browser CLI approval uses the configured audience' "$dispatcher_toml" 'public_url = "https://api.fixture.invalid/api"'
expect 'browser CLI approval uses the configured console' "$dispatcher_toml" 'device_verification_url = "https://api.fixture.invalid/console/device"'
expect 'the updated unit loads CILogon credentials' \
	"$host/etc/systemd/system/debuglet-dispatcher.service" \
	"EnvironmentFile=$host/etc/debuglet/dispatcher/cilogon-oidc.env"
expect 'the updated unit retains GitHub credentials' \
	"$host/etc/systemd/system/debuglet-dispatcher.service" \
	"EnvironmentFile=$host/etc/debuglet/dispatcher/github-oauth.env"
if cmp -s "$work/cilogon_oidc.env" "$host/etc/debuglet/dispatcher/cilogon-oidc.env" &&
	[ "$(stat -c %a "$host/etc/debuglet/dispatcher/cilogon-oidc.env")" = 600 ]; then
	check 'CILogon credentials are installed privately' pass
else
	check 'CILogon credentials are installed privately' fail
fi
for file in "$dispatcher_toml" "$host/etc/systemd/system/debuglet-dispatcher.service" "$work/cilogon-enable.log"; do
	refute 'the CILogon client secret is excluded from rendered config and logs' "$file" 'fixture-secret'
done
printf '%s\n' 'CILOGON_CLIENT_ID=cilogon:/client_id/fixture' \
	'CILOGON_CLIENT_SECRET=cilogon-fixture-rotated' >"$work/cilogon_oidc.env"
if run "$work/cilogon-rotate.log" update-config.yml --limit dispatcher \
	-e "deploy_version=$release_version" -e "@$work/cilogon.yml" &&
	cmp -s "$work/cilogon_oidc.env" "$host/etc/debuglet/dispatcher/cilogon-oidc.env"; then
	check 'a configuration update replaces CILogon credentials' pass
else
	check 'a configuration update replaces CILogon credentials' fail
	tail -20 "$work/cilogon-rotate.log" >&2
fi
refute 'rotation keeps the new secret out of deployment logs' "$work/cilogon-rotate.log" 'cilogon-fixture-rotated'
if run "$work/cilogon-disable.log" update-config.yml --limit dispatcher \
	-e "deploy_version=$release_version" -e dispatcher_cilogon_oidc_enabled=false; then
	check 'CILogon can be disabled through a configuration update' pass
else
	check 'CILogon can be disabled through a configuration update' fail
	tail -20 "$work/cilogon-disable.log" >&2
fi
if [ "$(cilogon_enabled)" = 'enabled = false' ]; then
	check 'disabled CILogon is rendered as disabled' pass
else
	check 'disabled CILogon is rendered as disabled' fail
fi
refute 'browser CLI approval is removed with its URLs' "$dispatcher_toml" '[authentication]'
refute 'disabled CILogon is not loaded by systemd' \
	"$host/etc/systemd/system/debuglet-dispatcher.service" 'cilogon-oidc.env'

# Disabling the RIS refresh removes its units and the configuration entry, and
# leaves the last database in place.
if run "$work/ris-disable.log" deploy-dispatcher.yml --limit dispatcher \
	-e "deploy_version=$release_version" -e dispatcher_ris_asn_enabled=false; then
	check 'the RIS ASN refresh can be disabled' pass
else
	check 'the RIS ASN refresh can be disabled' fail
	tail -20 "$work/ris-disable.log" >&2
fi
if [ ! -e "$ris_service" ] && [ ! -e "$ris_timer" ] && [ -f "$ris_database" ]; then
	check 'disabling the RIS refresh removes its units only' pass
else
	check 'disabling the RIS refresh removes its units only' fail
fi
refute 'a disabled RIS refresh configures no ASN database' "$dispatcher_toml" 'asn_database'
refute 'a disabled RIS refresh renders no metadata section' "$dispatcher_toml" '[metadata]'

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

# The unit's ambient set, where it is used, is the binary's capability set:
# the eBPF tagger needs cap_perfmon to pass the verifier and the pure-Go
# tagger cap_net_raw. Only a kernel that charges BPF maps to RLIMIT_MEMLOCK
# gets the limit lifted, in place of cap_sys_resource.
identities() {
	local name=$1
	shift
	(cd "$playbooks" && ANSIBLE_CONFIG=ansible.cfg ansible-playbook \
		-i "$work/inventory.yml" -e @vars/prod.yml \
		-e "template_dir=$playbooks" -e "output_dir=$work/$name" "$@" \
		"$work/identities.yml") >"$work/identities-$name.log" 2>&1
}
mkdir -p "$work/caps-old" "$work/caps-new"
if identities caps-old -e executor_ambient_caps=true -e ansible_kernel=5.10.0-28-amd64 &&
	identities caps-new -e executor_ambient_caps=true -e ansible_kernel=5.15.0-130-generic; then
	expect 'the ambient set is the executor capability set' "$work/caps-new/prod.service" \
		'AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_PERFMON CAP_BPF'
	expect 'the bounding set is the executor capability set' "$work/caps-new/prod.service" \
		'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_PERFMON CAP_BPF'
	refute 'the executor is not granted cap_sys_resource' "$work/caps-new/prod.service" 'CAP_SYS_RESOURCE'
	refute 'a memcg-accounting kernel keeps the memlock limit' "$work/caps-new/prod.service" 'LimitMEMLOCK'
	expect 'an older kernel lifts the memlock limit' "$work/caps-old/prod.service" 'LimitMEMLOCK=infinity'
else
	check 'the executor capability set renders' fail
	tail -20 "$work/identities-caps-old.log" "$work/identities-caps-new.log" >&2
fi

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
elif grep -q 'The deployment does not upgrade a database' "$work/legacy.log" &&
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
elif grep -q 'The deployment does not upgrade a database' "$work/legacy-dispatcher.log" &&
	[ ! -f "$host/var/lib/debuglet/dispatcher/dispatcher.db" ]; then
	check 'legacy dispatcher state blocks a fresh seed' pass
else
	check 'legacy dispatcher state blocks a fresh seed' fail
	tail -25 "$work/legacy-dispatcher.log" >&2
fi
expect 'legacy dispatcher database is preserved' \
	"$host/etc/debuglet/dispatcher/dispatcher.db" 'legacy dispatcher accounts and runs'

# ------------------------------------------------------- executor binding ---
# With client certificates required, the dispatcher admits an executor only
# over the certificate bound to its ID in its database. The deployment binds
# every inventory executor from the certificate it installs, before the
# dispatcher runs with the requirement, and again when a certificate is
# reissued. This runs on a host tree of its own with a real dispatcher
# database, which the installed dispatcher creates.
mkdir -p "$work/no-client-certs"
cp -R "$certs/ca.crt" "$certs/dispatcher" "$work/no-client-certs/"
refuses 'enforcement is refused for an executor without a certificate to bind' \
	'the dispatcher would then' -e dispatcher_require_client_cert=true \
	-e "certs_dir=$work/no-client-certs" --limit dispatcher
refuses 'enforcement without inventory binding is refused for an executor without a token' \
	'dispatcher_bind_inventory_executors' -e dispatcher_require_client_cert=true \
	-e dispatcher_bind_inventory_executors=false
if run "$work/token-preflight.log" preflight-variables.yml -e dispatcher_require_client_cert=true \
	-e dispatcher_bind_inventory_executors=false -e executor_enrollment_token=dbx_fixtureselector.fixtureverifier; then
	check 'enforcement without inventory binding is accepted for an executor with a token' pass
else
	check 'enforcement without inventory binding is accepted for an executor with a token' fail
	tail -20 "$work/token-preflight.log" >&2
fi
refuses 'a malformed enrollment token is refused' 'Require a well-formed enrollment token' \
	-e executor_enrollment_token=not-a-token-secretvalue
refute 'a refused enrollment token is not shown' "$work/refuse.log" 'secretvalue'
mkdir -p "$work/token"
if run "$work/token-render.log" "$work/tls-render.yml" --limit executors \
	-e "tls_template_dir=$playbooks" -e "tls_render_dir=$work/token" \
	-e executor_enrollment_token=dbx_fixtureselector.fixtureverifier; then
	expect 'an enrollment token renders into the executor credentials' "$work/token/executor.toml" \
		'enrollment_token = "dbx_fixtureselector.fixtureverifier"'
	output=$(timeout 10 "$host/opt/debuglet/prod/bin/debuglet-executor" \
		--config "$work/token/executor.toml" 2>&1 || true)
	case $output in
		*"$host/var/lib/debuglet/executor-prod/executor.db"*)
			check 'the installed executor accepts an enrollment token' pass ;;
		*)
			check 'the installed executor accepts an enrollment token' fail
			printf '%s\n' "$output" | head -5 >&2 ;;
	esac
else
	check 'an enrollment token renders into the executor credentials' fail
	tail -20 "$work/token-render.log" >&2
fi
refute 'no enrollment token is rendered by default' "$executor_toml" 'enrollment_token'

bind_host=$work/bind-host
bind_certs=$work/bind-certs
bind_dist=$work/bind-dist
mkdir -p "$bind_host/etc/systemd/system" "$bind_dist" "$work/bind-seed"
chmod 0700 "$work/bind-seed"
cp -R "$certs" "$bind_certs"
cp "$dist"/* "$bind_dist/"
rm -f "$bind_dist/dispatcher-seed.db"
"$host/opt/debuglet/prod/bin/debuglet-dispatcher" -init-database "$work/bind-seed/dispatcher.db" \
	>"$work/bind-seed.log" 2>&1 && cp "$work/bind-seed/dispatcher.db" "$bind_dist/dispatcher-seed.db"
cat >"$work/bind.yml" <<EOF
payload_prefix: "$bind_host/opt/debuglet/{{ debuglet_env }}"
payload_staging_dir: "$bind_host/var/tmp/debuglet-payload-{{ debuglet_env }}"
config_dir: $bind_host/etc/debuglet
state_dir: $bind_host/var/lib/debuglet
log_dir: $bind_host/var/log/debuglet
systemd_unit_dir: $bind_host/etc/systemd/system
dist_dir: $bind_dist
certs_dir: $bind_certs
dispatcher_ris_asn_enabled: false
dispatcher_require_client_cert: true
EOF
bind_run() {
	local log=$1
	shift
	run "$log" "$@" --limit dispatcher -e "@$work/bind.yml"
}
fingerprint() {
	openssl x509 -in "$1" -outform DER | sha256sum | cut -d' ' -f1
}
bound_cert=$bind_certs/executors/$fixture_executor/client.crt
first_fingerprint=$(fingerprint "$bound_cert")
if bind_run "$work/bind-certs.log" deploy-certs.yml; then
	check 'certificates install before any dispatcher exists to bind them' pass
	expect 'binding waits for the deployment while no dispatcher is installed' \
		"$work/bind-certs.log" 'no executor was bound now'
else
	check 'certificates install before any dispatcher exists to bind them' fail
	tail -30 "$work/bind-certs.log" >&2
fi
if bind_run "$work/bind-apply.log" deploy-dispatcher.yml; then
	check 'a deployment that requires client certificates applies' pass
else
	check 'a deployment that requires client certificates applies' fail
	tail -30 "$work/bind-apply.log" >&2
fi
expect 'the deployment binds the inventory executor to its certificate' "$work/bind-apply.log" \
	"executor $fixture_executor is now bound to certificate sha256:$first_fingerprint"
if cmp -s "$bound_cert" "$bind_host/etc/debuglet/dispatcher/executors/$fixture_executor.crt"; then
	check 'the dispatcher holds the public executor certificate it bound' pass
else
	check 'the dispatcher holds the public executor certificate it bound' fail
fi
if find "$bind_host/etc/debuglet/dispatcher" -name 'client.key' | grep -q .; then
	check 'no executor key reaches the dispatcher' fail
else
	check 'no executor key reaches the dispatcher' pass
fi
if bind_run "$work/bind-update.log" update-config.yml -e "deploy_version=$release_version"; then
	check 'a configuration update with client certificates required applies' pass
	expect 'a repeated binding changes nothing' "$work/bind-update.log" \
		"executor $fixture_executor is already bound to certificate sha256:$first_fingerprint"
else
	check 'a configuration update with client certificates required applies' fail
	tail -30 "$work/bind-update.log" >&2
fi
# Reissuing a certificate with the generator re-binds it on the next
# certificate installation, before the executor presents it.
rm -rf "${bind_certs:?}/executors/$fixture_executor"
CERTS_DIR=$bind_certs DISPATCHER_SANS=$fixture_sans \
	"$root/deploy/scripts/generate-certs.sh" "$fixture_executor" >"$work/bind-reissue.log" 2>&1
second_fingerprint=$(fingerprint "$bound_cert")
if [ "$second_fingerprint" != "$first_fingerprint" ] &&
	bind_run "$work/bind-rebind.log" deploy-certs.yml; then
	check 'a reissued certificate installs' pass
	expect 'a reissued certificate replaces the binding' "$work/bind-rebind.log" \
		"executor $fixture_executor is now bound to certificate sha256:$second_fingerprint, replacing sha256:$first_fingerprint"
else
	check 'a reissued certificate installs' fail
	tail -30 "$work/bind-rebind.log" >&2
fi
# A certificate the configured authority did not issue is refused rather than
# bound, and the deployment stops before the dispatcher restarts.
cp "$bound_cert" "$work/bind-good.crt"
CERTS_DIR=$work/foreign-ca DISPATCHER_SANS='DNS:other.fixture.invalid' \
	"$root/deploy/scripts/generate-certs.sh" "$fixture_executor" >/dev/null 2>&1
cp "$work/foreign-ca/executors/$fixture_executor/client.crt" "$bound_cert"
if bind_run "$work/bind-foreign.log" update-config.yml -e "deploy_version=$release_version"; then
	check 'a certificate from another authority is not bound' fail
elif grep -qF 'not a client certificate of the configured authority' "$work/bind-foreign.log"; then
	check 'a certificate from another authority is not bound' pass
else
	check 'a certificate from another authority is not bound' fail
	tail -20 "$work/bind-foreign.log" >&2
fi
cp "$work/bind-good.crt" "$bound_cert"

if [ "$failures" -ne 0 ]; then
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi
printf 'all deployment render checks passed\n'
