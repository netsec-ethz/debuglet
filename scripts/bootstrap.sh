#!/bin/sh
# Download and install a versioned Debuglet release for Linux amd64.
set +x
set -eu
LC_ALL=C
export LC_ALL
umask 077

fail() { printf 'bootstrap: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail 'configure DEBUGLET_VERSION and DEBUGLET_PREFIX through the environment'
for command in curl sha256sum tar mktemp uname rm sh; do
	command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'this package requires Linux amd64'

valid_version() (
	[ "${#1}" -le 128 ] || exit 1
	case "$1" in v*) value=${1#v} ;; *) exit 1 ;; esac
	case "$value" in
		*-*)
			prerelease=${value#*-}
			value=${value%%-*}
			case "$prerelease" in ''|*[!0-9A-Za-z.]*|.*|*.|*..*) exit 1 ;; esac
			;;
	esac
	case "$value" in ''|*[!0-9.]*|.*|*.|*..*) exit 1 ;; esac
	IFS=.
	set -- $value
	[ "$#" -eq 3 ] || exit 1
	for number do
		case "$number" in ''|*[!0-9]*|0?*) exit 1 ;; esac
	done
)

version=${DEBUGLET_VERSION:-}
valid_version "$version" || fail 'set DEBUGLET_VERSION to a published version such as v1.2.3 or v1.2.3-rc.1'
prefix=${DEBUGLET_PREFIX:-${HOME:?HOME or DEBUGLET_PREFIX is required}/.local}
carriage_return=$(printf '\r')
case "$prefix" in ''|*'
'*|*"$carriage_return"*) fail 'DEBUGLET_PREFIX must be a nonempty path without line breaks' ;; esac
case "$prefix" in /*) ;; *) prefix=$(pwd -P)/$prefix ;; esac

work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-bootstrap.XXXXXXXXXX") || fail 'cannot create a temporary directory'
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	rm -rf -- "$work" || status=1
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

archive_name=debuglet-$version-linux-amd64.tar.gz
release=https://github.com/netsec-ethz/debuglet/releases/download/$version
for name in "$archive_name" install.sh SHA256SUMS; do
	# GitHub serves release assets through HTTPS redirects. No credentials are
	# needed, and curl configuration is disabled for a consistent download.
	transfer_status=0
	http_status=$(curl -q --fail --silent --show-error --location --max-redirs 5 \
		--proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 \
		--output "$work/$name" --write-out '%{http_code}' "$release/$name" \
		2> "$work/download-error") || transfer_status=$?
	case "$http_status" in
		404) fail "release asset $name is unavailable; check that DEBUGLET_VERSION names a published Linux amd64 release" ;;
		200) [ "$transfer_status" -eq 0 ] || fail "transfer of $name failed; check the connection and retry" ;;
		*) fail "download of $name failed; a successful HTTPS release response is required" ;;
	esac
done

archive_digest= installer_digest=
while IFS= read -r line || [ -n "$line" ]; do
	digest=${line%% *}
	[ "${#digest}" -eq 64 ] || fail 'invalid checksum digest'
	case "$digest" in *[!0-9a-f]*) fail 'invalid checksum digest' ;; esac
	name=${line#"$digest  "}
	[ "$line" = "$digest  $name" ] || fail 'invalid checksum entry'
	case "$name" in
		"$archive_name") [ -z "$archive_digest" ] || fail 'duplicate package checksum'; archive_digest=$digest ;;
		install.sh) [ -z "$installer_digest" ] || fail 'duplicate installer checksum'; installer_digest=$digest ;;
		*) fail 'checksums must name only the selected package and install.sh' ;;
	esac
done < "$work/SHA256SUMS"
[ -n "$archive_digest" ] && [ -n "$installer_digest" ] || fail 'package checksums are incomplete'
(cd "$work" && sha256sum --check --strict SHA256SUMS > /dev/null 2>&1) || fail 'checksum verification failed; no installer was run'

sh "$work/install.sh" --archive "$work/$archive_name" \
	--checksums "$work/SHA256SUMS" --version "$version" --prefix "$prefix" || fail 'package installer failed'

shell_quote() {
	value=$1
	printf "'"
	while [ "${value#*\'}" != "$value" ]; do
		printf '%s' "${value%%\'*}"
		printf '%s' "'\\''"
		value=${value#*\'}
	done
	printf "%s'" "$value"
}
printf '\nInstalled Debuglet %s. Next commands:\n' "$version"
printf 'export PATH='
shell_quote "$prefix/bin"
printf ':"$PATH"\n'
shell_quote "$prefix/bin/dbl"
printf ' --output json demo\n'
shell_quote "$prefix/bin/dbl"
printf ' up\n'
