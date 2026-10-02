#!/bin/sh
# Download and install a versioned Debuglet release for Linux amd64.
set +x
set -eu
LC_ALL=C
export LC_ALL
umask 077

fail() { printf 'bootstrap: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail 'configure DEBUGLET_VERSION and DEBUGLET_PREFIX through the environment'
command -v uname >/dev/null 2>&1 || fail 'required command is missing: uname'
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'supported platform: Linux amd64; run dbl on a Linux amd64 machine; see https://github.com/netsec-ethz/debuglet/blob/main/README-install.md#supported-platforms'
for command in sha256sum tar mktemp rm sh cp; do
	command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done


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

component=${DEBUGLET_COMPONENT:-}
case "$component" in ''|cli|executor|dispatcher) ;; *) fail 'DEBUGLET_COMPONENT must be cli, executor or dispatcher, or empty for the full bundle' ;; esac
suffix=
[ -z "$component" ] || suffix=-$component
archive_name=debuglet$suffix-$version-linux-amd64.tar.gz
installer_name=install$suffix.sh
checksums_name=SHA256SUMS$suffix
release=https://github.com/netsec-ethz/debuglet/releases/download/$version
release_dir=${DEBUGLET_RELEASE_DIR:-}
if [ -z "$release_dir" ]; then
	command -v curl >/dev/null 2>&1 || fail 'required command is missing: curl'
else
	[ -d "$release_dir" ] && [ ! -L "$release_dir" ] || fail 'DEBUGLET_RELEASE_DIR must name a local release directory'
fi
verify_signature=false
case "${DEBUGLET_REQUIRE_SIGNATURE:-}" in
	'') ;;
	1) verify_signature=true ;;
	*) fail 'DEBUGLET_REQUIRE_SIGNATURE must be empty or exactly 1' ;;
esac
[ -z "${DEBUGLET_RELEASE_TRUST:-}${DEBUGLET_RELEASE_SIGNER:-}" ] || verify_signature=true
case "${DEBUGLET_ALLOW_UNSIGNED:-}" in
	'') ;;
	1) [ "$verify_signature" = false ] || fail 'unsigned mode must not be combined with signature or trust settings' ;;
	*) fail 'DEBUGLET_ALLOW_UNSIGNED must be empty or exactly 1' ;;
esac
if [ "$verify_signature" = true ]; then
	[ -n "${DEBUGLET_RELEASE_TRUST:-}" ] && [ -f "$DEBUGLET_RELEASE_TRUST" ] &&
		[ -n "${DEBUGLET_RELEASE_SIGNER:-}" ] || fail 'signed installation requires independently provisioned DEBUGLET_RELEASE_TRUST and DEBUGLET_RELEASE_SIGNER; no installer was run'
	for command in ssh-keygen python3; do
		command -v "$command" >/dev/null 2>&1 || fail "required signature verification command is missing: $command"
	done
else
	printf '%s\n' 'WARNING: installing an unsigned legacy/development package; checksums do not authenticate a release signer. Set DEBUGLET_REQUIRE_SIGNATURE=1 and provision release trust for signed installation.' >&2
fi

download() {
	name=$1
	if [ -n "$release_dir" ]; then
		[ -f "$release_dir/$name" ] && [ ! -L "$release_dir/$name" ] || fail "local release asset $name is missing or linked"
		cp -- "$release_dir/$name" "$work/$name" || fail "cannot read local release asset $name"
		return
	fi
	# No ambient curl configuration or credentials enter release downloads.
	transfer_status=0
	http_status=$(curl -q --fail --silent --show-error --location --max-redirs 5 \
		--proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 \
		--output "$work/$name" --write-out '%{http_code}' "$release/$name" \
		2> "$work/download-error") || transfer_status=$?
	case "$http_status" in
		404) fail "release asset $name is unavailable; check the selected published version" ;;
		200) [ "$transfer_status" -eq 0 ] || fail "transfer of $name failed; check the connection and retry" ;;
		*) fail "download of $name failed; a successful HTTPS release response is required" ;;
	esac
}

if [ "$verify_signature" = true ]; then
	download release.json
	download release.json.sig
	ssh-keygen -Y verify -f "$DEBUGLET_RELEASE_TRUST" -I "$DEBUGLET_RELEASE_SIGNER" \
		-n debuglet-release -s "$work/release.json.sig" < "$work/release.json" \
		> /dev/null 2>&1 || fail 'release signature is missing, invalid or from an untrusted signer; no installer was run'
fi
for name in "$archive_name" "$installer_name" "$checksums_name"; do download "$name"; done
if [ "$verify_signature" = true ]; then
	python3 - "$work" "$version" "$DEBUGLET_RELEASE_SIGNER" "$archive_name" "$installer_name" "$checksums_name" <<'VERIFY_RELEASE'
import hashlib, json, re, sys
from pathlib import Path
root, version, signer, *names = sys.argv[1:]
root = Path(root)
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result
try:
    path = root / 'release.json'
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('oversized release subjects')
    release = json.loads(path.read_text(), object_pairs_hook=unique)
    if (set(release) != {'schema_version', 'version', 'source_sha', 'builder', 'files'} or
        release['schema_version'] != 1 or release['version'] != version or
        not re.fullmatch(r'[0-9a-f]{40}', release['source_sha']) or
        not re.fullmatch(r'https://github\.com/netsec-ethz/debuglet/actions/runs/[1-9][0-9]*', release['builder'])):
        raise ValueError('release identity does not match')
    for name in names:
        expected = release['files'][name]
        data = root / name
        with data.open('rb') as stream:
            actual = {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'bytes': data.stat().st_size}
        if expected != actual:
            raise ValueError('signed subject mismatch')
    print('Verified release ' + version + ' signed by ' + signer + ' from source ' + release['source_sha'])
except (OSError, ValueError, KeyError, TypeError):
    sys.exit('bootstrap: signed release identity or content verification failed; no installer was run')
VERIFY_RELEASE
fi

archive_digest= installer_digest=
while IFS= read -r line || [ -n "$line" ]; do
	digest=${line%% *}
	[ "${#digest}" -eq 64 ] || fail 'invalid checksum digest'
	case "$digest" in *[!0-9a-f]*) fail 'invalid checksum digest' ;; esac
	name=${line#"$digest  "}
	[ "$line" = "$digest  $name" ] || fail 'invalid checksum entry'
	case "$name" in
		"$archive_name") [ -z "$archive_digest" ] || fail 'duplicate package checksum'; archive_digest=$digest ;;
		"$installer_name") [ -z "$installer_digest" ] || fail 'duplicate installer checksum'; installer_digest=$digest ;;
		*) fail 'checksums must name only the selected package and install.sh' ;;
	esac
done < "$work/$checksums_name"
[ -n "$archive_digest" ] && [ -n "$installer_digest" ] || fail 'package checksums are incomplete'
(cd "$work" && sha256sum --check --strict "$checksums_name" > /dev/null 2>&1) || fail 'checksum verification failed; no installer was run'

sh "$work/$installer_name" --archive "$work/$archive_name" \
	--checksums "$work/$checksums_name" --version "$version" --prefix "$prefix" || fail 'package installer failed'

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
if [ -n "$component" ]; then
	printf 'Installed component: %s\n' "$component"
	exit 0
fi
shell_quote "$prefix/bin/dbl"
printf ' --output json demo\n'
shell_quote "$prefix/bin/dbl"
printf ' up\n'
