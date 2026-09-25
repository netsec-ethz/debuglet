#!/bin/sh
# Generated for one package. Obtain SHA256SUMS from the same trusted source
# as the archive; these checksums are not signatures.
set -eu
LC_ALL=C
export LC_ALL
unset TAR_OPTIONS GZIP POSIXLY_CORRECT
umask 077

candidate_version='@VERSION@'
candidate_source='@SOURCE_SHA@'
payload_sums='@PAYLOAD_SUMS@'

fail() { printf 'install: %s\n' "$*" >&2; exit 1; }

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

valid_digest() {
	[ "${#1}" -eq 64 ] || return 1
	case "$1" in *[!0-9a-f]*) return 1 ;; esac
}

archive_arg= checksums_arg= version_arg= prefix_arg=
while [ "$#" -gt 0 ]; do
	[ "$#" -ge 2 ] || fail 'every option requires a value'
	case "$1" in
		--archive) [ -z "$archive_arg" ] || fail 'duplicate --archive'; archive_arg=$2 ;;
		--checksums) [ -z "$checksums_arg" ] || fail 'duplicate --checksums'; checksums_arg=$2 ;;
		--version) [ -z "$version_arg" ] || fail 'duplicate --version'; version_arg=$2 ;;
		--prefix) [ -z "$prefix_arg" ] || fail 'duplicate --prefix'; prefix_arg=$2 ;;
		*) fail "unknown option: $1" ;;
	esac
	[ -n "$2" ] || fail 'option values must not be empty'
	shift 2
done
[ -n "$archive_arg" ] && [ -n "$checksums_arg" ] && [ -n "$version_arg" ] && [ -n "$prefix_arg" ] ||
	fail 'usage: install.sh --archive FILE --checksums FILE --version VERSION --prefix DIR'
valid_version "$candidate_version" && valid_version "$version_arg" || fail 'invalid candidate version'
[ "$version_arg" = "$candidate_version" ] || fail 'version does not match this installer'
[ "${#candidate_source}" -eq 40 ] || fail 'invalid candidate source revision'
case "$candidate_source" in *[!0-9a-f]*) fail 'invalid candidate source revision' ;; esac
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || fail 'this candidate requires Linux amd64'

# Resolve inputs before any directory changes. Reject newlines, which shell
# command substitution cannot preserve in the final component of a pathname.
absolute_path() {
	case "$1" in
		*'
'*) fail 'newlines in installation paths are unsupported' ;;
		/*) printf '%s\n' "$1" ;;
		*) printf '%s/%s\n' "$(pwd -P)" "$1" ;;
	esac
}
archive_input=$(absolute_path "$archive_arg")
checksums_input=$(absolute_path "$checksums_arg")
installer_input=$(absolute_path "$0")
prefix_input=$(absolute_path "$prefix_arg")
for input in "$archive_input" "$checksums_input" "$installer_input"; do
	[ -f "$input" ] && [ ! -L "$input" ] || fail "input must be a regular file: $input"
done
archive_name=debuglet-${candidate_version}-linux-amd64.tar.gz
archive_digest= installer_digest=
while IFS= read -r checksum_line || [ -n "$checksum_line" ]; do
	digest=${checksum_line%% *}
	valid_digest "$digest" || fail 'invalid SHA256SUMS digest'
	name=${checksum_line#"$digest  "}
	[ "$checksum_line" = "$digest  $name" ] || fail 'invalid SHA256SUMS entry'
	case "$name" in
		"$archive_name") [ -z "$archive_digest" ] || fail 'duplicate archive checksum'; archive_digest=$digest ;;
		install.sh) [ -z "$installer_digest" ] || fail 'duplicate installer checksum'; installer_digest=$digest ;;
		*) fail 'SHA256SUMS must contain exactly this archive and install.sh' ;;
	esac
done < "$checksums_input"
[ -n "$archive_digest" ] && [ -n "$installer_digest" ] || fail 'SHA256SUMS is incomplete'
check_digest() (
	actual=$(sha256sum < "$1") || exit 1
	[ "${actual%% *}" = "$2" ] || fail "checksum mismatch: $1"
)
check_digest "$installer_input" "$installer_digest" || fail 'installer verification failed'
check_digest "$archive_input" "$archive_digest" || fail 'archive verification failed'

installer_uid=$(id -u)
owned_directory() (
	[ -d "$1" ] && [ ! -L "$1" ] || fail "not a real directory: $1"
	[ "$(stat -c %u -- "$1")" = "$installer_uid" ] || fail "directory is not owned by this user: $1"
)
regular_owned_file() (
	[ -f "$1" ] && [ ! -L "$1" ] || fail "not a regular file: $1"
	[ "$(stat -c %u -- "$1")" = "$installer_uid" ] || fail "file is not owned by this user: $1"
)

# Inspect literal path components before creating descendants; a symlink is
# rejected even if it happens to resolve to an otherwise acceptable directory.
prefix= remaining=${prefix_input#/}
while [ -n "$remaining" ]; do
	component=${remaining%%/*}
	case "$remaining" in */*) remaining=${remaining#*/} ;; *) remaining= ;; esac
	case "$component" in ''|.) continue ;; ..) fail 'parent traversal in --prefix is unsupported' ;; esac
	prefix=$prefix/$component
	[ ! -L "$prefix" ] || fail "symlink in installation prefix: $prefix"
	if [ -e "$prefix" ]; then
		[ -d "$prefix" ] || fail "prefix component is not a directory: $prefix"
	else
		mkdir -m 0755 -- "$prefix" || fail "cannot create prefix component: $prefix"
	fi
done
[ -n "$prefix" ] || fail 'the filesystem root is not an installation prefix'
owned_directory "$prefix" || fail 'invalid installation prefix'
for directory in "$prefix/bin" "$prefix/lib" "$prefix/lib/debuglet"; do
	if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
		mkdir -m 0755 -- "$directory" || fail "cannot create managed directory: $directory"
	fi
	owned_directory "$directory" || fail 'invalid managed directory'
done
managed=$prefix/lib/debuglet
destination=$managed/$candidate_version
cli=$prefix/bin/dbl
lock= stage= link_directory=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$link_directory" ]; then rm -rf -- "$link_directory" || status=1; fi
	if [ -n "$stage" ]; then rm -rf -- "$stage" || status=1; fi
	if [ -n "$lock" ]; then rmdir -- "$lock" || status=1; fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if mkdir -m 0700 -- "$managed/.install.lock" 2>/dev/null; then
	lock=$managed/.install.lock
else
	fail 'another installer holds .install.lock; do not remove it without checking the owning invocation'
fi

check_managed_link() (
	if [ -L "$cli" ]; then
		# Preserve trailing newlines so the exact managed-link check cannot
		# accidentally accept a different link after command substitution.
		link=$(readlink -n -- "$cli" || exit 1; printf '.') || exit 1
		link=${link%.}
		case "$link" in ../lib/debuglet/*/bin/dbl) previous=${link#../lib/debuglet/}; previous=${previous%/bin/dbl} ;; *) fail 'existing bin/dbl is not a managed link' ;; esac
		valid_version "$previous" || fail 'existing bin/dbl has an invalid managed version'
		old_root=$managed/$previous
		for directory in "$old_root" "$old_root/bin" "$old_root/share" "$old_root/share/debuglet"; do
			owned_directory "$directory" || exit 1
		done
		regular_owned_file "$old_root/bin/dbl" || exit 1
		regular_owned_file "$old_root/share/debuglet/manifest.json" || exit 1
	elif [ -e "$cli" ]; then
		fail 'existing bin/dbl is unrelated to this managed installation'
	fi
)
check_managed_link || fail 'refusing to replace existing bin/dbl'

stage=$(mktemp -d "$managed/.install-stage.XXXXXXXXXX") || fail 'cannot create private stage'
# All archive reads below use this owned snapshot. Recheck after copying so a
# changed download can never bypass the checks before extraction.
cp -- "$archive_input" "$stage/archive.tar.gz" || fail 'cannot snapshot archive'
check_digest "$stage/archive.tar.gz" "$archive_digest" || fail 'archive changed while staging'
expected_names='LICENSE
README-install.md
bin/dbl
bin/debuglet-dispatcher
bin/debuglet-executor
share/debuglet/demo.wasm
share/debuglet/hello.wasm
share/debuglet/manifest.json'
tar --list --gzip --file "$stage/archive.tar.gz" --absolute-names --ignore-zeros --quoting-style=escape > "$stage/names" || fail 'cannot list archive'
names=$(sort "$stage/names") || fail 'cannot inspect archive names'
[ "$names" = "$expected_names" ] || fail 'archive must contain exactly the eight literal payload paths'
tar --list --verbose --numeric-owner --gzip --file "$stage/archive.tar.gz" --absolute-names --ignore-zeros --quoting-style=escape > "$stage/details" || fail 'cannot inspect archive metadata'
member_count=0
while read -r mode owner size date clock name extra; do
	[ -z "$extra" ] || fail 'unexpected archive metadata'
	case "$name" in
		bin/dbl|bin/debuglet-dispatcher|bin/debuglet-executor) expected_mode=-rwxr-xr-x ;;
		LICENSE|README-install.md|share/debuglet/demo.wasm|share/debuglet/hello.wasm|share/debuglet/manifest.json) expected_mode=-rw-r--r-- ;;
		*) fail 'unexpected archive member' ;;
	esac
	[ "$mode" = "$expected_mode" ] || fail "archive member must be a regular file with the required mode: $name"
	member_count=$((member_count + 1))
done < "$stage/details"
[ "$member_count" -eq 8 ] || fail 'archive member count is invalid'

verify_tree() (
	root=$1
	for directory in "$root" "$root/bin" "$root/share" "$root/share/debuglet"; do
		owned_directory "$directory" || exit 1
		for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
			[ -e "$entry" ] || [ -L "$entry" ] || continue
			relative=${entry#"$root"/}
			case "$relative" in
				bin|share|share/debuglet|LICENSE|README-install.md|bin/dbl|bin/debuglet-dispatcher|bin/debuglet-executor|share/debuglet/demo.wasm|share/debuglet/hello.wasm|share/debuglet/manifest.json) ;;
				*) fail "unexpected installed entry: $relative" ;;
			esac
		done
	done
	count=0
	while IFS= read -r line || [ -n "$line" ]; do
		digest=${line%% *}
		valid_digest "$digest" || fail 'invalid embedded payload checksum'
		relative=${line#"$digest  "}
		[ "$line" = "$digest  $relative" ] || fail 'invalid embedded payload entry'
		case "$relative" in
			bin/dbl|bin/debuglet-dispatcher|bin/debuglet-executor) mode=755 ;;
			LICENSE|README-install.md|share/debuglet/demo.wasm|share/debuglet/hello.wasm|share/debuglet/manifest.json) mode=644 ;;
			*) fail 'unexpected embedded payload entry' ;;
		esac
		regular_owned_file "$root/$relative" || exit 1
		[ "$(stat -c %a -- "$root/$relative")" = "$mode" ] || fail "installed mode mismatch: $relative"
		check_digest "$root/$relative" "$digest" || exit 1
		count=$((count + 1))
	done <<PAYLOAD_DIGESTS
$payload_sums
PAYLOAD_DIGESTS
	[ "$count" -eq 8 ] || fail 'embedded payload checksums are incomplete'
)

mkdir -m 0755 -- "$stage/payload" "$stage/payload/bin" "$stage/payload/share" "$stage/payload/share/debuglet" || fail 'cannot create payload stage'
tar --extract --gzip --file "$stage/archive.tar.gz" --directory "$stage/payload" --ignore-zeros --no-same-owner --same-permissions --keep-old-files || fail 'archive extraction failed'
verify_tree "$stage/payload" || fail 'extracted candidate verification failed'
if [ -e "$destination" ] || [ -L "$destination" ]; then
	verify_tree "$destination" || fail 'existing version conflicts with this complete candidate'
else
	mv -T -n -- "$stage/payload" "$destination" || fail 'cannot publish version directory'
	[ ! -e "$stage/payload" ] || fail 'version destination appeared during publication'
fi
# Recheck under the held lock immediately before replacing the managed link.
check_managed_link || fail 'managed link changed during installation'
link_directory=$(mktemp -d "$prefix/bin/.dbl-link.XXXXXXXXXX") || fail 'cannot create private link stage'
ln -s -- "../lib/debuglet/$candidate_version/bin/dbl" "$link_directory/dbl" || fail 'cannot stage managed link'
mv -T -f -- "$link_directory/dbl" "$cli" || fail 'cannot publish managed link'
printf 'Installed Debuglet %s (%s) at %s\n' "$candidate_version" "$candidate_source" "$destination"
