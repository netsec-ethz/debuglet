#!/usr/bin/env bash
# Source from a lane after creating its temporary installation prefix.
install_candidate() {
    local prefix=$1 log=$2 package_dir=$3 requested_archive=${4:-} requested_checksums=${5:-}
    local archive_name installer_hash= hash filename extra
    if [[ -n "$requested_archive" ]]; then
        archive=$(realpath -e "$requested_archive")
        package_dir=$(dirname "$archive")
    else
        local archives=("$package_dir"/debuglet-v*-linux-amd64.tar.gz)
        [[ ${#archives[@]} == 1 && -f "${archives[0]}" ]] || { echo 'expected one candidate archive' >&2; return 1; }
        archive=$(realpath -e "${archives[0]}")
    fi
    package_dir=$(realpath -e "$package_dir")
    checksums=$(realpath -e "${requested_checksums:-$package_dir/SHA256SUMS}")
    archive_name=${archive##*/}
    [[ "$archive_name" =~ ^debuglet-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-linux-amd64\.tar\.gz$ ]] || { echo 'invalid candidate archive name' >&2; return 1; }
    [[ -f "$archive" && -f "$package_dir/install.sh" && -f "$checksums" ]] || { echo 'missing candidate inputs' >&2; return 1; }
    version=${archive_name#debuglet-}; version=${version%-linux-amd64.tar.gz}
    archive_hash=
    # Only the archive and installer may appear; check both before executing either.
    while read -r hash filename extra || [[ -n "${hash:-}${filename:-}${extra:-}" ]]; do
        [[ "$hash" =~ ^[0-9a-f]{64}$ && -z "$extra" ]] || { echo 'invalid candidate checksums' >&2; return 1; }
        case "$filename" in
            "$archive_name") [[ -z "$archive_hash" ]] || return 1; archive_hash=$hash ;;
            install.sh) [[ -z "$installer_hash" ]] || return 1; installer_hash=$hash ;;
            *) echo 'unexpected candidate checksum member' >&2; return 1 ;;
        esac
    done < "$checksums"
    [[ -n "$archive_hash" && -n "$installer_hash" ]] || { echo 'candidate checksums are incomplete' >&2; return 1; }
    (cd "$package_dir" && sha256sum --check --strict "$checksums") >&2
    sh "$package_dir/install.sh" --archive "$archive" --checksums "$checksums" \
        --version "$version" --prefix "$prefix" > "$log"
    installed_root="$prefix/lib/debuglet/$version"
    "${GO:-go}" run -mod=readonly ./internal/packaging verify -installed-root "$installed_root"
}
