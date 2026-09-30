#!/usr/bin/env bash
# Build images on the disposable runner, then scan saved archives in the
# ordinary CI container. The scanner never receives a Docker socket.
set -euo pipefail
cd "$(dirname "$0")/.."
evidence="$PWD/.cache/ci/image-vulnerabilities"
archives="$PWD/.cache/ci/image-archives"
mkdir -p "$evidence" "$archives"
case "${1:-}" in
    build)
        revision=$(git rev-parse HEAD)
        [[ -z $(git status --porcelain) ]] || { echo 'image scan requires a clean checkout' >&2; exit 1; }
        printf '%s\n' "$revision" > "$evidence/source.txt"
        for role in full cli dispatcher executor; do
            image="debuglet-$role:ci-$revision"
            docker build --platform linux/amd64 --pull=false --target "$role" \
                -f deploy/docker/debuglet.Dockerfile -t "$image" . > "$evidence/build-$role.log" 2>&1
            docker image inspect --format '{{.Id}}' "$image" > "$evidence/image-$role.txt"
            docker save --output "$archives/$role.tar" "$image"
            sha256sum "$archives/$role.tar" > "$evidence/archive-$role.sha256"
        done
        ;;
    scan)
        work=$(mktemp -d)
        trap 'rm -rf -- "$work"' EXIT
        curl --fail --location --retry 2 --max-time 180 \
            https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_amd64.tar.gz \
            -o "$work/grype.tar.gz"
        printf '%s  %s\n' 3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b "$work/grype.tar.gz" | sha256sum --check --strict
        tar -xf "$work/grype.tar.gz" -C "$work" grype
        scanner="$work/grype"
        export GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_CACHE_DIR="$work/db"
        "$scanner" version -o json > "$evidence/scanner.json"
        timeout 8m "$scanner" db update > "$evidence/database-update.log" 2>&1
        "$scanner" db status -o json > "$evidence/database.json"
        export GRYPE_DB_AUTO_UPDATE=false
        scan() {
            local target=$1 report=$2
            # Preserve a bounded report even when a scanner misbehaves; a
            # truncated document or failing process never reaches a clean gate.
            timeout 5m "$scanner" "$target" -o json 2> >(head -c 65536 > "$evidence/$report.stderr") \
                | head -c 33554433 > "$evidence/$report.json"
            [[ $(stat -c %s "$evidence/$report.json") -le 33554432 ]]
        }
        # Only a package identifier is scanned. No vulnerable executable is
        # fetched, executed, or added to a supported runtime image.
        scan 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' control
        set +e
        python3 tools/check-image-vulnerabilities.py "$evidence/control.json" \
            tools/image-vulnerability-exceptions.json control - > "$evidence/control.txt"
        status=$?
        set -e
        [[ $status == 1 ]] || { echo 'known vulnerable image-scanner control was not rejected' >&2; exit 1; }
        grep -q 'GHSA-jfh8-c2jp-5v3q' "$evidence/control.txt"
        status=0
        for role in full cli dispatcher executor; do
            scan "docker-archive:$archives/$role.tar" "$role"
            python3 tools/check-image-vulnerabilities.py "$evidence/$role.json" \
                tools/image-vulnerability-exceptions.json "$role" "$archives/$role.tar" \
                > "$evidence/$role.txt" || status=1
            cat "$evidence/$role.txt"
        done
        exit "$status"
        ;;
    *) echo 'usage: ci-image-vulnerabilities.sh build|scan' >&2; exit 2 ;;
esac
