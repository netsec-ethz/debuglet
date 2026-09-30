#!/usr/bin/env bash
# Execute one CI lane in a disposable container on a Linux runner.
set -euo pipefail
cd "$(dirname "$0")/.."
lane=${1:-}
case "$lane" in
    fmt|vet|generate|build|test|race|package|demo|compatibility|local|kernel|secrets|faults|soak|offline|vulnerabilities|image-vulnerabilities) ;;
    *) echo "unknown CI lane: $lane" >&2; exit 2 ;;
esac

if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    [[ ${GITHUB_REPOSITORY:-} == netsec-ethz/debuglet &&
       ${RUNNER_ENVIRONMENT:-} == github-hosted &&
       ${RUNNER_OS:-} == Linux && ${RUNNER_ARCH:-} == X64 ]] || {
        echo 'CI requires the official repository and a GitHub-hosted Linux X64 VM.' >&2; exit 1;
    }
    case "${GITHUB_EVENT_NAME:-}:${GITHUB_REF:-}" in
        push:refs/heads/main|schedule:refs/heads/main|\
        workflow_dispatch:refs/heads/*) ;;
        pull_request:refs/pull/*/merge)
            [[ ${GITHUB_REF:-} =~ ^refs/pull/[0-9]+/merge$ &&
               ${GITHUB_BASE_REF:-} == main ]] || {
                echo 'pull request CI requires a merge ref targeting main' >&2; exit 1;
            }
            ;;
        *) echo 'unsupported CI event or ref' >&2; exit 1 ;;
    esac
    [[ $(git rev-parse HEAD) == "${GITHUB_SHA:-}" ]] || {
        echo 'checkout does not match the workflow commit' >&2; exit 1;
    }
fi

# shellcheck source=deploy/ci/images.env
. deploy/ci/images.env
image="${DEBUGLET_CI_BASE_IMAGE}@${DEBUGLET_CI_BASE_DIGEST}"
profile=base
options=()
case "$lane" in
    local|kernel) image=$DEBUGLET_CI_TOOLS_IMAGE; profile=$lane ;;
esac
if [[ $lane == kernel ]]; then
    options+=(--cap-add BPF --cap-add NET_ADMIN --cap-add NET_RAW --cap-add PERFMON --cap-add SYS_RESOURCE)
fi
# Hosted jobs start with a fresh VM. Local reproduction can use prepared images.
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    docker pull "${DEBUGLET_CI_BASE_IMAGE}@${DEBUGLET_CI_BASE_DIGEST}"
    if [[ $profile != base ]]; then
        docker build --tag "$DEBUGLET_CI_TOOLS_IMAGE" --file deploy/ci/Dockerfile \
            --build-arg "BASE_IMAGE=$DEBUGLET_CI_BASE_IMAGE" \
            --build-arg "BASE_DIGEST=$DEBUGLET_CI_BASE_DIGEST" \
            --build-arg "DEBIAN_SNAPSHOT=$DEBUGLET_CI_DEBIAN_SNAPSHOT" \
            --build-arg "TOOLS_IMAGE=$DEBUGLET_CI_TOOLS_IMAGE" deploy/ci
    fi
fi
if [[ $lane == image-vulnerabilities ]]; then
    bash scripts/ci-image-vulnerabilities.sh build
fi
image_id=$(docker image inspect --format '{{.Id}}' "$image")
name="debuglet-ci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$lane-$$"
prepare_name="$name-modules"
cleanup() {
    local status=$?
    if [[ $lane == faults || $lane == soak ]]; then
        mkdir -p ".cache/ci/$lane"
        docker rm --force "$name" "$prepare_name" >/dev/null 2>&1 || true
        if remaining=$(docker container ls --all --format '{{.Names}}') &&
            ! grep -Fxq -e "$name" -e "$prepare_name" <<< "$remaining"; then
            printf '{"container":"%s","preparation_container":"%s","removed":true,"test_status":%s}\n' \
                "$name" "$prepare_name" "$status" > ".cache/ci/$lane/cleanup.json"
        else
            echo "$lane container cleanup could not be verified" >&2
            status=1
        fi
    else
        docker rm --force "$name" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Only public build identity enters the container. In particular, no Actions
# token, runner directory, Docker socket or deployment credential is mounted.
forward=()
for key in GITHUB_ACTIONS GITHUB_EVENT_NAME GITHUB_REPOSITORY GITHUB_REF GITHUB_BASE_REF \
    GITHUB_REF_PROTECTED GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_JOB \
    GITHUB_SERVER_URL CI_SCAN_BASE RUNNER_NAME RUNNER_ENVIRONMENT RUNNER_OS RUNNER_ARCH; do
    [[ -z ${!key+x} ]] || forward+=(--env "$key")
done
# Fetch dependencies before local fixtures enter their no-network boundary.
if [[ $lane == faults || $lane == soak ]]; then
    docker run --rm --init --pull=never --name "$prepare_name" \
        --mount "type=bind,source=$PWD,target=/workspace,readonly" \
        --mount type=volume,source=debuglet-ci-go-mod,target=/go/pkg/mod \
        --workdir /workspace --env GOTOOLCHAIN=local "$image" go mod download
    options+=(--network none --cpus 4 --memory 4g --pids-limit 512)
    if [[ $lane == faults ]]; then
        options+=(--env DEBUGLET_FAULT_ISOLATED=1)
    else
        options+=(--env DEBUGLET_SOAK_ISOLATED=1)
    fi
fi
docker run --rm --init --pull=never --name "$name" \
    --mount "type=bind,source=$PWD,target=/workspace" \
    --mount type=volume,source=debuglet-ci-go-mod,target=/go/pkg/mod \
    --mount type=volume,source=debuglet-ci-go-build,target=/go/build-cache \
    --workdir /workspace \
    --env GOTOOLCHAIN=local --env GOMAXPROCS=4 \
    --env GOMODCACHE=/go/pkg/mod --env GOCACHE=/go/build-cache \
    --env "DEBUGLET_CI_JOB_IMAGE=$image" --env "DEBUGLET_CI_IMAGE_ID=$image_id" \
    "${forward[@]+"${forward[@]}"}" "${options[@]+"${options[@]}"}" "$image" bash -ceu '
        trap '\''chown -R "$3" /workspace'\'' EXIT
        git config --global --add safe.directory /workspace
        if [[ ${GITHUB_ACTIONS:-} == true ]]; then
            export CI_COMMIT_TAG=""
            export CI_COMMIT_REF_PROTECTED="$GITHUB_REF_PROTECTED"
            export CI_PIPELINE_URL="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
        fi
        bash deploy/ci/verify-image.sh "$2"
        case "$1" in
            fmt) python3 -m unittest -v tools/test_ci_fmt.py; make ci-fmt ;;
            generate) bash scripts/ci-generate.sh check ;;
            race) python3 -m unittest -v tools/test_check_evidence.py; make ci-race ;;
            secrets) python3 -m unittest -v tools/test_ci_security.py; bash "scripts/ci-$1.sh" ;;
            vulnerabilities) python3 -m unittest -v tools/test_ci_vulnerabilities.py; bash scripts/ci-vulnerabilities.sh ;;
            image-vulnerabilities) python3 -m unittest -v tools/test_ci_image_vulnerabilities.py; bash scripts/ci-image-vulnerabilities.sh scan ;;
            faults) bash scripts/ci-faults.sh ;;
            soak) bash scripts/ci-soak.sh ;;
            offline)
                mkdir -p .cache/ci/offline-evidence
                . scripts/ci-install-candidate.sh
                install_candidate "$PWD/.cache/ci/offline-install" .cache/ci/offline-evidence/install.log \
                    .cache/ci/packages > .cache/ci/offline-evidence/verify.json
                printf "%s\n" "$version" > .cache/ci/offline-version.txt
                ;;
            *) make "ci-$1" ;;
        esac
    ' -- "$lane" "$profile" "$(id -u):$(id -g)"

if [[ $lane == kernel ]]; then
    bash scripts/ci-shared-workers.sh
fi
