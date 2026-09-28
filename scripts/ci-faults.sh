#!/usr/bin/env bash
# Existing local fixtures only; the launcher supplies a network-isolated container.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/ci/faults
: > .cache/ci/faults/commands.txt
: "${DEBUGLET_FAULT_ISOLATED:?Run through scripts/ci-github.sh faults}"
export GOPROXY=off GOSUMDB=off
selections=(
    './cmd/executor:TestExecutorCommandReconnectWithRealGuest'
    './internal/executor:TestRecoveryLeaseBlocksGuestEntryAfterDelayedStep|TestRecoveryReconnectWaitsForCleanupAndQuarantinesQueue|TestOperationOutputSendFailureCancelsProducer'
    './internal/dispatcher:TestOutputStreamFailureIsNoTerminalResult|TestRestoreSchedulerSkipsFinishedRuns'
    './internal/dispatcher/transport/rpc:TestLeaseBothChannelPartitions'
    './internal/executor/scheduler/sqlite:TestRestoreDoesNotReplayStartedWork|TestSQLiteReservedWriteSurvivesLeaseLossAndShutdown'
    './internal/executor/debuglet/netpolicy:TestAdmitDestinationFollowsDNSChanges|TestResolutionFailuresAreAlsoBounded'
    './internal/executor/tagger/tesla:TestNoSigningKeyBeforeEpochOne|TestFirstSigningKeyDisclosedAfterItsEpoch|TestExhaustedChainHasNoSigningKey'
)
{
    git rev-parse HEAD
    printf 'Container limits: network=none cpus=4 memory=4g pids=512\n'
    printf 'Iterations: 3; each package timeout: 3m; package parallelism: 1\n'
} > .cache/ci/faults/config.txt
for iteration in 1 2 3; do
    for selection in "${selections[@]}"; do
        package=${selection%%:*}
        tests=${selection#*:}
        name=${package#./}
        report=".cache/ci/faults/${name//\//-}-$iteration.json"
        printf 'go test -race -count=1 -p 1 -timeout=3m %s -run ^(%s)$\n' "$package" "$tests" \
            >> .cache/ci/faults/commands.txt
        "${GO:-go}" test -mod=readonly -race -json -count=1 -p 1 -timeout=3m \
            "$package" -run "^($tests)$" | tee "$report"
        required=()
        IFS='|' read -r -a names <<< "$tests"
        for test in "${names[@]}"; do required+=(--test "$package:$test"); done
        python3 tools/check-evidence.py --evidence "$report" "${required[@]}"
    done
done
