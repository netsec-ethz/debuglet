#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# ci-local supplies the same verified installation used by its original flow.
: "${DEBUGLET_LOCAL_INSTALL_ROOT:?Run make ci-local to install the candidate first}"
: "${DEBUGLET_LOCAL_SOURCE_ROOT:?Missing matching source root}"
: "${DEBUGLET_LOCAL_SOURCE_SHA:?Missing candidate revision}"
mkdir -p .cache/ci
evidence="$(realpath .cache/ci)/role-evidence"
mkdir -p -m 0700 "$evidence"
export DEBUGLET_ROLE_EVIDENCE_DIR="$evidence"
GOOS=wasip1 GOARCH=wasm "${GO:-go}" build -mod=readonly -trimpath -o "$evidence/experiment-peer.wasm" ./examples/experiments/peer
export DEBUGLET_EXPERIMENT_WASM="$evidence/experiment-peer.wasm"
# Exercise the actual previous release, not a rebuild with a similar version.
previous="$(realpath .cache/ci)/previous-release"
mkdir -p "$previous"
base=https://github.com/netsec-ethz/debuglet/releases/download/v0.2.0
for file in debuglet-v0.2.0-linux-amd64.tar.gz install.sh; do
  curl --fail --location --retry 2 --max-time 180 "$base/$file" -o "$previous/$file"
done
cat > "$previous/SHA256SUMS" <<'EOF'
dc7e8f4f53c721ed3d484fdd97246082cb7a682e1e382de9e9671bcfafacac45  debuglet-v0.2.0-linux-amd64.tar.gz
be84201ebda835e52be8749de3947ed399892939f2700b97a86df7511abe614b  install.sh
EOF
(cd "$previous" && sha256sum --check --strict SHA256SUMS)
sh "$previous/install.sh" --archive "$previous/debuglet-v0.2.0-linux-amd64.tar.gz" \
  --checksums "$previous/SHA256SUMS" --version v0.2.0 --prefix "$previous/installed" \
  > .cache/ci/role-previous-install.log
export DEBUGLET_PREVIOUS_INSTALL_ROOT="$previous/installed/lib/debuglet/v0.2.0"
"${GO:-go}" test -mod=readonly -json -tags=roles_integration -count=1 -timeout=5m \
  ./internal/acceptance/roles -run '^TestInstalled(Roles|BackupRestore|Recovery|Output|ReleasedCompatibility|ReleasedUpgrade|Rendezvous|Experiment)$' | tee .cache/ci/role-tests.json
python3 tools/check-evidence.py --test ./internal/acceptance/roles:TestInstalledRoles \
  --test ./internal/acceptance/roles:TestInstalledBackupRestore \
  --test ./internal/acceptance/roles:TestInstalledRecovery \
  --test ./internal/acceptance/roles:TestInstalledOutput \
  --test ./internal/acceptance/roles:TestInstalledReleasedCompatibility \
  --test ./internal/acceptance/roles:TestInstalledReleasedUpgrade \
  --test ./internal/acceptance/roles:TestInstalledRendezvous \
  --test ./internal/acceptance/roles:TestInstalledExperiment \
  --test ./internal/acceptance/roles:TestInstalledRecovery/graceful \
  --test ./internal/acceptance/roles:TestInstalledRecovery/terminated \
  --evidence .cache/ci/role-tests.json
