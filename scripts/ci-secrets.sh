#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/ci/secrets
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --location \
    https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
    --output "$work/gitleaks.tar.gz"
echo '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks.tar.gz' \
    | (cd "$work" && sha256sum --check --strict)
tar -xzf "$work/gitleaks.tar.gz" -C "$work" gitleaks
scanner="$work/gitleaks"
"$scanner" version > .cache/ci/secrets/version.txt
# Construct a deliberately invalid token only in a temporary scanner fixture.
mkdir "$work/fixture"
printf 'token = "%s%s"\n' 'ghp_' 'd9F2m7Qa4Z6c8Vk1Xs3Bp5Ht0Nu2Ry4We6Ld' > "$work/fixture/control.txt"
set +e
python3 tools/scan-secrets.py --scanner "$scanner" --report .cache/ci/secrets/control.json \
    -- dir "$work/fixture" > .cache/ci/secrets/control.txt
status=$?
set -e
[[ $status == 1 ]] || { echo 'secret scanner did not reject its canary' >&2; exit 1; }
base=${CI_SCAN_BASE:-}
[[ "$base" =~ ^[0-9a-f]{40}$ ]] || { echo 'missing source scan base revision' >&2; exit 1; }
git cat-file -e "$base^{commit}"
python3 tools/scan-secrets.py --scanner "$scanner" --report .cache/ci/secrets/source.json \
    -- git --log-opts="$base..HEAD" --ignore-gitleaks-allow .
# Scan the produced archive and installer; binary entries remain in scope.
python3 tools/scan-secrets.py --scanner "$scanner" --report .cache/ci/secrets/package.json \
    -- dir --max-archive-depth=2 --ignore-gitleaks-allow .cache/ci/packages
