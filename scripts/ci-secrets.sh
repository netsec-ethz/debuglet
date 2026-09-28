#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# New tags have an all-zero before SHA. Scan their complete reachable history;
# choosing HEAD as an ordinary base would silently scan an empty range.
secret_scan_range() {
    local base=${1:-}
    if [[ -z "$base" || "$base" == 0000000000000000000000000000000000000000 ]]; then
        git rev-parse --verify HEAD^{commit} >/dev/null
        printf '%s\n' HEAD
        return
    fi
    [[ "$base" =~ ^[0-9a-f]{40}$ ]] || { echo 'invalid source scan base revision' >&2; return 1; }
    git cat-file -e "$base^{commit}" || return 1
    git merge-base --is-ancestor "$base" HEAD || return 1
    printf '%s..HEAD\n' "$base"
}
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return; fi
repo=$PWD
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
scan() {
    python3 "$repo/tools/scan-secrets.py" --scanner "$scanner" --exceptions "$repo/.gitleaksignore" "$@"
}
# Construct a deliberately invalid token only in a temporary scanner fixture.
# The control exempts one exact finding; the same token on another line, in
# another file, or under an exception for another rule must still be rejected.
mkdir "$work/fixture"
canary=$(printf 'token = "%s%s"' 'ghp_' 'd9F2m7Qa4Z6c8Vk1Xs3Bp5Ht0Nu2Ry4We6Ld')
printf '%s\n%s\n' "$canary" "$canary" > "$work/fixture/exempt.txt"
printf '%s\n' "$canary" > "$work/fixture/other.txt"
printf '%s\n' "$canary" > "$work/fixture/wrong-rule.txt"
printf '%s\n' 'exempt.txt:github-pat:1' 'wrong-rule.txt:generic-api-key:1' > "$work/control-exceptions"
set +e
(cd "$work/fixture" && python3 "$repo/tools/scan-secrets.py" --scanner "$scanner" \
    --exceptions "$work/control-exceptions" --report "$repo/.cache/ci/secrets/control.json" \
    -- dir .) > .cache/ci/secrets/control.txt
status=$?
set -e
[[ $status == 1 ]] || { echo 'secret scanner did not reject its canary' >&2; exit 1; }
python3 - .cache/ci/secrets/control.json <<'EOF' || { echo 'secret scan exceptions are not exact' >&2; exit 1; }
import json, sys
found = {(f['File'], f['RuleID'], f['StartLine']) for f in json.load(open(sys.argv[1]))}
sys.exit(found != {('exempt.txt', 'github-pat', 2), ('other.txt', 'github-pat', 1),
                   ('wrong-rule.txt', 'github-pat', 1)})
EOF
scan_range=$(secret_scan_range "${CI_SCAN_BASE:-}")
scan --report .cache/ci/secrets/source.json -- git --log-opts="$scan_range" --ignore-gitleaks-allow .
# Scan every tracked file at HEAD; existing fixtures pass only via exact exceptions.
mkdir "$work/tree"
git archive --format=tar HEAD | tar -xf - -C "$work/tree"
(cd "$work/tree" && scan --report "$repo/.cache/ci/secrets/tree.json" -- dir --ignore-gitleaks-allow .)
# Scan the produced archive and installer; binary entries remain in scope.
scan --report .cache/ci/secrets/package.json \
    -- dir --max-archive-depth=2 --ignore-gitleaks-allow .cache/ci/packages
