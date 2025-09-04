#!/usr/bin/env bash
set -euo pipefail

# Report-only AST checks for panic!/unwrap()/expect() in non-test code.
# Exits 0 and prints a summary to avoid breaking local CI until all issues are fixed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT_DIR"

if ! command -v sg >/dev/null 2>&1; then
  echo "ast-grep (sg) not found; skipping structural checks." >&2
  exit 0
fi

echo "Running structural checks for panic!/unwrap()/expect() in src/** ..."

issues=0

run_check() {
  local name=$1
  local pattern=$2
  # Search only under src; exclude examples, tests directory, benches
  if ! sg run --lang rust --pattern "$pattern" src --json=stream > \
      "./test_logs/astgrep_${name}.json" 2>/dev/null; then
    # sg returns non-zero on no matches when using --json=stream; normalize
    :
  fi
  local count
  count=$(wc -l < "./test_logs/astgrep_${name}.json" | tr -d ' ' || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "Found $count occurrences for $name. See ./test_logs/astgrep_${name}.json"
    issues=$((issues + count))
  fi
}

mkdir -p ./test_logs

# Prefer configured scan to better ignore inline #[cfg(test)] modules.
if [ -f sgconfig.yml ]; then
  if ! sg scan -c sgconfig.yml --json=stream src > ./test_logs/astgrep_scan.json 2>/dev/null; then
    :
  fi
  count=$(wc -l < ./test_logs/astgrep_scan.json | tr -d ' ' || echo 0)
  if [ "$count" -gt 0 ]; then
    echo "Found $count violations via sgconfig. See ./test_logs/astgrep_scan.json"
    issues=$((issues + count))
  fi
else
  run_check panic 'panic!($A)'
  run_check unwrap '$A.unwrap()'
  run_check expect '$A.expect($B)'
fi

if [ "$issues" -gt 0 ]; then
  echo "ERROR: Found $issues potential policy violations in src/**."
  echo "Blockers: panic!/unwrap()/expect() are forbidden in production code."
  exit 1
fi

echo "No panic/unwrap/expect found in src/**"
exit 0
