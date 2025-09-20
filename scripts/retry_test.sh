#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <test-filter> [runs=5] [timeout=120]" >&2
  exit 2
fi

FILTER="$1"
RUNS=${2:-5}
TIMEOUT=${3:-120}

PASS=0
FAIL=0

for i in $(seq 1 "$RUNS"); do
  echo "\n===> Run $i/$RUNS: $FILTER (timeout ${TIMEOUT}s)"
  if command -v cargo-nextest >/dev/null 2>&1; then
    python3 - "$TIMEOUT" cargo nextest run --all-features -E "$FILTER" --profile default <<'PY'
import sys, subprocess
limit=float(sys.argv[1]); cmd=sys.argv[2:]
try:
    subprocess.run(cmd, timeout=limit, check=True)
    sys.exit(0)
except subprocess.TimeoutExpired:
    print("timeout", file=sys.stderr); sys.exit(124)
except subprocess.CalledProcessError as e:
    sys.exit(e.returncode)
PY
  else
    python3 - "$TIMEOUT" cargo test --all-features "$FILTER" -- --nocapture <<'PY'
import sys, subprocess
limit=float(sys.argv[1]); cmd=sys.argv[2:]
try:
    subprocess.run(cmd, timeout=limit, check=True)
    sys.exit(0)
except subprocess.TimeoutExpired:
    print("timeout", file=sys.stderr); sys.exit(124)
except subprocess.CalledProcessError as e:
    sys.exit(e.returncode)
PY
  fi
  rc=$?
  if [ $rc -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
done

echo "\nSummary for $FILTER: PASS=$PASS FAIL=$FAIL"
if [ $FAIL -gt 0 ]; then exit 1; fi
