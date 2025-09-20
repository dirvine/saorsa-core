#!/usr/bin/env bash

set -euo pipefail

run() {
  local name="$1"
  local timeout="$2"
  shift 2
  local logfile
  logfile=$(mktemp)
  printf '\n===> %s (timeout %ss)\n' "$name" "$timeout"
  python3 - "$timeout" "$logfile" "$@" <<'PY'
import sys, subprocess, threading, time

limit = float(sys.argv[1])
log_path = sys.argv[2]
cmd = sys.argv[3:]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

def reader(p):
    with open(log_path, "w", encoding="utf8") as log:
        for line in p.stdout:
            print(line, end="")
            log.write(line)

t = threading.Thread(target=reader, args=(proc,), daemon=True)
t.start()

start = time.monotonic()
code = 0
while True:
    rc = proc.poll()
    if rc is not None:
        code = rc
        break
    if time.monotonic() - start > limit:
        try:
            proc.kill()
        finally:
            print(f"\n!! timed out after {limit}s", file=sys.stderr)
            sys.exit(124)
    time.sleep(0.2)

sys.exit(code)
PY
  local status=$?
  if [ "$status" -ne 0 ]; then
    printf '!! %s failed (status %d)\n' "$name" "$status"
    printf '   log: %s\n' "$logfile"
    exit "$status"
  fi
  rm -f "$logfile"
}

if [[ "${CHUNKED_FMT_CHECK:-0}" == "1" ]]; then
  run "cargo fmt (check)" 120 cargo fmt --all -- --check
else
  run "cargo fmt (apply)" 120 cargo fmt --all
fi
run "cargo clippy" 900 cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
run "unit tests" 900 cargo test --lib --all-features -- --test-threads=4
run "adaptive suite" 900 cargo test --all-features adaptive:: -- --test-threads=4
run "identity management" 900 cargo test --all-features --test identity_management_test -- --nocapture
run "multi-device" 900 cargo test --all-features --test multi_device_tests -- --nocapture
