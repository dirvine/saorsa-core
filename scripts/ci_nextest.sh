#!/usr/bin/env bash
set -euo pipefail

if command -v cargo-nextest >/dev/null 2>&1; then
  echo "Running tests with cargo-nextest (timeouts enforced)..."
  cargo nextest run --all-features --profile default
else
  echo "cargo-nextest not found; falling back to scripts/chunked_tests.sh"
  "$(dirname "$0")/chunked_tests.sh"
fi
