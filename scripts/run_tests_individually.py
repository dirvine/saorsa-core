#!/usr/bin/env python3
"""
Run tests that fail due to Prometheus metrics registration conflicts.

These tests pass individually but fail when run in parallel due to global
registry conflicts in the Prometheus metrics system.
"""

import subprocess
import sys

# Tests that need to be run individually
INDIVIDUAL_TESTS = [
    "adaptive::client::tests::test_client_connect",
    "adaptive::client::tests::test_client_creation", 
    "adaptive::client::tests::test_compute_job",
    "adaptive::client::tests::test_network_stats",
    "adaptive::client::tests::test_not_connected_error",
    "adaptive::client::tests::test_pubsub_messaging",
    "adaptive::client::tests::test_storage_operations",
]

def run_test(test_name):
    """Run a single test and return whether it passed."""
    cmd = ["cargo", "test", "--lib", test_name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

def main():
    print("Running tests individually to avoid metrics conflicts...")
    print("-" * 60)
    
    failed_tests = []
    passed_tests = []
    
    for test in INDIVIDUAL_TESTS:
        print(f"Running {test}...", end=" ")
        if run_test(test):
            print("✓ PASSED")
            passed_tests.append(test)
        else:
            print("✗ FAILED")
            failed_tests.append(test)
    
    print("-" * 60)
    print(f"Results: {len(passed_tests)} passed, {len(failed_tests)} failed")
    
    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"  - {test}")
        sys.exit(1)
    else:
        print("\nAll tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()