#!/bin/bash

# Adaptive Network Test Runner
# Tests all adaptive network components comprehensively

set -e

echo "=================================="
echo "Adaptive Network Test Suite"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${YELLOW}Running:${NC} $test_name"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if $test_command 2>&1 | tee /tmp/test_output.log; then
        echo -e "${GREEN}✓ PASSED:${NC} $test_name\n"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED:${NC} $test_name\n"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "Error output:"
        tail -n 20 /tmp/test_output.log
        echo ""
    fi
}

# Build the project first
echo "Building project..."
cargo build --release --all-features

echo ""
echo "Running Adaptive Network Tests..."
echo "=================================="

# Individual component tests
run_test "Thompson Sampling Adaptation" \
    "cargo test --release test_thompson_sampling_adaptation -- --nocapture"

run_test "Multi-Armed Bandit Routing" \
    "cargo test --release test_multi_armed_bandit_routing -- --nocapture"

run_test "Q-Learning Cache Optimization" \
    "cargo test --release test_q_learning_cache_optimization -- --nocapture"

run_test "LSTM Churn Prediction" \
    "cargo test --release test_lstm_churn_prediction -- --nocapture"

run_test "Adaptive Eviction Strategies" \
    "cargo test --release test_adaptive_eviction_strategies -- --nocapture"

run_test "Adaptive Replication" \
    "cargo test --release test_adaptive_replication -- --nocapture"

run_test "Adaptive Gossip Protocol" \
    "cargo test --release test_adaptive_gossip_protocol -- --nocapture"

run_test "Security Monitoring" \
    "cargo test --release test_security_monitoring -- --nocapture"

# Comprehensive tests
echo ""
echo "Running Comprehensive Tests..."
echo "=================================="

run_test "Full Adaptive Network Simulation" \
    "cargo test --release test_full_adaptive_network_simulation -- --nocapture"

run_test "Network Resilience Under Stress" \
    "cargo test --release test_adaptive_network_resilience -- --nocapture"

run_test "Performance Optimization" \
    "cargo test --release test_adaptive_performance_optimization -- --nocapture"

# Run existing adaptive tests
echo ""
echo "Running Existing Adaptive Tests..."
echo "=================================="

run_test "Coordinator Integration" \
    "cargo test --release coordinator_integration_test -- --nocapture"

run_test "Multi-Armed Bandit Benchmarks" \
    "cargo test --release --test multi_armed_bandit_test -- --nocapture"

run_test "Q-Learning Tests" \
    "cargo test --release --test q_learning_test -- --nocapture"

# Summary
echo ""
echo "=================================="
echo "Test Summary"
echo "=================================="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed successfully!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed. Please review the output above.${NC}"
    exit 1
fi