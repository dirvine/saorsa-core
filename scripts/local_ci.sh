#!/usr/bin/env bash

# Local CI/CD Workflow Script with Comprehensive Reporting
# Mimics GitHub Actions workflow locally with detailed success/failure tracking
#
# SAFETY: This script is designed to be NON-DESTRUCTIVE
# - Does NOT modify Cargo.lock
# - Does NOT install or update tools
# - Does NOT modify your Rust installation
# - Only runs read-only checks and validations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Result tracking - using regular arrays for compatibility
RESULT_KEYS=()
RESULT_VALUES=()
DEBUG_KEYS=()
DEBUG_VALUES=()
TIMING_KEYS=()
TIMING_VALUES=()
TOTAL_START=$(date +%s)

# Helper functions for array management
set_result() {
    local key=$1
    local value=$2
    RESULT_KEYS+=("$key")
    RESULT_VALUES+=("$value")
}

get_result() {
    local key=$1
    for i in "${!RESULT_KEYS[@]}"; do
        if [[ "${RESULT_KEYS[$i]}" == "$key" ]]; then
            echo "${RESULT_VALUES[$i]}"
            return
        fi
    done
    echo ""
}

set_debug() {
    local key=$1
    local value=$2
    DEBUG_KEYS+=("$key")
    DEBUG_VALUES+=("$value")
}

get_debug() {
    local key=$1
    for i in "${!DEBUG_KEYS[@]}"; do
        if [[ "${DEBUG_KEYS[$i]}" == "$key" ]]; then
            echo "${DEBUG_VALUES[$i]}"
            return
        fi
    done
    echo ""
}

set_timing() {
    local key=$1
    local value=$2
    TIMING_KEYS+=("$key")
    TIMING_VALUES+=("$value")
}

get_timing() {
    local key=$1
    for i in "${!TIMING_KEYS[@]}"; do
        if [[ "${TIMING_KEYS[$i]}" == "$key" ]]; then
            echo "${TIMING_VALUES[$i]}"
            return
        fi
    done
    echo "0"
}

# Function to print colored status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "SUCCESS" ]; then
        echo -e "${GREEN}✅ ${message}${NC}"
    elif [ "$status" = "FAILURE" ]; then
        echo -e "${RED}❌ ${message}${NC}"
    elif [ "$status" = "WARNING" ]; then
        echo -e "${YELLOW}⚠️  ${message}${NC}"
    elif [ "$status" = "INFO" ]; then
        echo -e "${BLUE}ℹ️  ${message}${NC}"
    else
        echo -e "${BOLD}${message}${NC}"
    fi
}

# Function to run a command and track results
run_step() {
    local step_name=$1
    local command=$2
    local allow_failure=${3:-false}
    
    echo -e "\n${BOLD}Running: ${step_name}${NC}"
    echo "Command: $command"
    
    local start_time=$(date +%s)
    local output_file=$(mktemp)
    local exit_code=0
    
    if eval "$command" > "$output_file" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        set_timing "$step_name" "$duration"
        set_result "$step_name" "SUCCESS"
        print_status "SUCCESS" "$step_name completed in ${duration}s"
    else
        exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        set_timing "$step_name" "$duration"
        
        if [ "$allow_failure" = "true" ]; then
            set_result "$step_name" "WARNING"
            print_status "WARNING" "$step_name failed (non-critical) in ${duration}s"
        else
            set_result "$step_name" "FAILURE"
            print_status "FAILURE" "$step_name failed with exit code $exit_code in ${duration}s"
        fi
        
        # Capture debug info
        set_debug "$step_name" "$(tail -n 50 "$output_file")"
        
        # Show last few lines of error
        echo -e "${RED}Last 10 lines of output:${NC}"
        tail -n 10 "$output_file"
    fi
    
    rm -f "$output_file"
    return $exit_code
}

# Function to check prerequisites
check_prerequisites() {
    print_status "INFO" "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check for required tools
    for tool in cargo rustc rustfmt; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=("$tool")
            set_result "prereq_$tool" "FAILURE"
        else
            local version=$($tool --version 2>/dev/null | head -n 1 || echo "unknown")
            set_result "prereq_$tool" "SUCCESS"
            print_status "SUCCESS" "$tool: $version"
        fi
    done
    
    # Check for clippy (invoked via cargo clippy)
    if cargo clippy --version &> /dev/null; then
        local version=$(cargo clippy --version 2>/dev/null | head -n 1 || echo "unknown")
        set_result "prereq_clippy" "SUCCESS"
        print_status "SUCCESS" "clippy: $version"
    else
        missing_tools+=("clippy")
        set_result "prereq_clippy" "FAILURE"
    fi
    
    # Check for optional tools
    for tool in cargo-audit cargo-mutants cargo-llvm-cov act docker; do
        if command -v $tool &> /dev/null; then
            local version=$($tool --version 2>/dev/null | head -n 1 || echo "installed")
            set_result "prereq_$tool" "SUCCESS"
            print_status "SUCCESS" "$tool: $version"
        else
            set_result "prereq_$tool" "WARNING"
            print_status "WARNING" "$tool: not installed (optional)"
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_status "FAILURE" "Missing required tools: ${missing_tools[*]}"
        return 1
    fi
    
    return 0
}

# Main workflow execution
main() {
    echo -e "${BOLD}=====================================${NC}"
    echo -e "${BOLD}  Local CI/CD Workflow for saorsa-core${NC}"
    echo -e "${BOLD}=====================================${NC}"
    echo -e "Started at: $(date)"
    echo ""
    
    # Safety check: Backup Cargo.lock to detect any modifications
    if [ -f "Cargo.lock" ]; then
        CARGO_LOCK_BACKUP=$(mktemp)
        cp Cargo.lock "$CARGO_LOCK_BACKUP"
        print_status "INFO" "Backed up Cargo.lock for safety"
    fi
    
    # Try to add cargo to PATH if not already available
    if ! command -v cargo &> /dev/null; then
        if [ -d "$HOME/.cargo/bin" ]; then
            export PATH="$HOME/.cargo/bin:$PATH"
            print_status "INFO" "Added ~/.cargo/bin to PATH"
        elif [ -f "$HOME/.cargo/env" ]; then
            # Source cargo env only if cargo is not found
            source "$HOME/.cargo/env"
            print_status "INFO" "Sourced cargo environment from ~/.cargo/env"
        fi
    fi
    
    # Check prerequisites
    if ! check_prerequisites; then
        print_status "FAILURE" "Prerequisites check failed. Please install missing tools."
        print_summary
        exit 1
    fi
    
    # Store current directory
    PROJECT_ROOT=$(pwd)
    
    # 1. Format Check
    run_step "Format Check" "cargo fmt --all -- --check" true
    
    # 2. Clippy Linting (Strict)
    run_step "Clippy (Strict)" "cargo clippy --all-features -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used -W clippy::pedantic" false
    
    # 3. Build Debug
    run_step "Build (Debug)" "cargo build --all-features" false
    
    # 4. Build Release
    run_step "Build (Release)" "cargo build --release --all-features" true
    
    # 5. Run Tests
    run_step "Unit Tests" "cargo test --lib --all-features" false
    
    # 6. Run Integration Tests
    run_step "Integration Tests" "cargo test --tests --all-features" false
    
    # 7. Run Doc Tests
    run_step "Doc Tests" "cargo test --doc --all-features" true
    
    # 8. Check for compilation warnings
    run_step "Warning Check" "RUSTFLAGS='-D warnings' cargo check --all-features --all-targets" false
    
    # 9. Security Audit (if cargo-audit is installed)
    if command -v cargo-audit &> /dev/null; then
        run_step "Security Audit" "cargo audit" true
    fi
    
    # 10. Test Coverage (if cargo-llvm-cov is installed)
    if command -v cargo-llvm-cov &> /dev/null; then
        run_step "Code Coverage" "cargo llvm-cov --all-features --workspace --summary-only" true
    fi
    
    # 11. Minimal Versions Check (nightly only) - DISABLED: Modifies Cargo.lock
    # WARNING: This command modifies Cargo.lock and can break dependencies
    # if rustc --version | grep -q nightly; then
    #     run_step "Minimal Versions" "cargo update -Z minimal-versions && cargo check --all-features" true
    # fi
    
    # 12. Mutation Testing Sample (if cargo-mutants is installed)
    if command -v cargo-mutants &> /dev/null; then
        run_step "Mutation Testing (Sample)" "timeout 60 cargo mutants --no-shuffle --test-timeout 30 --file src/adaptive/beta_distribution.rs -- -D warnings" true
    fi
    
    # 13. Check GitHub Workflows with act (if available)
    if command -v act &> /dev/null && command -v docker &> /dev/null; then
        run_step "Workflow Validation (act)" "act -n --container-architecture linux/amd64" true
    fi
    
    # 14. Benchmark compilation check
    run_step "Benchmark Check" "cargo check --benches --all-features" true
    
    # 15. Example compilation check
    run_step "Examples Check" "cargo check --examples --all-features" true
    
    # Safety verification: Check if Cargo.lock was modified
    if [ -n "$CARGO_LOCK_BACKUP" ] && [ -f "$CARGO_LOCK_BACKUP" ]; then
        if ! diff -q Cargo.lock "$CARGO_LOCK_BACKUP" > /dev/null 2>&1; then
            print_status "FAILURE" "WARNING: Cargo.lock was modified! Restoring original..."
            cp "$CARGO_LOCK_BACKUP" Cargo.lock
            print_status "SUCCESS" "Cargo.lock restored to original state"
        else
            print_status "SUCCESS" "Cargo.lock unchanged (safe)"
        fi
    fi
    
    # Print comprehensive summary
    print_summary
}

# Function to print comprehensive summary
print_summary() {
    local TOTAL_END=$(date +%s)
    local TOTAL_DURATION=$((TOTAL_END - TOTAL_START))
    
    echo ""
    echo -e "${BOLD}=====================================${NC}"
    echo -e "${BOLD}           WORKFLOW SUMMARY${NC}"
    echo -e "${BOLD}=====================================${NC}"
    echo ""
    
    # Count results
    local success_count=0
    local failure_count=0
    local warning_count=0
    
    # Prerequisites Summary
    echo -e "${BOLD}Prerequisites:${NC}"
    for i in "${!RESULT_KEYS[@]}"; do
        local key="${RESULT_KEYS[$i]}"
        local status="${RESULT_VALUES[$i]}"
        if [[ $key == prereq_* ]]; then
            local tool_name=${key#prereq_}
            if [ "$status" = "SUCCESS" ]; then
                echo -e "  ${GREEN}✅${NC} $tool_name"
                ((success_count++))
            elif [ "$status" = "WARNING" ]; then
                echo -e "  ${YELLOW}⚠️${NC}  $tool_name (optional)"
                ((warning_count++))
            else
                echo -e "  ${RED}❌${NC} $tool_name"
                ((failure_count++))
            fi
        fi
    done
    
    # Workflow Steps Summary
    echo ""
    echo -e "${BOLD}Workflow Steps:${NC}"
    for i in "${!RESULT_KEYS[@]}"; do
        local key="${RESULT_KEYS[$i]}"
        local status="${RESULT_VALUES[$i]}"
        if [[ $key != prereq_* ]]; then
            local duration=$(get_timing "$key")
            
            if [ "$status" = "SUCCESS" ]; then
                echo -e "  ${GREEN}✅${NC} $key (${duration}s)"
                ((success_count++))
            elif [ "$status" = "WARNING" ]; then
                echo -e "  ${YELLOW}⚠️${NC}  $key (${duration}s) - non-critical failure"
                ((warning_count++))
            else
                echo -e "  ${RED}❌${NC} $key (${duration}s) - FAILED"
                ((failure_count++))
            fi
        fi
    done
    
    # Debug Information for Failures
    if [ ${#DEBUG_KEYS[@]} -gt 0 ]; then
        echo ""
        echo -e "${BOLD}${RED}Debug Information for Failures:${NC}"
        for i in "${!DEBUG_KEYS[@]}"; do
            local key="${DEBUG_KEYS[$i]}"
            local debug_info="${DEBUG_VALUES[$i]}"
            echo ""
            echo -e "${YELLOW}Failed Step: $key${NC}"
            echo "----------------------------------------"
            echo "$debug_info" | head -n 20
            echo "----------------------------------------"
        done
    fi
    
    # Statistics
    echo ""
    echo -e "${BOLD}Statistics:${NC}"
    echo -e "  Total Steps: $((success_count + failure_count + warning_count))"
    echo -e "  ${GREEN}Successful: $success_count${NC}"
    echo -e "  ${YELLOW}Warnings: $warning_count${NC}"
    echo -e "  ${RED}Failed: $failure_count${NC}"
    echo -e "  Total Time: ${TOTAL_DURATION}s"
    
    # Overall Status
    echo ""
    if [ $failure_count -eq 0 ]; then
        if [ $warning_count -eq 0 ]; then
            echo -e "${BOLD}${GREEN}🎉 WORKFLOW COMPLETED SUCCESSFULLY! 🎉${NC}"
            echo -e "${GREEN}All checks passed with no issues.${NC}"
        else
            echo -e "${BOLD}${GREEN}✅ WORKFLOW COMPLETED WITH WARNINGS${NC}"
            echo -e "${YELLOW}$warning_count non-critical issues were found.${NC}"
        fi
    else
        echo -e "${BOLD}${RED}❌ WORKFLOW FAILED${NC}"
        echo -e "${RED}$failure_count critical failures need to be addressed.${NC}"
        
        # Provide fix suggestions
        echo ""
        echo -e "${BOLD}Suggested Fixes:${NC}"
        
        if [[ "$(get_result 'Format Check')" == "FAILURE" ]]; then
            echo -e "  • Run: ${BLUE}cargo fmt --all${NC}"
        fi
        
        if [[ "$(get_result 'Clippy (Strict)')" == "FAILURE" ]]; then
            echo -e "  • Fix clippy warnings: ${BLUE}cargo clippy --all-features --fix${NC}"
        fi
        
        if [[ "$(get_result 'Unit Tests')" == "FAILURE" ]] || [[ "$(get_result 'Integration Tests')" == "FAILURE" ]]; then
            echo -e "  • Debug failing tests: ${BLUE}cargo test -- --nocapture${NC}"
        fi
        
        if [[ "$(get_result 'Security Audit')" == "FAILURE" ]]; then
            echo -e "  • Review security issues: ${BLUE}cargo audit fix${NC}"
        fi
    fi
    
    echo ""
    echo -e "${BOLD}=====================================${NC}"
    echo -e "Completed at: $(date)"
    
    # Exit with appropriate code
    if [ $failure_count -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Global variable for Cargo.lock backup
CARGO_LOCK_BACKUP=""

# Cleanup function
cleanup() {
    # Restore Cargo.lock if it was backed up
    if [ -n "$CARGO_LOCK_BACKUP" ] && [ -f "$CARGO_LOCK_BACKUP" ]; then
        if [ -f "Cargo.lock" ]; then
            if ! diff -q Cargo.lock "$CARGO_LOCK_BACKUP" > /dev/null 2>&1; then
                echo -e "${RED}WARNING: Restoring original Cargo.lock${NC}"
                cp "$CARGO_LOCK_BACKUP" Cargo.lock
            fi
        fi
        rm -f "$CARGO_LOCK_BACKUP"
    fi
    
    # Print summary
    print_summary
}

# Trap to ensure cleanup and summary on exit
trap 'cleanup' EXIT

# Run main workflow
main "$@"