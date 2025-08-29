# Scripts Directory

This directory contains utility scripts for development and testing.

## local_ci.sh

A comprehensive local CI/CD workflow script that mimics GitHub Actions locally with detailed success/failure tracking and debug information.

### Features

- **Prerequisites Checking**: Validates all required and optional tools
- **Comprehensive Testing**: Runs format checks, clippy, builds, and all test types
- **Detailed Reporting**: Shows success/failure for each step with timing information
- **Debug Information**: Captures and displays debug output for any failures
- **Fix Suggestions**: Provides actionable fix commands for common issues
- **Color-Coded Output**: Clear visual feedback with ✅ ❌ ⚠️ indicators

### Usage

```bash
# Run the full local CI workflow
./scripts/local_ci.sh
```

### Workflow Stages

1. **Prerequisites Check**
   - Required: cargo, rustc, clippy, rustfmt
   - Optional: cargo-audit, cargo-mutants, cargo-llvm-cov, act, docker

2. **Format Check** - Ensures consistent code formatting
3. **Clippy (Strict)** - Enforces zero warnings with pedantic settings
4. **Build (Debug)** - Validates debug compilation
5. **Build (Release)** - Validates release compilation
6. **Unit Tests** - Runs all unit tests
7. **Integration Tests** - Runs all integration tests
8. **Doc Tests** - Validates documentation examples
9. **Warning Check** - Ensures zero compilation warnings
10. **Security Audit** - Checks for known vulnerabilities (if cargo-audit installed)
11. **Code Coverage** - Generates coverage report (if cargo-llvm-cov installed)
12. **Mutation Testing** - Sample mutation tests (if cargo-mutants installed)
13. **Workflow Validation** - Validates GitHub Actions with act (if available)

### Summary Report

The script provides a comprehensive summary including:

- **Prerequisites Status**: Shows which tools are installed
- **Workflow Steps**: Success/failure status with execution time
- **Debug Information**: Detailed output for any failures
- **Statistics**: Total steps, successes, warnings, failures, and total time
- **Fix Suggestions**: Actionable commands to fix common issues

### Exit Codes

- `0`: All critical checks passed (warnings allowed)
- `1`: One or more critical failures detected

### Example Output

```
=====================================
  Local CI/CD Workflow for saorsa-core
=====================================
Started at: Fri 29 Aug 2025 22:30:00 BST

ℹ️  Checking prerequisites...
✅ cargo: cargo 1.84.0
✅ rustc: rustc 1.84.0
✅ clippy: clippy 0.1.84
✅ rustfmt: rustfmt 1.8.0

Running: Format Check
✅ Format Check completed in 2s

Running: Clippy (Strict)
✅ Clippy (Strict) completed in 15s

...

=====================================
           WORKFLOW SUMMARY
=====================================

Prerequisites:
  ✅ cargo
  ✅ rustc
  ✅ clippy
  ✅ rustfmt

Workflow Steps:
  ✅ Format Check (2s)
  ✅ Clippy (Strict) (15s)
  ✅ Build (Debug) (30s)
  ✅ Unit Tests (12s)
  ✅ Integration Tests (45s)

Statistics:
  Total Steps: 8
  Successful: 8
  Warnings: 0
  Failed: 0
  Total Time: 120s

🎉 WORKFLOW COMPLETED SUCCESSFULLY! 🎉
All checks passed with no issues.
```

## test_adaptive_network.sh

A specialized script for testing the adaptive networking components, including Thompson Sampling, Multi-Armed Bandits, and Q-Learning cache optimization.

### Usage

```bash
./scripts/test_adaptive_network.sh
```

This script runs focused tests on the adaptive networking layer to ensure all ML-driven routing strategies are functioning correctly.