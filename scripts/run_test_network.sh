#!/bin/bash

# Saorsa Core Test Network Runner
# This script runs a comprehensive test network to verify the library functionality

set -e

echo "🧪 Saorsa Core Test Network"
echo "=========================="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Please run this script from the saorsa-core project root"
    exit 1
fi

# Build the test network example
echo "🔨 Building test network example..."
cargo build --example test_network --all-features

# Run the test network
echo ""
echo "🚀 Starting test network..."
echo "This will create 4 nodes that will:"
echo "• Connect to each other"
echo "• Send 50 test messages"
echo "• Measure bandwidth for 10 seconds"
echo "• Display comprehensive statistics"
echo ""
echo "Press Ctrl+C to stop the test network"
echo ""

# Run the test network
cargo run --example test_network --all-features