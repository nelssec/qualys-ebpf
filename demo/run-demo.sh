#!/bin/bash
# Qualys CRS Demo Runner
# This script builds and runs the interactive demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPERATOR_DIR="$(dirname "$SCRIPT_DIR")/operator"

echo "Building Qualys CRS Demo..."

# Build the demo
cd "$OPERATOR_DIR"
go build -o "$SCRIPT_DIR/demo" "$SCRIPT_DIR/main.go"

echo "Build complete!"
echo ""

# Run the demo
cd "$SCRIPT_DIR"
./demo
