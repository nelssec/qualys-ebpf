#!/bin/bash
# Generate policies using the Python generator

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR_DIR="${SCRIPT_DIR}/../generator"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed"
    exit 1
fi

# Install dependencies if needed
if [ ! -d "${GENERATOR_DIR}/venv" ]; then
    echo "Setting up Python virtual environment..."
    python3 -m venv "${GENERATOR_DIR}/venv"
    source "${GENERATOR_DIR}/venv/bin/activate"
    pip install -r "${GENERATOR_DIR}/requirements.txt"
else
    source "${GENERATOR_DIR}/venv/bin/activate"
fi

# Run the generator
cd "${GENERATOR_DIR}"
python cli.py "$@"
