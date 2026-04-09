#!/usr/bin/env bash
# setup.sh — initialise the FlatFinder Automator environment
set -euo pipefail

echo "==> Installing Python dependencies..."
pip install -r requirements.txt

echo "==> Initialising Reflex project..."
reflex init

echo "==> Environment ready. Run 'reflex run' to start the application."
