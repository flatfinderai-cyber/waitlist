#!/usr/bin/env bash
# setup.sh — initialise the FlatFinder Automator environment
set -euo pipefail

echo "==> Installing Python dependencies..."
pip install reflex pydantic python-dotenv requests supabase bandit PyYAML

echo "==> Initialising Reflex project..."
reflex init

echo "==> Environment ready. Run 'reflex run' to start the application."
