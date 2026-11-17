#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# Packaged alongside the app's own runtime; no system Python or install needed.
exec "$ROOT/Runtime/bin/python3.13" -I -B "$ROOT/Engine/checkpoint_diagnostic.py"
