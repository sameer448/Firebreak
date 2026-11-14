#!/usr/bin/env bash
# One-time setup on macOS / Linux. Run from the repository root:  ./scripts/setup.sh [--skip-models]
# Creates .venv, installs Python packages, pulls the Ollama models, builds the vector indexes
# for both example org packs, runs the tests, and finishes with `python -m capstone doctor`.
set -euo pipefail
cd "$(dirname "$0")/.."

SKIP_MODELS=0
[ "${1:-}" = "--skip-models" ] && SKIP_MODELS=1
PY=${PYTHON:-python3}

echo "==> Python: $($PY --version)"
$PY -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "Python 3.8+ required"; exit 1; }

echo "==> Virtual environment (.venv) and packages"
[ -d .venv ] || $PY -m venv .venv
VPY=.venv/bin/python
$VPY -m pip install --quiet --upgrade pip
$VPY -m pip install --quiet -r requirements.txt

if [ "$SKIP_MODELS" -eq 0 ]; then
  command -v ollama >/dev/null || { echo "Ollama not found: install it from https://ollama.com, start it, and re-run"; exit 1; }
  echo "==> Ollama models (about 7 GB the first time)"
  ollama pull nomic-embed-text
  ollama pull llama3.1:8b
  ollama pull hf.co/Sgoyal16/soc-triage-llama3.2-3b-GGUF:Q4_K_M
  ollama create soc-triage -f Modelfile

  echo "==> Vector indexes for the example org packs"
  $VPY -m capstone --org demo-corp org ingest
  $VPY -m capstone --org harbor-valley-health org ingest
fi

echo "==> Tests (no model calls)"
$VPY -m unittest discover -s tests

echo "==> Environment check"
$VPY -m capstone doctor || true
echo
echo "Start the console:  .venv/bin/python -m capstone.web --org demo-corp   ->  http://127.0.0.1:8765"
