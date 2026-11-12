#!/usr/bin/env bash
# Download the BETH dataset from Kaggle into data/beth/.
# Requires: pip install kaggle, and an API token at ~/.kaggle/kaggle.json (see data/README.md).
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p data/beth

if ! command -v kaggle >/dev/null 2>&1; then
  echo "kaggle CLI not found. Run: pip install kaggle" >&2
  exit 1
fi

kaggle datasets download -d katehighnam/beth-dataset -p data/beth --unzip
echo
ls -lh data/beth
echo
echo "Next: python -m triage describe --data data/beth/labelled_training_data.csv"
