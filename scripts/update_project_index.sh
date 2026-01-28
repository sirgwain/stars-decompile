#!/usr/bin/env bash
set -euo pipefail

# update_project_index.sh
#
# Keeps project_index.json (and project_index_lite.json) up to date.
# Run from anywhere inside the repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"

# find repo root (CMakeLists.txt)
while [[ "$ROOT" != "/" && ! -f "$ROOT/CMakeLists.txt" ]]; do
  ROOT="$(dirname "$ROOT")"
done
if [[ ! -f "$ROOT/CMakeLists.txt" ]]; then
  echo "error: could not find repo root (CMakeLists.txt)" >&2
  exit 1
fi

OUT_FULL="${1:-$ROOT/project_index.json}"
OUT_LITE="${2:-$ROOT/project_index_lite.json}"

python3 "$ROOT/scripts/make_project_index.py" \
  --root "$ROOT" \
  --out "$OUT_FULL" \
  --out-lite "$OUT_LITE"

echo "OK: updated index files"
