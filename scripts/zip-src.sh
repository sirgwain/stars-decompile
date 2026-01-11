#!/usr/bin/env bash
set -e

#
# Find repo root (directory containing top-level CMakeLists.txt)
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR"

while [ "$ROOT" != "/" ] && [ ! -f "$ROOT/CMakeLists.txt" ]; do
    ROOT="$(dirname "$ROOT")"
done

if [ ! -f "$ROOT/CMakeLists.txt" ]; then
    echo "error: could not find repo root (CMakeLists.txt)" >&2
    exit 1
fi

#
# Output zip name
#
OUT_NAME="${1:-stars-src-$(date +%Y%m%d-%H%M%S).zip}"
OUT="$ROOT/$OUT_NAME"

echo "Repo root: $ROOT"
echo "Output:    $OUT"

rm -f "$OUT"

(
  cd "$ROOT"

  find . \
    \( -path "./.git" -o -path "./.git/*" \
       -o -path "./build" -o -path "./build/*" \
       -o -path "./cmake-build-*" \
       -o -path "./scripts" -o -path "./scripts/*" \
       -o -path "./decompiled" -o -path "./decompiled/*" \) -prune -o \
    \( -name "CMakeLists.txt" \
       -o -name "*.c" \
       -o -name "*.h" \
       -o -path "./test/*" \) -print \
  | zip -9 "$OUT" -@ \
      -x "**/.DS_Store" \
         "**/*.o" "**/*.obj" \
         "**/*.a" "**/*.so" "**/*.dll" \
         "**/*.dSYM/**"
)

echo "Wrote $OUT"
