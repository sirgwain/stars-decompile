#!/usr/bin/env bash
set -e

#
# Parse args
#
INCLUDE_SCRIPTS=0
OUT_NAME=""

for arg in "$@"; do
    case "$arg" in
        --with-scripts|-s)
            INCLUDE_SCRIPTS=1
            ;;
        *)
            if [ -z "$OUT_NAME" ]; then
                OUT_NAME="$arg"
            fi
            ;;
    esac
done

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
OUT_NAME="${OUT_NAME:-stars-src-$(date +%Y%m%d-%H%M%S).zip}"
OUT="$ROOT/$OUT_NAME"

echo "Repo root:        $ROOT"
echo "Output:           $OUT"
echo "Include scripts:  $INCLUDE_SCRIPTS"

rm -f "$OUT"

#
# Prune list
#
PRUNE_PATHS=(
  "./.git" "./.git/*"
  "./build" "./build/*"
  "./cmake-build-*"
  "./decompiled" "./decompiled/*"
)

if [ "$INCLUDE_SCRIPTS" -eq 0 ]; then
    PRUNE_PATHS+=("./scripts" "./scripts/*")
fi

# Build: \( -path "a" -o -path "b" -o ... \)
PRUNE_EXPR="\\("
for p in "${PRUNE_PATHS[@]}"; do
    PRUNE_EXPR="$PRUNE_EXPR -path \"$p\" -o"
done
PRUNE_EXPR="${PRUNE_EXPR% -o}"
PRUNE_EXPR="$PRUNE_EXPR \\) -prune -o"

(
  cd "$ROOT"

  # Build selection expression (what we include)
  SEL_EXPR="\\( -name \"CMakeLists.txt\" -o -name \"*.c\" -o -name \"*.h\" -o -path \"./test/*\""
  if [ "$INCLUDE_SCRIPTS" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./scripts/*\""
  fi
  SEL_EXPR="$SEL_EXPR \\) -print"

  # Use eval so the escaped parens/quotes are interpreted correctly on BSD find
  eval "find . $PRUNE_EXPR $SEL_EXPR" \
    | zip -9 "$OUT" -@ \
        -x "**/.DS_Store" \
           "**/*.o" "**/*.obj" \
           "**/*.a" "**/*.so" "**/*.dll" \
           "**/*.dSYM/**"
)

echo "Wrote $OUT"
