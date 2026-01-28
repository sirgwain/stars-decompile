#!/usr/bin/env bash
set -e

#
# Parse args
#
INCLUDE_SCRIPTS=1
INCLUDE_NOTES=1
INCLUDE_TEST=1
INCLUDE_TOOLCHAINS=1
INCLUDE_DECOMPILED=1
OUT_NAME=""

for arg in "$@"; do
    case "$arg" in
        # legacy (now default-on)
        --with-scripts|-s)
            INCLUDE_SCRIPTS=1
            ;;
        # opt-outs
        --no-scripts)
            INCLUDE_SCRIPTS=0
            ;;
        --no-notes)
            INCLUDE_NOTES=0
            ;;
        --no-test)
            INCLUDE_TEST=0
            ;;
        --no-toolchains)
            INCLUDE_TOOLCHAINS=0
            ;;
        --no-decompiled)
            INCLUDE_DECOMPILED=0
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

echo "Repo root:           $ROOT"
echo "Output:              $OUT"
echo "Include scripts:     $INCLUDE_SCRIPTS"
echo "Include notes:       $INCLUDE_NOTES"
echo "Include test:        $INCLUDE_TEST"
echo "Include toolchains:  $INCLUDE_TOOLCHAINS"
echo "Include decompiled:  $INCLUDE_DECOMPILED"

rm -f "$OUT"

#
# Prune list
#
PRUNE_PATHS=(
  "./.git" "./.git/*"
  "./build" "./build/*"
  "./cmake-build-*"
)

if [ "$INCLUDE_SCRIPTS" -eq 0 ]; then
    PRUNE_PATHS+=("./scripts" "./scripts/*")
fi
if [ "$INCLUDE_NOTES" -eq 0 ]; then
    PRUNE_PATHS+=("./notes" "./notes/*")
fi
if [ "$INCLUDE_TEST" -eq 0 ]; then
    PRUNE_PATHS+=("./test" "./test/*")
fi
if [ "$INCLUDE_TOOLCHAINS" -eq 0 ]; then
    PRUNE_PATHS+=("./toolchains" "./toolchains/*")
fi
if [ "$INCLUDE_DECOMPILED" -eq 0 ]; then
    PRUNE_PATHS+=("./decompiled" "./decompiled/*")
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
  # - Always include CMakeLists.txt anywhere
  # - Include CMakePresets.json and mise.toml ONLY from repo root
  SEL_EXPR="\\( -name \"CMakeLists.txt\" -o -path \"./CMakePresets.json\" -o -path \"./mise.toml\" -o -name \"*.c\" -o -name \"*.h\""

  if [ "$INCLUDE_TEST" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./test/*\""
  fi
  if [ "$INCLUDE_SCRIPTS" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./scripts/*\""
  fi
  if [ "$INCLUDE_NOTES" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./notes/*\""
  fi
  if [ "$INCLUDE_TOOLCHAINS" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./toolchains/*\""
  fi
  if [ "$INCLUDE_DECOMPILED" -eq 1 ]; then
      SEL_EXPR="$SEL_EXPR -o -path \"./decompiled/*\""
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
