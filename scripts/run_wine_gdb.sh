#!/usr/bin/env bash
set -euo pipefail

PIDFILE=".vscode/wine-gdb.pid"

# Kill any stale instance
if [[ -f "$PIDFILE" ]]; then
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  rm -f "$PIDFILE"
fi

# Start your existing target
cmake --preset macos-wine
cmake --build build-win --target run_in_wine_gdb &

PID=$!
echo "$PID" > "$PIDFILE"

wait "$PID"
