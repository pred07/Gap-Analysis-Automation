#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${CONFIG_DIR:-$ROOT_DIR/config}"
MODULES="${MODULES:-1 2 3 4 5 6 7 8}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-1}"

echo "=== GAP Analysis Phase 1 ==="
echo "Config directory: $CONFIG_DIR"
echo "Modules: $MODULES"
echo

EXIT_CODE=0

for MODULE in $MODULES; do
  echo ">>> Running module $MODULE"
  if python3 "$ROOT_DIR/run_module.py" --module "$MODULE" --config-dir "$CONFIG_DIR" "$@"; then
    echo "Module $MODULE completed."
  else
    MODULE_EXIT=$?
    echo "Module $MODULE failed with exit code $MODULE_EXIT"
    EXIT_CODE=$MODULE_EXIT
    if [[ "$CONTINUE_ON_ERROR" == "0" ]]; then
      echo "Halting due to failure (CONTINUE_ON_ERROR=0)"
      exit "$EXIT_CODE"
    fi
  fi
  echo
done

echo ">>> Merging module outputs"
python3 "$ROOT_DIR/merge/merge_results.py" || EXIT_CODE=$?

exit "$EXIT_CODE"

