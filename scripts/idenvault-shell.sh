#!/usr/bin/env bash
# idenvault-shell.sh — restricted helper to start a limited shell environment
# Usage: idenvault-shell.sh [--use-tools]

set -euo pipefail
USE_TOOLS=0

if [[ "$1" == "--use-tools" ]]; then
  USE_TOOLS=1
fi

echo "WARNING: entering a restricted shell. This environment limits available actions." >&2
read -p "Proceed and spawn restricted shell? [y/N]: " ans
ans=${ans,,}
if [[ "$ans" != "y" && "$ans" != "yes" ]]; then
  echo "Aborted."; exit 1
fi

# Build a sanitized PATH if the user wants to use a tools whitelist
if [[ $USE_TOOLS -eq 1 ]]; then
  TOOLS_DIR="$(pwd)/tools/bin"
  if [[ ! -d "$TOOLS_DIR" ]]; then
    echo "Tools directory not found: $TOOLS_DIR" >&2
    echo "Create it and add symlinks to allowed binaries, e.g.:" >&2
    echo "  mkdir -p tools/bin && ln -s /bin/ls tools/bin/ls" >&2
    exit 1
  fi
  export PATH="$TOOLS_DIR"
else
  # minimal PATH to common binaries (still risky) — keep very small
  export PATH="/bin:/usr/bin"
fi

# Drop environment variables for safety
env -i PATH="$PATH" TERM="$TERM" /bin/bash --noprofile --norc --restricted
