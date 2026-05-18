#!/usr/bin/env bash
# install-man.sh — Instala a página de manual para os comandos vault-*
# Usage: sudo ./install-man.sh [--man-dir DIR] [--install-shell]

set -euo pipefail
MAN_DIR="/usr/local/share/man/man1"
INSTALL_SHELL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --man-dir) MAN_DIR="$2"; shift 2;;
    --install-shell) INSTALL_SHELL=1; shift;;
    -h|--help) echo "Usage: sudo $0 [--man-dir DIR] [--install-shell]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root to install system manpages." >&2
  echo "Run with: sudo $0" >&2
  exit 1
fi

SRC_MD="docs/vault_commands.md"
if [[ ! -f "$SRC_MD" ]]; then
  echo "Cannot find $SRC_MD" >&2
  exit 1
fi

mkdir -p "$MAN_DIR"
TMP_MAN=$(mktemp /tmp/IdenVault.XXXXXX.1)

cat > "$TMP_MAN" <<'MANHDR'
.TH IdenVault-vault-commands 1 "May 2026" "IdenVault 1.0.2" "IdenVault Vault Commands"
.SH NAME
IdenVault-vault-commands \- Vault commands manual
.SH SYNOPSIS
.B vault-*
.SH DESCRIPTION
MANHDR

# Convert minimal Markdown to roff: paragraphs -> .PP, code blocks or listings preserved simply.
awk '
  BEGIN{p=0}
  /^[[:space:]]*$/ { if(p==1){print ".PP"; p=0} else { print ""; } next }
  { gsub(/\\/, "\\\\"); print $0; p=1 }
' "$SRC_MD" >> "$TMP_MAN"

# Compress and install
gzip -9 -c "$TMP_MAN" > "$MAN_DIR/IdenVault-vault-commands.1.gz"
rm -f "$TMP_MAN"

# Update mandb if available
if command -v mandb >/dev/null 2>&1; then
  mandb >/dev/null 2>&1 || true
fi

echo "Installed man page to $MAN_DIR/IdenVault-vault-commands.1.gz"

# Optionally install the restricted shell helper
if [[ $INSTALL_SHELL -eq 1 ]]; then
  TARGET_BIN="/usr/local/bin/idenvault-shell"
  mkdir -p "$(dirname "$TARGET_BIN")"
  cp scripts/idenvault-shell.sh "$TARGET_BIN"
  chmod +x "$TARGET_BIN"
  echo "Installed restricted shell helper to $TARGET_BIN"
  echo "Note: enable allowed commands by creating a 'tools/bin' directory and symlinking allowed binaries there. See docs/TOOLS.md"
fi

exit 0
